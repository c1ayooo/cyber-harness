package fence

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	mitmproxy "github.com/chainreactors/utils/mitmproxy/proxy"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ScopeJudge is the fence's request judge: the control plane's machine-
// matchable test range judges the HTTP requests the proxy forwards,
// independently of the guardrail provider (an unconfigured judge must not
// disable the operator's explicit rule table). Review holds reuse the
// guardrail runtime's pending queue through the SubmitReview seam (G3), so a
// held request is exactly a tool call held for review with the synthetic tool
// name "http.request" and the control plane's existing Pending/Resolve RPC
// works unchanged. The composition obtains the judge from the fence
// extension (ScopeJudge) after the bind hook has set its runtime.

// ScopeJudge judges proxied requests and tunnels against the fence tables.
type ScopeJudge struct {
	fence     *Extension
	guardrail func() *guardrailext.Runtime
}

// NewScopeJudge builds the request judge over the fence extension. The
// guardrail runtime is read lazily (the bind hook may run after this).
func NewScopeJudge(e *Extension) *ScopeJudge {
	return &ScopeJudge{fence: e, guardrail: func() *guardrailext.Runtime {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.guardrail
	}}
}

var _ scoperules.ScopeJudge = (*ScopeJudge)(nil)

//
// Publication policy: record verdicts ride only the flow's TrafficVerdict
// sidecar (core/scoperules registry, consumed by the observe extension) — one
// tool call fans out into many requests, and journaling every record would
// flood the run journal. review and block publish the same Decision/Review
// events a tool interception does, because those are the verdicts an operator
// must see and answer. Shadow judges and publishes but never holds or refuses.

// JudgeScopeRequest implements proxy.ScopeJudge.
func (j *ScopeJudge) JudgeScopeRequest(req scoperules.ScopeRequest) scoperules.ScopeDecision {
	if j == nil || req.Call == nil || req.Invocation.SessionID == "" {
		return scoperules.ScopeDecision{}
	}
	rawURL := scopeRequestURL(req.Call)
	// The instance fence wins before the project fence (spec #1 工单3): a
	// denied domain refuses even when a project row allowlists it. Domain
	// hits are rare enough that the audit row is worth its journal line, and
	// the sidecar names the global entry so the traffic view shows it. The
	// default-allow list (fork patch 37) sits between them: infrastructure
	// the operator always permits is recorded and forwarded before the
	// project fence can queue it as a pending asset.
	scopes, globals, _ := j.fence.stores()
	if globals != nil {
		if rule, hit := globals.AllowDomainHit(req.Invocation.SessionID, requestHost(rawURL)); hit {
			return j.allowGlobal(req, rule, scopeRequestFlowID(req.Call))
		}
		if rule, hit := globals.DomainHit(req.Invocation.SessionID, requestHost(rawURL)); hit {
			return j.refuseGlobal(req, rule, scopeRequestFlowID(req.Call))
		}
	}
	if scopes == nil {
		return scoperules.ScopeDecision{}
	}
	verdict, judged := scopes.JudgeSession(req.Invocation.SessionID, scopeRequestMethod(req.Call), rawURL)
	if !judged {
		return scoperules.ScopeDecision{}
	}
	ctx := operation.ContextWithInvocation(context.Background(), req.Invocation)
	// A page pulls its own static subresources (scripts, styles, images,
	// fonts) from third-party hosts all the time; under the allowlist fence
	// each one would queue a pending asset the operator has to wave through.
	// A passive request (Sec-Fetch-Dest) that misses the rule table is
	// rewritten to a plain record verdict — forwarded, journaled in the
	// traffic view, and never routed to the pending-approval flow. Deliberate
	// requests and every explicit rule row keep the full semantics.
	if verdict.DefaultMissed && scopeRequestPassive(req.Call) {
		verdict = scoperules.Verdict{Action: scoperules.ActionRecord,
			Reason: "静态资源（Sec-Fetch-Dest），范围外放行并记录", Passive: true}
	}
	scoperules.RecordVerdict(scopeRequestFlowID(req.Call), verdict)
	// The quiet path covers three shapes: a record row, a shadow set, and —
	// since the allowlist fence (fork patch 30) — a default miss. A miss never
	// holds (approving one request cannot admit the asset, and a held request
	// blocks the whole run while its concurrent twins are refused anyway) and
	// publishes no Decision/Review event: one tool call fans out into many
	// requests, and the control plane reads the refusal from the sidecar's
	// default_missed flag, routing the asset — not the request — to the
	// operator. Explicit rows keep their event-backed hold/refuse semantics.
	// The decision carries the verdict verbatim (fork patch 33), so the
	// proxy's sidecar keeps default_missed/passive instead of a projection.
	if verdict.DefaultMissed || verdict.Shadow || verdict.Action == scoperules.ActionRecord {
		return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	decision := &guardrailext.Decision{Action: scopeActionEnum(verdict.Action), Reason: verdict.Reason}
	refusal := scopeRefusal(rawURL, verdict)
	if verdict.Action == scoperules.ActionBlock {
		j.emitScope(ctx, decision, req)
		return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict, Refusal: refusal}
	}
	// Review: hold the request on the pending-review lifecycle. The operator
	// answers through the ordinary guardrail Pending/Resolve RPC; expiry uses
	// the runtime's own review timeout.
	approved := j.holdScopeRequest(ctx, req, decision)
	return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Refusal: refusal, Hold: func(context.Context) bool { return approved }}
}

// allowGlobal records an instance-fence allowance: infrastructure the
// operator always permits (DNS/DoH endpoints, passive intel sources) is
// forwarded and recorded with the global-allow sidecar so the traffic view
// reads it as the operator's own standing, not a project asset. No Decision
// event: unlike a refusal this is not worth a journal line per request — the
// sidecar and the fence audit carry it.
func (j *ScopeJudge) allowGlobal(req scoperules.ScopeRequest, rule globalfence.DomainRule, flowID string) scoperules.ScopeDecision {
	verdict := scoperules.Verdict{Action: scoperules.ActionRecord,
		RuleID: "global.allow:" + rule.ID, Reason: "基础设施放行 " + rule.ID}
	scoperules.RecordVerdict(flowID, verdict)
	return scoperules.ScopeDecision{Judged: true, Action: scoperules.ActionRecord, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict}
}

// refuseGlobal refuses one request (or tunnel) for an instance-fence domain
// hit: the synthetic 403 is the proxy's business — here we publish the audit
// Decision and record the sidecar verdict naming the global entry, so the
// traffic view and the audit trail both show a red line the operator wrote,
// not a project rule.
func (j *ScopeJudge) refuseGlobal(req scoperules.ScopeRequest, rule globalfence.DomainRule, flowID string) scoperules.ScopeDecision {
	verdict := scoperules.Verdict{Action: scoperules.ActionBlock,
		RuleID: "global:" + rule.ID, Reason: "全局禁访域名 " + rule.ID}
	scoperules.RecordVerdict(flowID, verdict)
	ctx := operation.ContextWithInvocation(context.Background(), req.Invocation)
	j.emitScope(ctx, &guardrailext.Decision{Action: guardrailext.Action_ACTION_BLOCK, Reason: verdict.Reason}, req)
	return scoperules.ScopeDecision{Judged: true, Action: scoperules.ActionBlock, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict}
}

// JudgeScopeConnect judges a CONNECT tunnel (fork patch 31): the instance
// fence judges fully; the project fence judges its host form only — rows
// match on host alone (a method/path row refines decrypted inner requests,
// not the tunnel), CIDR rows match literal IPs directly and hostnames through
// the cached resolver, and an unmatched tunnel refuses under the allowlist
// default rather than passing unjudged. Decrypted inner requests carry the
// full judgment; in relay mode this host-form pass/fail IS the fence.
func (j *ScopeJudge) JudgeScopeConnect(req scoperules.ScopeRequest) scoperules.ScopeDecision {
	if j == nil || req.Call == nil || req.Invocation.SessionID == "" {
		return scoperules.ScopeDecision{}
	}
	rawURL := scopeRequestURL(req.Call)
	scopes, globals, _ := j.fence.stores()
	if globals != nil {
		if rule, hit := globals.AllowDomainHit(req.Invocation.SessionID, scoperules.RequestHost(rawURL)); hit {
			return j.allowGlobal(req, rule, scopeRequestFlowID(req.Call))
		}
		if rule, hit := globals.DomainHit(req.Invocation.SessionID, scoperules.RequestHost(rawURL)); hit {
			return j.refuseGlobal(req, rule, scopeRequestFlowID(req.Call))
		}
	}
	if scopes == nil {
		return scoperules.ScopeDecision{}
	}
	verdict, judged := scopes.JudgeSessionConnect(req.Invocation.SessionID, rawURL)
	if !judged {
		return scoperules.ScopeDecision{}
	}
	ctx := operation.ContextWithInvocation(context.Background(), req.Invocation)
	scoperules.RecordVerdict(scopeRequestFlowID(req.Call), verdict)
	if verdict.DefaultMissed || verdict.Shadow || verdict.Action == scoperules.ActionRecord {
		return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	decision := &guardrailext.Decision{Action: scopeActionEnum(verdict.Action), Reason: verdict.Reason}
	refusal := scopeRefusal(rawURL, verdict)
	if verdict.Action == scoperules.ActionBlock {
		j.emitScope(ctx, decision, req)
		return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict, Refusal: refusal}
	}
	approved := j.holdScopeRequest(ctx, req, decision)
	return scoperules.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Refusal: refusal, Hold: func(context.Context) bool { return approved }}
}

// requestHost extracts the authority a synthetic call's URL names — the
// scoperules helper, which also handles the CONNECT authority form.
func requestHost(rawURL string) string {
	return scoperules.RequestHost(rawURL)
}

// holdScopeRequest holds the synthetic call on the guardrail runtime's
// pending-review lifecycle through the SubmitReview seam (G3): the operator
// answers through the ordinary Pending/Resolve RPC, expiry uses the runtime's
// review timeout. True only for an explicit approval.
func (j *ScopeJudge) holdScopeRequest(ctx context.Context, req scoperules.ScopeRequest, decision *guardrailext.Decision) bool {
	if req.Operation.GetOperationId() == "" {
		// Without an operation id the control plane cannot answer; refuse
		// rather than hold forever on an unanswerable review.
		j.emitScope(ctx, decision, req)
		return false
	}
	rt := j.guardrail()
	if rt == nil {
		// FailClosed: no approval queue, no hold.
		j.emitScope(ctx, decision, req)
		return false
	}
	ev := toolhooks.CallEvent{Call: req.Call, Operation: req.Operation}
	admission := rt.SubmitReview(ctx, ev, decision)
	return admission.Deny == nil
}

// emitScope publishes one guardrail event in the ordinary interception shape:
// the payload as the extension, the operation ref as the sidecar.
func (j *ScopeJudge) emitScope(ctx context.Context, payload protobuf.Message, req scoperules.ScopeRequest) {
	invocation := operation.InvocationFromContext(ctx)
	encoded, err := anypb.New(payload)
	if err != nil {
		return
	}
	event := &aop.Event{
		SessionId: invocation.SessionID, TurnId: invocation.TurnID, Emitter: "guardrail",
		Payload: &aop.Event_Extension{Extension: encoded},
	}
	if req.Operation != nil {
		ref, _ := anypb.New(req.Operation)
		event.Extensions = append(event.Extensions, ref)
	}
	j.fence.stream.Publish(event)
}

// scopeRequestMethod / scopeRequestURL / scopeRequestFlowID read the synthetic
// call the proxy built: arguments JSON {"method":...,"url":...,"flow_id":...}.
func scopeRequestMethod(call *aop.ToolCall) string {
	var value struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(call.GetArguments().GetData(), &value) == nil {
		return value.Method
	}
	return ""
}

// scopeRequestPassive reports whether one Sec-Fetch-Dest value names a
// passive subresource a page pulls by itself (scripts, stylesheets, images,
// fonts). Navigations (document) and API calls (empty) are deliberate
// requests and stay judgeable; anything unrecognized is not passive. The
// policy lives here since E3: the proxy carries the raw hint, the fence
// decides what it means. A call without the field — an old proxy, or a
// hand-built judge request — is not passive.
func scopeRequestPassive(call *aop.ToolCall) bool {
	var value struct {
		Dest    string `json:"dest"`
		Passive bool   `json:"passive"`
	}
	if json.Unmarshal(call.GetArguments().GetData(), &value) != nil {
		return false
	}
	if value.Dest != "" {
		return passiveDest(value.Dest)
	}
	// A call without the raw hint — an old proxy, or a hand-built judge
	// request like the acceptance corpus — carries the explicit verdict of
	// the old wire format instead.
	return value.Passive
}

// passiveDest reports whether one Sec-Fetch-Dest value names a passive
// subresource a page pulls by itself (scripts, stylesheets, images, fonts).
// Navigations (document) and API calls (empty) are deliberate requests and
// stay judgeable; anything unrecognized is not passive.
func passiveDest(dest string) bool {
	switch strings.ToLower(strings.TrimSpace(dest)) {
	case "script", "style", "image", "font":
		return true
	}
	return false
}

// scopeRefusal is the synthetic reply a block (or refused review) produces.
// 403 with a small JSON body: the tool that issued the request sees an HTTP
// failure, not a transport error. The body states WHY, so a model reading its
// tool output can stop retrying on its own: pending marks the allowlist
// fallback (the host is out of range and queued for the operator's approval —
// repeating the request cannot admit it), and reason carries the judge's
// verdict prose.
func scopeRefusal(rawURL string, verdict scoperules.Verdict) *mitmproxy.Response {
	pending := verdict.DefaultMissed && verdict.Action == scoperules.ActionReview
	body, _ := json.Marshal(map[string]any{
		"error":   "scope_rules_refused",
		"host":    scoperules.RequestHost(rawURL),
		"reason":  verdict.Reason,
		"pending": pending,
	})
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	return &mitmproxy.Response{StatusCode: http.StatusForbidden, Header: header, Body: body}
}

func scopeRequestURL(call *aop.ToolCall) string {
	var value struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(call.GetArguments().GetData(), &value) == nil {
		return value.URL
	}
	return ""
}

func scopeRequestFlowID(call *aop.ToolCall) string {
	var value struct {
		FlowID string `json:"flow_id"`
	}
	if json.Unmarshal(call.GetArguments().GetData(), &value) == nil {
		return value.FlowID
	}
	return ""
}

func scopeActionEnum(action string) guardrailext.Action {
	switch action {
	case scoperules.ActionRecord:
		return guardrailext.Action_ACTION_RECORD
	case scoperules.ActionReview:
		return guardrailext.Action_ACTION_REVIEW
	case scoperules.ActionBlock:
		return guardrailext.Action_ACTION_BLOCK
	}
	return guardrailext.Action_ACTION_UNSPECIFIED
}
