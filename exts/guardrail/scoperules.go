package guardrail

import (
	"context"
	"encoding/json"
	"time"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/globalfence"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/core/scoperules"
	"github.com/chainreactors/cyber/tools/proxy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Scope-rule judging (Tianwu/4zrcin P3): the control plane's machine-matchable
// test range judges the HTTP requests the proxy forwards, independently of the
// guardrail provider (an unconfigured judge must not disable the operator's
// explicit rule table). The Runtime is the judge because it already owns the
// pending-review lifecycle, the Decision/Review event shape and the redaction
// boundary — a request held for review is exactly a tool call held for review
// with the synthetic tool name "http.request", so the control plane's existing
// Pending/Resolve RPC works unchanged.
//
// Publication policy: record verdicts ride only the flow's TrafficVerdict
// sidecar (core/scoperules registry, consumed by the observe extension) — one
// tool call fans out into many requests, and journaling every record would
// flood the run journal. review and block publish the same Decision/Review
// events a tool interception does, because those are the verdicts an operator
// must see and answer. Shadow judges and publishes but never holds or refuses.

// The synthetic tool name every scope-rule HTTP verdict carries, so a journal
// row reads like any other guardrail interception. Defined here as the single
// documented value; the proxy builds its calls with the same name.
const httpRequestToolName = "http.request"

// JudgeScopeRequest implements proxy.ScopeJudge.
func (r *Runtime) JudgeScopeRequest(req proxy.ScopeRequest) proxy.ScopeDecision {
	if r == nil || req.Call == nil || req.Invocation.SessionID == "" {
		return proxy.ScopeDecision{}
	}
	rawURL := scopeRequestURL(req.Call)
	// The instance fence wins before the project fence (spec #1 工单3): a
	// denied domain refuses even when a project row allowlists it. Domain
	// hits are rare enough that the audit row is worth its journal line, and
	// the sidecar names the global entry so the traffic view shows it. The
	// default-allow list (fork patch 37) sits between them: infrastructure
	// the operator always permits is recorded and forwarded before the
	// project fence can queue it as a pending asset.
	if rule, hit := globalfence.AllowDomainHit(req.Invocation.SessionID, requestHost(rawURL)); hit {
		return r.allowGlobal(req, rule, scopeRequestFlowID(req.Call))
	}
	if rule, hit := globalfence.DomainHit(req.Invocation.SessionID, requestHost(rawURL)); hit {
		return r.refuseGlobal(req, rule, scopeRequestFlowID(req.Call))
	}
	verdict, judged := scoperules.JudgeSession(req.Invocation.SessionID, scopeRequestMethod(req.Call), rawURL)
	if !judged {
		return proxy.ScopeDecision{}
	}
	ctx := operation.ContextWithInvocation(r.ctx, req.Invocation)
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
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	decision := &Decision{Action: scopeActionEnum(verdict.Action), Reason: verdict.Reason}
	if verdict.Action == scoperules.ActionBlock {
		r.emitScope(ctx, decision, req)
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	// Review: hold the request on the pending-review lifecycle. The operator
	// answers through the ordinary guardrail Pending/Resolve RPC; expiry uses
	// the runtime's own review timeout.
	approved := r.holdScopeRequest(ctx, req, decision)
	return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Hold: func(context.Context) bool { return approved }}
}

// allowGlobal records an instance-fence allowance: infrastructure the
// operator always permits (DNS/DoH endpoints, passive intel sources) is
// forwarded and recorded with the global-allow sidecar so the traffic view
// reads it as the operator's own standing, not a project asset. No Decision
// event: unlike a refusal this is not worth a journal line per request — the
// sidecar and the fence audit carry it.
func (r *Runtime) allowGlobal(req proxy.ScopeRequest, rule globalfence.DomainRule, flowID string) proxy.ScopeDecision {
	verdict := scoperules.Verdict{Action: scoperules.ActionRecord,
		RuleID: "global.allow:" + rule.ID, Reason: "基础设施放行 " + rule.ID}
	scoperules.RecordVerdict(flowID, verdict)
	return proxy.ScopeDecision{Judged: true, Action: scoperules.ActionRecord, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict}
}

// refuseGlobal refuses one request (or tunnel) for an instance-fence domain
// hit: the synthetic 403 is the proxy's business — here we publish the audit
// Decision and record the sidecar verdict naming the global entry, so the
// traffic view and the audit trail both show a red line the operator wrote,
// not a project rule.
func (r *Runtime) refuseGlobal(req proxy.ScopeRequest, rule globalfence.DomainRule, flowID string) proxy.ScopeDecision {
	verdict := scoperules.Verdict{Action: scoperules.ActionBlock,
		RuleID: "global:" + rule.ID, Reason: "全局禁访域名 " + rule.ID}
	scoperules.RecordVerdict(flowID, verdict)
	ctx := operation.ContextWithInvocation(r.ctx, req.Invocation)
	r.emitScope(ctx, &Decision{Action: Action_ACTION_BLOCK, Reason: verdict.Reason}, req)
	return proxy.ScopeDecision{Judged: true, Action: scoperules.ActionBlock, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict}
}

// JudgeScopeConnect judges a CONNECT tunnel (fork patch 31): the instance
// fence judges fully; the project fence judges its host form only — rows
// match on host alone (a method/path row refines decrypted inner requests,
// not the tunnel), CIDR rows match literal IPs directly and hostnames through
// the cached resolver, and an unmatched tunnel refuses under the allowlist
// default rather than passing unjudged. Decrypted inner requests carry the
// full judgment; in relay mode this host-form pass/fail IS the fence.
func (r *Runtime) JudgeScopeConnect(req proxy.ScopeRequest) proxy.ScopeDecision {
	if r == nil || req.Call == nil || req.Invocation.SessionID == "" {
		return proxy.ScopeDecision{}
	}
	rawURL := scopeRequestURL(req.Call)
	if rule, hit := globalfence.AllowDomainHit(req.Invocation.SessionID, scoperules.RequestHost(rawURL)); hit {
		return r.allowGlobal(req, rule, scopeRequestFlowID(req.Call))
	}
	if rule, hit := globalfence.DomainHit(req.Invocation.SessionID, scoperules.RequestHost(rawURL)); hit {
		return r.refuseGlobal(req, rule, scopeRequestFlowID(req.Call))
	}
	verdict, judged := scoperules.JudgeSessionConnect(req.Invocation.SessionID, rawURL)
	if !judged {
		return proxy.ScopeDecision{}
	}
	ctx := operation.ContextWithInvocation(r.ctx, req.Invocation)
	scoperules.RecordVerdict(scopeRequestFlowID(req.Call), verdict)
	if verdict.DefaultMissed || verdict.Shadow || verdict.Action == scoperules.ActionRecord {
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	decision := &Decision{Action: scopeActionEnum(verdict.Action), Reason: verdict.Reason}
	if verdict.Action == scoperules.ActionBlock {
		r.emitScope(ctx, decision, req)
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
			Verdict: &verdict}
	}
	approved := r.holdScopeRequest(ctx, req, decision)
	return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Hold: func(context.Context) bool { return approved }}
}

// requestHost extracts the authority a synthetic call's URL names — the
// scoperules helper, which also handles the CONNECT authority form.
func requestHost(rawURL string) string {
	return scoperules.RequestHost(rawURL)
}

// holdScopeRequest publishes a pending Review and blocks until it resolves,
// expires, or the guardrail closes. True only for an explicit approval.
func (r *Runtime) holdScopeRequest(ctx context.Context, req proxy.ScopeRequest, decision *Decision) bool {
	id := req.Operation.GetOperationId()
	if id == "" {
		// Without an operation id the control plane cannot answer; refuse
		// rather than hold forever on an unanswerable review.
		r.emitScope(ctx, decision, req)
		return false
	}
	p := &pending{ctx: ctx, done: make(chan struct{}), review: &Review{
		Call: req.Call, Operation: req.Operation, SessionId: req.Invocation.SessionID,
		Decision: decision, State: ReviewState_REVIEW_STATE_PENDING,
		ExpiresAt: timestamppb.New(time.Now().Add(r.timeout)),
	}}
	r.mu.Lock()
	if r.closed || ctx.Err() != nil || r.pending[id] != nil {
		r.mu.Unlock()
		return false
	}
	r.pending[id] = p
	snapshot := proto.Clone(p.review).(*Review)
	r.mu.Unlock()
	r.emitScope(ctx, snapshot, req)
	timer := time.NewTimer(time.Until(p.review.ExpiresAt.AsTime()))
	defer timer.Stop()
	select {
	case <-p.done:
	case <-ctx.Done():
		r.finish(p, ReviewState_REVIEW_STATE_CANCELED)
	case <-timer.C:
		r.finish(p, ReviewState_REVIEW_STATE_EXPIRED)
	}
	r.mu.Lock()
	state := p.review.State
	snapshot = proto.Clone(p.review).(*Review)
	r.mu.Unlock()
	r.emitScope(ctx, snapshot, req)
	return state == ReviewState_REVIEW_STATE_APPROVED
}

// emitScope publishes one guardrail event in the ordinary interception shape:
// the payload as the extension, the operation ref as the sidecar.
func (r *Runtime) emitScope(ctx context.Context, payload proto.Message, req proxy.ScopeRequest) {
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
	r.stream.Publish(event)
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

// scopeRequestPassive reads the passive hint the proxy attaches to the
// synthetic call (Sec-Fetch-Dest naming a static subresource). A call without
// the field — an old proxy, or a hand-built judge request — is not passive.
func scopeRequestPassive(call *aop.ToolCall) bool {
	var value struct {
		Passive bool `json:"passive"`
	}
	if json.Unmarshal(call.GetArguments().GetData(), &value) != nil {
		return false
	}
	return value.Passive
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

func scopeActionEnum(action string) Action {
	switch action {
	case scoperules.ActionRecord:
		return Action_ACTION_RECORD
	case scoperules.ActionReview:
		return Action_ACTION_REVIEW
	case scoperules.ActionBlock:
		return Action_ACTION_BLOCK
	}
	return Action_ACTION_UNSPECIFIED
}
