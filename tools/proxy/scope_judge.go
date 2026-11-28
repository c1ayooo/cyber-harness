// The scope-judge seam (G2, 4zrcin docs/19 appendix A): the proxy exposes a
// judge interface and delegates each request's verdict to whoever implements
// it — in the fork's composition, the fence's request judge. This file is a
// pure addition relative to upstream: the seam types, the take-once verdict
// registry the sidecar consumer reads, the optional exemption hook, and the
// request-side orchestration (attribution, synthetic call, verdict carry).
// The 4z-specific policy — control-plane exemption, passive subresources, the
// refusal body — lives in exts/4zfence, which implements the interface
// without this package importing it.
package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	aop "github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/aop/payloads"
	traffic "github.com/chainreactors/cyber/aop/traffic"
	"github.com/chainreactors/cyber/core/egress"
	"github.com/chainreactors/cyber/core/operation"
	mitmproxy "github.com/chainreactors/utils/mitmproxy/proxy"
)

// The decision actions a verdict can name. The fence's rule tables spell the
// same values; the seam keeps the literals local so the proxy depends on no
// product package.
const (
	ActionRecord = "record"
	ActionReview = "review"
	ActionBlock  = "block"
)

// ScopeJudge decides whether the proxy may forward one attributed request.
// JudgeScopeConnect judges a CONNECT tunnel (host-form only). Nil keeps the
// proxy a pure capture/routing relay with byte-identical behavior.
type ScopeJudge interface {
	JudgeScopeRequest(req ScopeRequest) ScopeDecision
	JudgeScopeConnect(req ScopeRequest) ScopeDecision
}

// ScopeRequest is one proxied request with its attribution.
type ScopeRequest struct {
	Invocation operation.Invocation
	Call       *aop.ToolCall
	Operation  *operationpb.Ref
}

// ScopeDecision is the judge's answer. Judged=false means "not my business":
// forward untouched. Hold is set only for a review verdict; it blocks until
// the review resolves (true = approved, forward) or expires/is refused
// (false = refuse). Refusal is the synthetic reply the judge wants the
// requester to see when the decision refuses or a hold fails; the proxy
// applies it verbatim.
//
// Verdict is the judge's own verdict, carried verbatim so the capture sidecar
// keeps every field the judge set (default_missed, passive, shadow). When it
// is nil — a stub judge, or a path that answered from the action alone — the
// proxy reconstructs {action, rule_id, reason} as before.
type ScopeDecision struct {
	Judged  bool
	Action  string // record | review | block
	RuleID  string
	Reason  string
	Hold    func(ctx context.Context) bool
	Verdict *ScopeVerdict
	Refusal *mitmproxy.Response
}

// ScopeVerdict is the judge's verdict as the wire sees it. The contract
// payload is the neutral ground every party already shares.
type ScopeVerdict = payloads.TrafficVerdict

// The verdict registry is the take-once handoff between the judge's answers
// and the capture sidecar consumer, bounded like the rule tables: a flow id
// whose verdict is never taken is dropped once 4096 newer answers arrived.
var (
	verdictMu     sync.Mutex
	verdictOrder  []string
	verdictByFlow = map[string]ScopeVerdict{}
)

const maxVerdicts = 4096

// RecordVerdict stores the verdict of one judged request for the sidecar
// consumer to attach as the flow's TrafficVerdict.
func RecordVerdict(flowID string, verdict ScopeVerdict) {
	if flowID == "" {
		return
	}
	verdictMu.Lock()
	defer verdictMu.Unlock()
	if _, exists := verdictByFlow[flowID]; !exists {
		verdictOrder = append(verdictOrder, flowID)
		if len(verdictOrder) > maxVerdicts {
			delete(verdictByFlow, verdictOrder[0])
			verdictOrder = verdictOrder[1:]
		}
	}
	verdictByFlow[flowID] = verdict
}

// TakeVerdict consumes the verdict stored for one flow id.
func TakeVerdict(flowID string) (ScopeVerdict, bool) {
	verdictMu.Lock()
	defer verdictMu.Unlock()
	verdict, ok := verdictByFlow[flowID]
	if ok {
		delete(verdictByFlow, flowID)
	}
	return verdict, ok
}

// SetRequestExemption installs the exemption predicate the proxy consults
// before judging or capturing a request: a host it names is the requester's
// own plumbing — forwarded unjudged and uncaptured. Safe before Start; read
// per request. The composition decides the policy (in the fork, the fence's
// control-plane exemption); an unset hook exempts nothing, which is the
// upstream behavior.
func (h *Hub) SetRequestExemption(exempt func(host string) bool) {
	if h == nil {
		return
	}
	h.exemptMu.Lock()
	defer h.exemptMu.Unlock()
	h.exempt = exempt
}

// exempted reports whether the request host is exempt from judging and capture.
func (h *Hub) exempted(host string) bool {
	if h == nil || host == "" {
		return false
	}
	h.exemptMu.Lock()
	hook := h.exempt
	h.exemptMu.Unlock()
	if hook == nil {
		return false
	}
	return hook(host)
}

// SetScopeJudge installs the test-range judge. Safe before Start; judging
// reads it per request.
func (h *Hub) SetScopeJudge(judge ScopeJudge) {
	if h == nil {
		return
	}
	h.scopeJudge = judge
}

// SetSessionRoutes installs the per-session egress lookup (4zrcin.EgressProxy,
// patch 24): a session the control plane bound to its own project proxy dials
// through that endpoint instead of the node default. An explicit per-call
// dial (the `proxy <url> <cmd>` passthrough) still wins — precedence is
// per-call > per-session > node default. A nil lookup, or one that answers
// nil for the session, keeps the chain in State, byte-identical to the
// upstream behavior. Safe before Start; the egress lease reads it per call.
func (h *Hub) SetSessionRoutes(routes func(sessionID string) egress.Dial) {
	if h == nil {
		return
	}
	h.sessionRoutes = routes
}

// ---------------------------------------------------------------------------
// Request-side orchestration
// ---------------------------------------------------------------------------

type MitmCommand struct {
	store       *FlowStore
	hub         *Hub
	execCommand CommandExecutor
}

// judgeRequest runs the optional test-range judge on one attributed request.
//
// Only requests with a session attribution (a per-execution egress lease) are
// judged: unattributed traffic is the host's own plumbing, not the model's.
// The judge can hold the forwarding goroutine (review) or short-circuit the
// exchange with its synthetic refusal by setting Flow.Response, which the
// mitmproxy engine treats as the final reply. The returned verdict travels on
// the capture state and is keyed by the store's canonical flow id once the
// flow completes, so the observe extension can attach it as the flow's
// TrafficVerdict sidecar.
func (a *captureAddon) judgeRequest(f *mitmproxy.Flow) (ScopeVerdict, bool) {
	if a.hub == nil || a.hub.scopeJudge == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return ScopeVerdict{}, false
	}
	correlation := a.hub.resolveCorrelation(correlationTokenOf(f))
	defer correlation.finish()
	if correlation.invocation.SessionID == "" {
		return ScopeVerdict{}, false
	}
	call := &aop.ToolCall{Name: ScopeCallToolName, Arguments: &aop.EncodedValue{Data: scopeRequestArguments(f)}}
	req := ScopeRequest{Invocation: correlation.invocation, Call: call, Operation: correlation.operation}
	// A CONNECT tunnel is judged host-form only: the tunnel setup carries no
	// method or path, and the decrypted inner requests carry the full judgment
	// on their own.
	var decision ScopeDecision
	if strings.EqualFold(f.Request.Method, http.MethodConnect) {
		decision = a.hub.scopeJudge.JudgeScopeConnect(req)
	} else {
		decision = a.hub.scopeJudge.JudgeScopeRequest(req)
	}
	if !decision.Judged {
		return ScopeVerdict{}, false
	}
	ctx := operation.ContextWithInvocation(context.Background(), correlation.invocation)
	// verdictOf keeps the judge's answer verbatim: the sidecar must carry every
	// field the judge set (default_missed, passive, shadow), not a projection
	// of the action alone. A nil verdict (a stub judge) reconstructs the old
	// three fields.
	verdict := verdictOf(decision)
	switch decision.Action {
	case ActionReview:
		if decision.Hold != nil && decision.Hold(ctx) {
			return verdict, true // approved: forward untouched
		}
		f.Response = decision.Refusal
	case ActionBlock:
		f.Response = decision.Refusal
	}
	return verdict, true
}

// ScopeCallToolName is the synthetic tool name the scope judge's calls carry,
// so a judge's journal rows read like any other interception of this tool.
// It is defined here, where the calls are built; a judge takes it from here.
const ScopeCallToolName = "http.request"

// verdictOf returns the decision's own verdict, or the historical three-field
// reconstruction when the judge did not carry one.
func verdictOf(decision ScopeDecision) ScopeVerdict {
	if decision.Verdict != nil {
		return *decision.Verdict
	}
	return ScopeVerdict{Action: decision.Action, RuleID: decision.RuleID, Reason: decision.Reason}
}

// scopeRequestArguments builds the synthetic call's arguments: the request
// identity the judge reads — method, URL, the flow id the sidecar keys on,
// and the raw Sec-Fetch-Dest hint. Interpreting the hint is the judge's
// policy, not the proxy's.
func scopeRequestArguments(f *mitmproxy.Flow) []byte {
	dest := ""
	if f.Request.Header != nil {
		dest = f.Request.Header.Get("Sec-Fetch-Dest")
	}
	payload, _ := json.Marshal(map[string]any{
		"method":  f.Request.Method,
		"url":     f.Request.URL.String(),
		"flow_id": f.Id.String(),
		"dest":    dest,
	})
	return payload
}

// judged attaches the judge's outcome to a fresh capture state (request
// goroutine): the verdict for the sidecar registry, and the synthetic refusal
// hydrated into the flow — a refused exchange never reaches the engine's
// response stage, so without this it would be invisible in the traffic view.
func (s *captureState) judged(verdict ScopeVerdict, f *mitmproxy.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verdict = &verdict
	if f.Response != nil {
		s.flow.Response = &traffic.HttpResponse{
			StatusCode: int32(f.Response.StatusCode),
			Headers:    traffic.HeadersFromHTTP(f.Response.Header),
			Body:       f.Response.Body,
		}
		s.flow.ContentType = f.Response.Header.Get("Content-Type")
	}
}
