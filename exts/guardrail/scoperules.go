package guardrail

import (
	"context"
	"encoding/json"
	"time"

	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/operation"
	"github.com/c1ayooo/cyber/core/scoperules"
	"github.com/c1ayooo/cyber/tools/proxy"
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
	verdict, judged := scoperules.JudgeSession(req.Invocation.SessionID, scopeRequestMethod(req.Call), scopeRequestURL(req.Call))
	if !judged {
		return proxy.ScopeDecision{}
	}
	ctx := operation.ContextWithInvocation(r.ctx, req.Invocation)
	scoperules.RecordVerdict(scopeRequestFlowID(req.Call), verdict)
	if verdict.Shadow || verdict.Action == scoperules.ActionRecord {
		// Quiet fact: the sidecar carries it; no interception to journal.
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason}
	}
	decision := &Decision{Action: scopeActionEnum(verdict.Action), Reason: verdict.Reason}
	if verdict.Action == scoperules.ActionBlock {
		r.emitScope(ctx, decision, req)
		return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason}
	}
	// Review: hold the request on the pending-review lifecycle. The operator
	// answers through the ordinary guardrail Pending/Resolve RPC; expiry uses
	// the runtime's own review timeout.
	approved := r.holdScopeRequest(ctx, req, decision)
	return proxy.ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Hold: func(context.Context) bool { return approved }}
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
