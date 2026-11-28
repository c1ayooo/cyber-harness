package fence

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	aop "github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	"google.golang.org/protobuf/types/known/anypb"
)

// scopeRuntime builds a runtime with no provider policy: scope rules must
// judge even when no model judge is configured.
func scopeRuntime(t *testing.T) (*ScopeJudge, *guardrailext.Runtime, func() []guardrailEvent) {
	installStores(t)
	t.Helper()
	stream := events.New()
	var mu sync.Mutex
	collected := make([]guardrailEvent, 0, 4)
	stream.Observe(func(event *aop.Event) {
		mu.Lock()
		collected = append(collected, guardrailEvent{SessionID: event.GetSessionId(), TurnID: event.GetTurnId(), Payload: event.GetExtension()})
		mu.Unlock()
	})
	runtime := newApprovalRuntime(t, stream)
	e := testFenceWith(stream)
	e.Bind(runtime)
	judge := NewScopeJudge(e)
	return judge, runtime, func() []guardrailEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]guardrailEvent(nil), collected...)
	}
}

type guardrailEvent struct {
	SessionID string
	TurnID    string
	Payload   *anypb.Any
}

const scopeSetJSON = `{"enabled":true,"default_action":"review","rules":[{"id":"sr-1","action":"block","method":"*","host":"*.blocked.test"},{"id":"sr-2","action":"record","method":"GET","host":"api.ok.test"}]}`

func scopeCall(t *testing.T, flowID, method, url string) *aop.ToolCall {
	t.Helper()
	arguments, err := json.Marshal(map[string]string{"method": method, "url": url, "flow_id": flowID})
	if err != nil {
		t.Fatal(err)
	}
	return &aop.ToolCall{Name: scoperules.ScopeCallToolName, Arguments: &aop.EncodedValue{Data: arguments}}
}

func scopeRequest(sessionID string, call *aop.ToolCall) scoperules.ScopeRequest {
	return scoperules.ScopeRequest{
		Invocation: operation.Invocation{SessionID: sessionID, TurnID: "turn-1"},
		Call:       call,
		Operation:  &operationpb.Ref{OperationId: "op-http-1", CallId: "call-1"},
	}
}

func TestJudgeScopeRequestRecordGoesToSidecarOnly(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-1", "GET", "https://api.ok.test/v1")))
	if !decision.Judged || decision.Action != scoperules.ActionRecord || decision.RuleID != "sr-2" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Hold != nil {
		t.Fatal("record verdict must not hold")
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("record verdict published %d events, want 0 (sidecar only)", len(events))
	}
	verdict, ok := scoperules.TakeVerdict("flow-1")
	if !ok || verdict.Action != scoperules.ActionRecord {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

func TestJudgeScopeRequestBlockEmitsDecision(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-2", "POST", "https://sub.blocked.test/x")))
	if !decision.Judged || decision.Action != scoperules.ActionBlock || decision.RuleID != "sr-1" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Hold != nil {
		t.Fatal("block verdict must not hold")
	}
	events := collected()
	if len(events) != 1 {
		t.Fatalf("block published %d events, want 1 Decision", len(events))
	}
	var payload guardrailext.Decision
	if extension := events[0].Payload; extension == nil || !extension.MessageIs(&payload) || extension.UnmarshalTo(&payload) != nil {
		// MessageIs + UnmarshalTo in one condition mirrors runtime_test style.
		if extension == nil {
			t.Fatal("no payload")
		}
		_ = extension.UnmarshalTo(&payload)
	}
	if payload.Action != guardrailext.Action_ACTION_BLOCK {
		t.Fatalf("decision payload action = %v", payload.Action)
	}
	if events[0].SessionID != "sess-a" || events[0].TurnID != "turn-1" {
		t.Fatalf("event identity = %s/%s", events[0].SessionID, events[0].TurnID)
	}
}

// An explicit review row still holds the request on the pending lifecycle:
// the operator's own row named this exact request shape as human-decision
// territory, which is different from the default miss (refused quietly, the
// asset-pending flow owns that approval).
func TestJudgeScopeRequestReviewHoldsAndResolves(t *testing.T) {
	judge, runtime, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-review","action":"review","method":"*","host":"held.test"}]}`)); err != nil {
		t.Fatal(err)
	}
	req := scopeRequest("sess-a", scopeCall(t, "flow-3", "PUT", "https://held.test/admin"))
	done := make(chan scoperules.ScopeDecision, 1)
	go func() { done <- judge.JudgeScopeRequest(req) }()

	var decision scoperules.ScopeDecision
	select {
	case decision = <-done:
		t.Fatal("review returned without an operator answer")
	case <-time.After(100 * time.Millisecond):
	}

	events := collected()
	if len(events) != 1 {
		t.Fatalf("review published %d events, want the pending Review", len(events))
	}
	var review guardrailext.Review
	if extension := events[0].Payload; extension == nil || !extension.MessageIs(&review) || extension.UnmarshalTo(&review) != nil {
		if extension == nil {
			t.Fatal("no payload")
		}
		_ = extension.UnmarshalTo(&review)
	}
	if review.State != guardrailext.ReviewState_REVIEW_STATE_PENDING || review.GetCall().GetName() != scoperules.ScopeCallToolName {
		t.Fatalf("review state = %v call = %q", review.GetState(), review.GetCall().GetName())
	}

	// The operator resolves through the ordinary RPC path: the invocation
	// context carries the owning session.
	ctx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "sess-a", Emitter: "control"})
	if err := runtime.Resolve(ctx, "op-http-1", true); err != nil {
		t.Fatal(err)
	}
	select {
	case decision = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("review did not return after approval")
	}
	if decision.Hold == nil || !decision.Hold(context.Background()) {
		t.Fatal("approved review must forward")
	}
	// The resolution emitted the terminal Review event.
	events = collected()
	if len(events) != 2 {
		t.Fatalf("after resolve: %d events, want 2", len(events))
	}
	verdict, ok := scoperules.TakeVerdict("flow-3")
	if !ok || verdict.Action != scoperules.ActionReview || verdict.DefaultMissed {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

// A miss under the pending default refuses immediately (spec #1 工单4): the
// request is dead, not held. Holding would block the whole run for a decision
// that cannot admit the asset anyway — approving one request leaves the asset
// out of range — and a concurrent twin would be refused regardless. The
// refusal is quiet like a record verdict (one tool call fans out into many
// requests; the sidecar carries default_missed and the control plane's
// asset-pending flow owns the approval).
func TestJudgeScopeRequestDefaultMissRefusesWithoutHold(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	done := make(chan scoperules.ScopeDecision, 1)
	go func() {
		done <- judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-9", "PUT", "https://any.test/admin")))
	}()
	var decision scoperules.ScopeDecision
	select {
	case decision = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("default miss held the request instead of refusing")
	}
	if !decision.Judged || decision.Action != scoperules.ActionReview || decision.Hold != nil {
		t.Fatalf("decision = %+v", decision)
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("default miss published %d events, want 0 (sidecar only)", len(events))
	}
	verdict, ok := scoperules.TakeVerdict("flow-9")
	if !ok || verdict.Action != scoperules.ActionReview || !verdict.DefaultMissed {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

// The instance fence wins before the project fence: a project row
// allowlisting a globally denied domain does not un-denied it (spec #1 工单3).
// The refusal publishes a Decision (an audit row worth its journal line) and
// the sidecar names the global entry, not a project rule.
func TestJudgeScopeRequestGlobalDomainWinsOverProjectAllowlist(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-g", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-ok","action":"record","method":"*","host":"gov.cn"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := testFence.globals.SetRules("sess-g", []byte(`{"enabled_domains":true,"domains":[{"id":"gf-10","host":"gov.cn"}]}`)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-g", scopeCall(t, "flow-20", "GET", "https://www.gov.cn/x")))
	if !decision.Judged || decision.Action != scoperules.ActionBlock || decision.RuleID != "global:gf-10" || decision.Hold != nil {
		t.Fatalf("decision = %+v", decision)
	}
	events := collected()
	if len(events) != 1 {
		t.Fatalf("global refusal published %d events, want one Decision", len(events))
	}
	verdict, ok := scoperules.TakeVerdict("flow-20")
	if !ok || verdict.Action != scoperules.ActionBlock || verdict.RuleID != "global:gf-10" {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

// The CONNECT judge: a hostname row passes the tunnel quietly (relay mode's
// pass/fail IS the fence), an unmatched tunnel refuses under the default
// without holding, and a globally denied domain refuses with an audit event.
func TestJudgeScopeConnect(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-c", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-host","action":"record","method":"GET","host":"allowed.test"}]}`)); err != nil {
		t.Fatal(err)
	}
	quiet := judge.JudgeScopeConnect(scopeRequest("sess-c", scopeCall(t, "flow-30", "CONNECT", "allowed.test:443")))
	if !quiet.Judged || quiet.Action != scoperules.ActionRecord || quiet.Hold != nil {
		t.Fatalf("allowed tunnel = %+v", quiet)
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("allowed tunnel published %d events", len(events))
	}
	refused := judge.JudgeScopeConnect(scopeRequest("sess-c", scopeCall(t, "flow-31", "CONNECT", "unknown.test:443")))
	if !refused.Judged || refused.Hold != nil || refused.Action != scoperules.ActionRecord {
		t.Fatalf("unmatched tunnel = %+v (record default forwards; review default would refuse)", refused)
	}

	// Global denial wins over a project allowlist, on the tunnel itself.
	if err := testFence.globals.SetRules("sess-c", []byte(`{"enabled_domains":true,"domains":[{"id":"gf-10","host":"gov.cn"}]}`)); err != nil {
		t.Fatal(err)
	}
	denied := judge.JudgeScopeConnect(scopeRequest("sess-c", scopeCall(t, "flow-32", "CONNECT", "www.gov.cn:443")))
	if !denied.Judged || denied.Action != scoperules.ActionBlock || denied.RuleID != "global:gf-10" {
		t.Fatalf("global-denied tunnel = %+v", denied)
	}
	if events := collected(); len(events) != 1 {
		t.Fatalf("global tunnel refusal published %d events, want one Decision", len(events))
	}
}

func TestJudgeScopeRequestReviewWithoutOperationRefuses(t *testing.T) {
	// An explicit review row with no operation id cannot be answered by the
	// control plane: refuse rather than hold forever. (The default miss no
	// longer reaches the hold path at all — see the default-miss test.)
	judge, _, _ := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-review","action":"review","method":"*","host":"held.test"}]}`)); err != nil {
		t.Fatal(err)
	}
	req := scopeRequest("sess-a", scopeCall(t, "flow-4", "GET", "https://held.test/"))
	req.Operation = &operationpb.Ref{}
	decision := judge.JudgeScopeRequest(req)
	if !decision.Judged || decision.Hold == nil || decision.Hold(context.Background()) {
		t.Fatalf("unanswerable review must refuse: %+v", decision)
	}
}

func TestJudgeScopeRequestUnjudgedInputs(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	// A session without a registered set is never judged.
	if decision := judge.JudgeScopeRequest(scopeRequest("sess-other", scopeCall(t, "flow-5", "GET", "https://api.ok.test/"))); decision.Judged {
		t.Fatalf("unregistered session judged: %+v", decision)
	}
	// An unattributed request is never judged (the proxy guards this too).
	req := scopeRequest("", scopeCall(t, "flow-6", "POST", "https://sub.blocked.test/x"))
	if decision := judge.JudgeScopeRequest(req); decision.Judged {
		t.Fatalf("unattributed request judged: %+v", decision)
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("unjudged requests published events: %d", len(events))
	}
}

func TestJudgeScopeRequestShadowNeverHolds(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"shadow":true,"default_action":"review","rules":[{"id":"sr-9","action":"block","method":"*","host":"*"}]}`)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-7", "GET", "https://whatever.test/")))
	if !decision.Judged || decision.Action != scoperules.ActionBlock || decision.Hold != nil {
		t.Fatalf("shadow decision = %+v", decision)
	}
	if events := collected(); len(events) != 0 {
		// Shadow records the verdict to the sidecar only; nothing to answer.
		t.Fatalf("shadow published %d events", len(events))
	}
	if verdict, ok := scoperules.TakeVerdict("flow-7"); !ok || verdict.Action != scoperules.ActionBlock || !verdict.Shadow {
		t.Fatalf("shadow sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

// scopeCallPassive is scopeCall with the passive hint the proxy attaches to a
// page-pulled static subresource.
func scopeCallPassive(t *testing.T, flowID, method, url string) *aop.ToolCall {
	t.Helper()
	arguments, err := json.Marshal(map[string]any{"method": method, "url": url, "flow_id": flowID, "dest": "script", "passive": true})
	if err != nil {
		t.Fatal(err)
	}
	return &aop.ToolCall{Name: scoperules.ScopeCallToolName, Arguments: &aop.EncodedValue{Data: arguments}}
}

// The decision carries the verdict verbatim (fork patch 33): the proxy's
// sidecar keeps default_missed instead of a projection of the action, which
// is the flag the control plane's asset-pending flow routes on.
func TestJudgeScopeRequestCarriesVerdictVerbatim(t *testing.T) {
	judge, _, _ := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-11", "GET", "https://any.test/x")))
	if decision.Verdict == nil || decision.Verdict.Action != scoperules.ActionReview || !decision.Verdict.DefaultMissed {
		t.Fatalf("decision verdict = %+v", decision.Verdict)
	}
}

// A page-pulled static subresource (Sec-Fetch-Dest script/style/image/font)
// that misses the rule table is a record, not a pending asset: forwarded,
// journaled in the traffic view, never routed to the approval flow (fork
// patch 34). A deliberate request under the same rules stays a miss.
func TestJudgeScopeRequestPassiveMissRecordsWithoutPending(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCallPassive(t, "flow-12", "GET", "https://cdn.test/app.js")))
	if !decision.Judged || decision.Action != scoperules.ActionRecord || decision.Hold != nil {
		t.Fatalf("passive decision = %+v", decision)
	}
	if decision.Verdict == nil || !decision.Verdict.Passive || decision.Verdict.DefaultMissed {
		t.Fatalf("passive verdict = %+v", decision.Verdict)
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("passive miss published %d events, want 0 (sidecar only)", len(events))
	}
	verdict, ok := scoperules.TakeVerdict("flow-12")
	if !ok || verdict.Action != scoperules.ActionRecord || !verdict.Passive || verdict.DefaultMissed {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}

	deliberate := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-13", "GET", "https://cdn.test/api")))
	if deliberate.Verdict == nil || deliberate.Verdict.Passive || !deliberate.Verdict.DefaultMissed {
		t.Fatalf("deliberate verdict = %+v", deliberate.Verdict)
	}
}

// An explicit rule row outranks the passive hint: a subresource the operator
// blocked by row still blocks, and its verdict is the operator's own (fork
// patch 34).
func TestJudgeScopeRequestExplicitRowBeatsPassive(t *testing.T) {
	judge, _, collected := scopeRuntime(t)
	if err := testFence.scopes.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-no","action":"block","method":"*","host":"blocked.test"}]}`)); err != nil {
		t.Fatal(err)
	}
	decision := judge.JudgeScopeRequest(scopeRequest("sess-a", scopeCallPassive(t, "flow-14", "GET", "https://blocked.test/app.js")))
	if !decision.Judged || decision.Action != scoperules.ActionBlock || decision.RuleID != "sr-no" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Verdict == nil || decision.Verdict.Passive || decision.Verdict.DefaultMissed {
		t.Fatalf("verdict = %+v", decision.Verdict)
	}
	if events := collected(); len(events) != 1 {
		t.Fatalf("explicit block published %d events, want the one Decision", len(events))
	}
}
