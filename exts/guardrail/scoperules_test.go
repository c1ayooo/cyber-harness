package guardrail

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	aop "github.com/c1ayooo/cyber/aop"
	operationpb "github.com/c1ayooo/cyber/aop/operation"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/operation"
	"github.com/c1ayooo/cyber/core/scoperules"
	"github.com/c1ayooo/cyber/tools/proxy"
	"google.golang.org/protobuf/types/known/anypb"
)

// scopeRuntime builds a runtime with no provider policy: scope rules must
// judge even when no model judge is configured.
func scopeRuntime(t *testing.T) (*Runtime, func() []guardrailEvent) {
	t.Helper()
	stream := events.New()
	var mu sync.Mutex
	collected := make([]guardrailEvent, 0, 4)
	stream.Observe(testObserver(func(event *aop.Event) {
		mu.Lock()
		collected = append(collected, guardrailEvent{SessionID: event.GetSessionId(), TurnID: event.GetTurnId(), Payload: event.GetExtension()})
		mu.Unlock()
	}))
	runtime := newRuntimeWithPolicy(t.Context(), stream, runtimeOptions{timeout: 2 * time.Second}, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = runtime.Close(ctx)
	})
	return runtime, func() []guardrailEvent {
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
	return &aop.ToolCall{Name: httpRequestToolName, Arguments: &aop.EncodedValue{Data: arguments}}
}

func scopeRequest(sessionID string, call *aop.ToolCall) proxy.ScopeRequest {
	return proxy.ScopeRequest{
		Invocation: operation.Invocation{SessionID: sessionID, TurnID: "turn-1"},
		Call:       call,
		Operation:  &operationpb.Ref{OperationId: "op-http-1", CallId: "call-1"},
	}
}

func TestJudgeScopeRequestRecordGoesToSidecarOnly(t *testing.T) {
	runtime, collected := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	decision := runtime.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-1", "GET", "https://api.ok.test/v1")))
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
	runtime, collected := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	decision := runtime.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-2", "POST", "https://sub.blocked.test/x")))
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
	var payload Decision
	if extension := events[0].Payload; extension == nil || !extension.MessageIs(&payload) || extension.UnmarshalTo(&payload) != nil {
		// MessageIs + UnmarshalTo in one condition mirrors runtime_test style.
		if extension == nil {
			t.Fatal("no payload")
		}
		_ = extension.UnmarshalTo(&payload)
	}
	if payload.Action != Action_ACTION_BLOCK {
		t.Fatalf("decision payload action = %v", payload.Action)
	}
	if events[0].SessionID != "sess-a" || events[0].TurnID != "turn-1" {
		t.Fatalf("event identity = %s/%s", events[0].SessionID, events[0].TurnID)
	}
}

func TestJudgeScopeRequestReviewHoldsAndResolves(t *testing.T) {
	runtime, collected := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	req := scopeRequest("sess-a", scopeCall(t, "flow-3", "PUT", "https://any.test/admin"))
	done := make(chan proxy.ScopeDecision, 1)
	go func() { done <- runtime.JudgeScopeRequest(req) }()

	var decision proxy.ScopeDecision
	select {
	case decision = <-done:
		t.Fatal("review returned without an operator answer")
	case <-time.After(100 * time.Millisecond):
	}

	events := collected()
	if len(events) != 1 {
		t.Fatalf("review published %d events, want the pending Review", len(events))
	}
	var review Review
	if extension := events[0].Payload; extension == nil || !extension.MessageIs(&review) || extension.UnmarshalTo(&review) != nil {
		if extension == nil {
			t.Fatal("no payload")
		}
		_ = extension.UnmarshalTo(&review)
	}
	if review.State != ReviewState_REVIEW_STATE_PENDING || review.GetCall().GetName() != httpRequestToolName {
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
}

func TestJudgeScopeRequestReviewWithoutOperationRefuses(t *testing.T) {
	runtime, _ := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	req := scopeRequest("sess-a", scopeCall(t, "flow-4", "GET", "https://any.test/"))
	req.Operation = &operationpb.Ref{}
	decision := runtime.JudgeScopeRequest(req)
	if !decision.Judged || decision.Hold == nil || decision.Hold(context.Background()) {
		t.Fatalf("unanswerable review must refuse: %+v", decision)
	}
}

func TestJudgeScopeRequestUnjudgedInputs(t *testing.T) {
	runtime, collected := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(scopeSetJSON)); err != nil {
		t.Fatal(err)
	}
	// A session without a registered set is never judged.
	if decision := runtime.JudgeScopeRequest(scopeRequest("sess-other", scopeCall(t, "flow-5", "GET", "https://api.ok.test/"))); decision.Judged {
		t.Fatalf("unregistered session judged: %+v", decision)
	}
	// An unattributed request is never judged (the proxy guards this too).
	req := scopeRequest("", scopeCall(t, "flow-6", "POST", "https://sub.blocked.test/x"))
	if decision := runtime.JudgeScopeRequest(req); decision.Judged {
		t.Fatalf("unattributed request judged: %+v", decision)
	}
	if events := collected(); len(events) != 0 {
		t.Fatalf("unjudged requests published events: %d", len(events))
	}
}

func TestJudgeScopeRequestShadowNeverHolds(t *testing.T) {
	runtime, collected := scopeRuntime(t)
	if err := scoperules.SetRules("sess-a", []byte(`{"enabled":true,"shadow":true,"default_action":"review","rules":[{"id":"sr-9","action":"block","method":"*","host":"*"}]}`)); err != nil {
		t.Fatal(err)
	}
	decision := runtime.JudgeScopeRequest(scopeRequest("sess-a", scopeCall(t, "flow-7", "GET", "https://whatever.test/")))
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
