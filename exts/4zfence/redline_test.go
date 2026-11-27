package fence

// The instance fence (spec #1 工单3) judges on the fence's own tool.before
// hook, before every policy concern: a deny red line refuses even when no
// provider is configured, and a review red line holds the call on the
// ordinary approval lifecycle (guardrail's pending queue, via SubmitReview).

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	"google.golang.org/protobuf/types/known/anypb"
)

type redlineEvent struct {
	SessionID string
	TurnID    string
	Payload   *anypbAny
}

// anypbAny is an alias shim so the ported tests read like their guardrail
// originals.
type anypbAny = anypb.Any

func redlineFixture(t *testing.T) (*Extension, *guardrailext.Runtime, func() []redlineEvent) {
	t.Helper()
	stream := events.New()
	var mu sync.Mutex
	var collected []redlineEvent
	stream.Observe(func(event *aop.Event) {
		mu.Lock()
		collected = append(collected, redlineEvent{SessionID: event.GetSessionId(), TurnID: event.GetTurnId(), Payload: event.GetExtension()})
		mu.Unlock()
	})
	rt := guardrailext.NewRuntime(t.Context(), stream, 2*time.Second, guardrailext.ModeAuto)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rt.Close(ctx)
	})
	e := &Extension{stream: stream}
	e.Bind(rt)
	return e, rt, func() []redlineEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]redlineEvent(nil), collected...)
	}
}

// The instance fence (spec #1 工单3) judges after the guaranteed audit and
// before every policy concern: a deny red line refuses even when no provider
// is configured, and a review red line holds the call on the ordinary
// approval lifecycle. The deny's audit reason carries the global.<id> prefix
// the control plane badges. (The deny pattern deliberately avoids the builtin
// corpus so the event count stays one per verdict.)
func TestAdmitInstanceCommandFence(t *testing.T) {
	e, rt, collected := redlineFixture(t)
	if err := globalfence.SetRules("sess-gf", []byte(`{
		"enabled_commands": true,
		"commands": [
			{"id": "gf-1", "pattern": "shutdown\\s+-h\\b", "desc": "关机", "action": "deny"},
			{"id": "gf-2", "pattern": "^curl\\b", "action": "review"}
		],
		"enabled_domains": true,
		"domains": [{"id": "gf-10", "host": "gov.cn"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	invocation := operation.Invocation{SessionID: "sess-gf", TurnID: "turn-1"}
	ctx := operation.ContextWithInvocation(context.Background(), invocation)

	deny, _ := e.admit(ctx, toolhooks.CallEvent{
		Call:      &aop.ToolCall{Name: "bash", Arguments: &aop.EncodedValue{Data: []byte(`{"command":"shutdown -h now"}`)}},
		Operation: &operationpb.Ref{OperationId: "op-gf-deny"},
	})
	if deny.Deny == nil {
		t.Fatal("a deny red line passed")
	}
	events := collected()
	if len(events) != 1 {
		t.Fatalf("deny published %d events, want one global Decision", len(events))
	}
	var decision guardrailext.Decision
	if extension := events[0].Payload; extension == nil || !extension.MessageIs(&decision) || extension.UnmarshalTo(&decision) != nil {
		t.Fatal("deny payload is not a Decision")
	}
	if decision.Action != guardrailext.Action_ACTION_BLOCK || !strings.HasPrefix(decision.Reason, "global.gf-1") {
		t.Fatalf("deny decision = %v %q", decision.Action, decision.Reason)
	}

	// A review red line holds the call: unapproved, it refuses; the operator's
	// approval through the ordinary RPC releases it.
	done := make(chan toolhooks.Admission, 1)
	go func() {
		admission, _ := e.admit(ctx, toolhooks.CallEvent{
			Call:      &aop.ToolCall{Name: "bash", Arguments: &aop.EncodedValue{Data: []byte(`{"command":"curl https://example.test"}`)}},
			Operation: &operationpb.Ref{OperationId: "op-gf-review"},
		})
		done <- admission
	}()
	deadline := time.After(2 * time.Second)
	var pending bool
	for !pending {
		select {
		case <-deadline:
			t.Fatal("review red line neither held nor resolved")
		default:
			pending = len(collected()) > 1
			if !pending {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	resolveCtx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "sess-gf", Emitter: "control"})
	if err := rt.Resolve(resolveCtx, "op-gf-review", true); err != nil {
		t.Fatal(err)
	}
	select {
	case admission := <-done:
		if admission.Deny != nil {
			t.Fatalf("approved red line still denied: %v", admission.Deny)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval did not release the held call")
	}
}

// Command red lines judge command-like calls only (fork patch 35): a write
// tool whose content quotes a blocked command is a document, not a command —
// judging its text would hold every report that mentions one. A bare-string
// argument IS a command and stays judged.
func TestAdmitInstanceCommandFenceSkipsNonCommandCalls(t *testing.T) {
	e, _, collected := redlineFixture(t)
	if err := globalfence.SetRules("sess-gf-doc", []byte(`{
		"enabled_commands": true,
		"commands": [{"id": "gf-doc", "pattern": "shutdown\\s+-h\\b", "desc": "关机", "action": "deny"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	invocation := operation.Invocation{SessionID: "sess-gf-doc", TurnID: "turn-1"}
	ctx := operation.ContextWithInvocation(context.Background(), invocation)

	allowed, _ := e.admit(ctx, toolhooks.CallEvent{
		Call:      &aop.ToolCall{Name: "write", Arguments: &aop.EncodedValue{Data: []byte(`{"path":"/tmp/report.md","content":"to shut down the host run shutdown -h now"}`)}},
		Operation: &operationpb.Ref{OperationId: "op-gf-doc"},
	})
	if allowed.Deny != nil {
		t.Fatalf("a document quoting a red line was denied: %v", allowed.Deny)
	}
	if events := len(collected()); events != 0 {
		t.Fatalf("non-command call published %d events, want 0", events)
	}

	denied, _ := e.admit(ctx, toolhooks.CallEvent{
		Call:      &aop.ToolCall{Name: "exec", Arguments: &aop.EncodedValue{Data: []byte(`"shutdown -h now"`)}},
		Operation: &operationpb.Ref{OperationId: "op-gf-doc-2"},
	})
	if denied.Deny == nil {
		t.Fatal("a bare-string command was not judged")
	}
}
