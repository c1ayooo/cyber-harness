package fence

// The fence's own tool admission (4zrcin docs/19 P1-4): the guaranteed audit
// (fork patch 23b) and the instance fence red lines judge on a tool.before
// hook registered ahead of the guardrail extension, so a red line denies —
// or holds on the ordinary approval lifecycle via guardrail's SubmitReview
// seam (G3) — before any policy concern, and no provider state can suppress
// the audit. The guardrail runtime keeps its policy providers (JEV, LLM,
// hybrid) as the approval queue; the two judges compose through the veto
// reducer (first deny wins) and never import each other's admission logic.
//
// The guardrail runtime reaches this extension through Bind, called by a
// one-line composition hook after both extensions load (fence must subscribe
// before guardrail, so it cannot resolve the runtime in its own Load).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
)

// Bind the guardrail runtime whose journal shape and approval lifecycle the
// fence composes with. Called by the composition after both extensions load.
func (e *Extension) Bind(rt *guardrailext.Runtime) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.guardrail = rt
}

// admit is the fence's tool.before handler: the guaranteed audit, then the
// instance fence. An empty admission hands the call to the next judge.
func (e *Extension) admit(ctx context.Context, ev toolhooks.CallEvent) (toolhooks.Admission, error) {
	// The guaranteed audit: record-only, before every policy concern.
	if reason := BuiltinCommandReason(ev.Call); reason != "" {
		e.emitDecision(ctx, &guardrailext.Decision{Action: guardrailext.Action_ACTION_RECORD, Reason: reason}, ev)
	}
	// The instance fence: only command-like calls are judged (fork patch 35) —
	// a pattern is a statement about commands, and a write tool whose content
	// quotes "rm -rf /" is a document, not one. Other calls skip the red lines
	// but still reach the policy judge (docs/19 E3-3).
	if commandLikeCall(ev.Call) {
		rule, hit := globalfence.JudgeCommand(operation.InvocationFromContext(ctx).SessionID, commandText(ev.Call))
		if hit {
			return e.redLine(ctx, ev, rule)
		}
	}
	// The policy judge (docs/19 E3-3) runs last: a red line denies — or holds
	// — before any model judge sees the invocation.
	return e.judge(ctx, ev, e.options)
}

// redLine enforces one instance-fence row: a deny refuses here, a review
// holds on the ordinary approval lifecycle. The operator decides this exact
// invocation, not a model judge. The bound guardrail runtime owns the
// pending queue; without it the hold cannot happen, so the fence fails
// closed.
func (e *Extension) redLine(ctx context.Context, ev toolhooks.CallEvent, rule globalfence.CommandRule) (toolhooks.Admission, error) {
	reason := "global." + rule.ID
	if rule.Desc != "" {
		reason += "（" + rule.Desc + "）"
	}
	decision := &guardrailext.Decision{Action: guardrailext.Action_ACTION_BLOCK, Reason: reason}
	if rule.Action == globalfence.ActionDeny {
		e.emitDecision(ctx, decision, ev)
		return denied(reason), nil
	}
	// A review red line holds on the ordinary approval lifecycle: the
	// operator decides this exact invocation, not a model judge. The bound
	// guardrail runtime owns the pending queue; without it the hold cannot
	// happen, so the fence fails closed.
	e.mu.Lock()
	rt := e.guardrail
	e.mu.Unlock()
	if rt == nil {
		return denied(reason + "（fence admission is not bound to a guardrail runtime）"), nil
	}
	if admission := rt.SubmitReview(ctx, ev, decision); admission.Deny == nil {
		return admission, nil
	}
	return denied(reason), nil
}

// denied builds the admission denial the guardrail journal already uses.
func denied(reason string) toolhooks.Admission {
	return toolhooks.Admission{Deny: fmt.Errorf("%w: %s", operation.ErrDenied, reason)}
}

// emitDecision publishes one decision event in the guardrail journal shape
// (the emitter stays "guardrail" so the control plane renders fence rows
// exactly like admission rows).
func (e *Extension) emitDecision(ctx context.Context, decision protobuf.Message, ev toolhooks.CallEvent) {
	invocation := operation.InvocationFromContext(ctx)
	encoded, err := anypb.New(decision)
	if err != nil {
		return
	}
	event := &aop.Event{
		SessionId: invocation.SessionID, TurnId: invocation.TurnID, Emitter: "guardrail",
		Payload: &aop.Event_Extension{Extension: encoded},
	}
	if ev.Operation != nil {
		if ref, err := anypb.New(ev.Operation); err == nil {
			event.Extensions = append(event.Extensions, ref)
		}
	}
	e.stream.Publish(event)
}

// commandLikeCall reports whether a tool call IS a command — its arguments
// are a bare command string, or an object carrying one of the documented
// command fields (fork patch 35). Everything else is a different shape of
// work: a write tool whose content quotes a blocked command is a document.
func commandLikeCall(call *aop.ToolCall) bool {
	if call == nil {
		return false
	}
	raw := call.GetArguments().GetData()
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case map[string]any:
		for _, key := range []string{"command", "cmd", "script", "input", "code"} {
			if text, ok := typed[key].(string); ok && strings.TrimSpace(text) != "" {
				return true
			}
		}
	}
	return false
}
