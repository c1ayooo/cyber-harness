package fence

// The fence's policy judge (docs/19 E3-3): the judging half of the old
// guardrail admission — the scope filter, the policy evaluation, the shadow
// and safe-mode releases — moved here, so the fence is the sole judge and
// the guardrail runtime stays only the approval queue. Review holds ride the
// guardrail runtime's ordinary lifecycle through the SubmitReview seam (G3,
// the one registered hook guardrail carries).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	jevapi "github.com/chainreactors/cyber/agent/provider/jev"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	"github.com/chainreactors/cyber/exts/4zfence/policy"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	"google.golang.org/protobuf/proto"
)

// judgeOptions are the fence section's admission settings. They are installed
// before the extension admits anything and read-only afterwards.
type judgeOptions struct {
	mode          string
	scope         map[string]struct{}
	allowPrefixes []string
	shadow        bool
}

func newJudgeOptions(cfg fenceconfig.Config) judgeOptions {
	options := judgeOptions{mode: cfg.Mode, shadow: cfg.Shadow}
	for _, name := range cfg.Scope {
		if name = strings.TrimSpace(name); name != "" {
			if options.scope == nil {
				options.scope = make(map[string]struct{})
			}
			options.scope[name] = struct{}{}
		}
	}
	options.allowPrefixes = append([]string(nil), cfg.AllowPrefixes...)
	return options
}

// inScope reports whether the invocation is subject to judgment. An empty
// scope keeps the historical behavior: every tool call is checked.
func (o judgeOptions) inScope(name string) bool {
	if len(o.scope) == 0 {
		return true
	}
	_, ok := o.scope[name]
	return ok
}

// allowedPrefix is the deterministic safe-mode bypass. It matches the tool's
// command text only; it is not a semantic classifier.
func (o judgeOptions) allowedPrefix(ev toolhooks.CallEvent) bool {
	if len(o.allowPrefixes) == 0 {
		return false
	}
	text := commandText(ev.Call)
	if text == "" {
		return false
	}
	for _, prefix := range o.allowPrefixes {
		// Prefixes are literal, including any trailing space. The configuration
		// validator rejects empty entries; trimming here would silently turn
		// "ls " into a substring allowance for "lsof".
		if prefix != "" && strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

// commandText extracts the command-ish text from a tool call's arguments.
// It recognizes the documented bash/subagent command fields first, then falls
// back to the raw argument string. Matching stays a literal prefix test.
func commandText(call *aop.ToolCall) string {
	if call == nil {
		return ""
	}
	raw := call.GetArguments().GetData()
	var value any
	if json.Unmarshal(raw, &value) == nil {
		switch typed := value.(type) {
		case string:
			return typed
		case map[string]any:
			for _, key := range []string{"command", "cmd", "script", "input", "code"} {
				if text, ok := typed[key].(string); ok && strings.TrimSpace(text) != "" {
					return text
				}
			}
		}
	}
	return string(raw)
}

// judge is the policy stage of the fence admission: one invocation, judged by
// the configured provider. The returned admission hands the call to the next
// tool.before judge (an empty admission) or denies; a review holds on the
// bound guardrail runtime's approval lifecycle.
func (e *Extension) judge(ctx context.Context, ev toolhooks.CallEvent, options judgeOptions) (toolhooks.Admission, error) {
	if e.policy == nil {
		return toolhooks.Admission{}, nil
	}
	// Scope is a routing filter, not a judgment: an unmatched tool name is not
	// sent to the provider and produces no policy event.
	if !options.inScope(ev.Call.GetName()) {
		return toolhooks.Admission{}, nil
	}
	risk, err := evaluatePolicy(ctx, e.policy.Check, ev)
	if errors.Is(err, policy.ErrNoPolicy) {
		return toolhooks.Admission{}, nil
	}
	d := risk
	if err == nil && risk.Action != guardrailext.Action_ACTION_RECORD && options.mode == string(guardrailext.ModeAuto) {
		consequence, confirmErr := evaluatePolicy(ctx, e.policy.Confirm, ev)
		if !errors.Is(confirmErr, policy.ErrNoConsequence) {
			d, err = consequence, confirmErr
		}
	}
	invalid := err != nil || d == nil
	if invalid {
		if d == nil {
			d = &guardrailext.Decision{Action: guardrailext.Action_ACTION_RECORD, Reason: "guardrail policy failed"}
		}
		e.emitDecision(ctx, d, ev)
	} else {
		e.emitDecision(ctx, d, ev)
	}
	// Cancellation is never overridden. Shadow mode records the judgment and
	// always lets the invocation through, including a broken-judgment fallback.
	if ctx.Err() != nil {
		return denied(d.Reason), nil
	}
	if options.shadow {
		return toolhooks.Admission{}, nil
	}
	// Failed judgments cannot be overridden by a human decision; only a valid
	// provider judgment can enter review.
	if invalid {
		return denied(d.Reason), nil
	}
	// Safe mode's deterministic prefix allow list releases a judged call
	// without a human, while still emitting the decision event above.
	if options.mode == string(guardrailext.ModeSafe) && options.allowedPrefix(ev) {
		return toolhooks.Admission{}, nil
	}
	if options.mode != string(guardrailext.ModeSafe) && options.mode != string(guardrailext.ModeAuto) {
		return denied("invalid fence mode"), nil
	}
	if d.Action == guardrailext.Action_ACTION_RECORD {
		return toolhooks.Admission{}, nil
	}
	// Every risky judgment — review and block — holds on the ordinary approval
	// lifecycle, in safe and auto mode alike: only the operator's refusal or
	// the failed-judgment path above denies.
	rt := e.boundRuntime()
	if rt == nil {
		return denied(d.Reason + "（fence admission is not bound to a guardrail runtime）"), nil
	}
	admission := rt.SubmitReview(ctx, ev, d)
	if admission.Deny == nil {
		return admission, nil
	}
	return denied(d.Reason), nil
}

// evaluatePolicy preserves the original call for the policy stage and never
// exposes provider failures through the tool result; the hook boundary
// handles panics. The fence reports its own failures in its own journal.
func evaluatePolicy(ctx context.Context, fn func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error), ev toolhooks.CallEvent) (*guardrailext.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := fn(ctx, cloneCallEvent(ev))
	if err != nil {
		// Sentinels that describe the policy shape (no judgment, no second
		// stage) pass through so the caller can distinguish them from
		// provider failures.
		if errors.Is(err, policy.ErrNoPolicy) || errors.Is(err, policy.ErrNoConsequence) {
			return nil, err
		}
		return nil, errors.New("fence check failed")
	}
	if d == nil || d.Action < guardrailext.Action_ACTION_RECORD || d.Action > guardrailext.Action_ACTION_BLOCK {
		return nil, errors.New("guardrail check failed")
	}
	return d, nil
}

func cloneCallEvent(ev toolhooks.CallEvent) toolhooks.CallEvent {
	ev.Call = proto.Clone(ev.Call).(*aop.ToolCall)
	return ev
}

// buildPolicy assembles the provider the fence section selects. provider jev
// borrows the shared JEV client; provider none installs no judgment at all
// and the fence judges only its red lines.
func (e *Extension) buildPolicy(scope *extension.Scope, stream *events.Stream) (policy.Policy, error) {
	switch e.fence.Provider {
	case fenceconfig.ProviderJEV, fenceconfig.ProviderHybrid:
		client, err := extension.Use[*jevapi.Client](scope)
		if err != nil {
			return nil, err
		}
		jev := policy.NewJEV(e.jevRules, client)
		policy.SetUsage(jev, policy.UsageReporter(stream, policy.EmitterJEV))
		if e.fence.Provider == fenceconfig.ProviderJEV {
			return jev, nil
		}
		llm := policy.NewLLM(e.fence.LLM, e.fence.OnError, e.fence.LLMTimeout(), e.fence.Concurrency, policy.UsageReporter(stream, policy.EmitterLLM))
		return policy.NewHybrid(llm, jev), nil
	case fenceconfig.ProviderLLM:
		llm := policy.NewLLM(e.fence.LLM, e.fence.OnError, e.fence.LLMTimeout(), e.fence.Concurrency, policy.UsageReporter(stream, policy.EmitterLLM))
		return llm, nil
	default:
		return nil, nil
	}
}

// boundRuntime returns the guardrail runtime whose approval lifecycle the
// review holds ride, or nil when the composition has not bound one.
func (e *Extension) boundRuntime() *guardrailext.Runtime {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.guardrail
}
