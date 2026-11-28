package fence

// The fence's policy judge (docs/19 E3-3): the judging half of the old
// guardrail admission — the scope filter, the policy evaluation, the shadow
// and safe-mode releases — moved here, so the fence is the sole judge and
// the guardrail runtime stays only the approval queue. Review holds ride the
// guardrail runtime's ordinary lifecycle through the SubmitReview seam (G3,
// the one registered hook guardrail carries).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jevapi "github.com/chainreactors/cyber/agent/provider/jev"
	aop "github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/operation"
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

// commandText extracts the command-ish text from a tool call's arguments by
// the same rules the command tools decode with (commandField), falling back
// to the raw argument string. Matching stays a literal prefix test.
func commandText(call *aop.ToolCall) string {
	if call == nil {
		return ""
	}
	text, _ := commandField(call.GetArguments().GetData())
	return text
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
		d = &guardrailext.Decision{Action: guardrailext.Action_ACTION_BLOCK, Reason: "Guardrail policy unavailable or invalid"}
	}
	if ctx.Err() != nil {
		d = &guardrailext.Decision{Action: guardrailext.Action_ACTION_BLOCK, Reason: "Invocation canceled"}
	}
	d.Reason = guardrailext.RedactText(d.Reason)
	// The journal carries the first-stage judgment when it is valid; the
	// fallback or canceled decision otherwise.
	if !invalid && risk != nil && ctx.Err() == nil {
		e.emitDecision(ctx, risk, ev)
	} else {
		e.emitDecision(ctx, d, ev)
	}
	if ctx.Err() != nil {
		return denied(d.Reason), nil
	}
	// Shadow mode records the judgment and always lets the invocation
	// through, including a broken-judgment fallback.
	if options.shadow {
		return toolhooks.Admission{}, nil
	}
	// Failed judgments cannot be overridden by a human decision; only a valid
	// provider judgment can enter review.
	if invalid {
		return denied(d.Reason), nil
	}
	if options.mode != string(guardrailext.ModeSafe) && options.mode != string(guardrailext.ModeAuto) {
		return denied("invalid fence mode"), nil
	}
	if options.mode == string(guardrailext.ModeSafe) && options.allowedPrefix(ev) {
		return toolhooks.Admission{}, nil
	}
	if d.Action == guardrailext.Action_ACTION_RECORD {
		return toolhooks.Admission{}, nil
	}
	if options.mode == string(guardrailext.ModeAuto) {
		// Auto mode denies, with the model-visible rejection message and the
		// bounded same-invocation backoff; the audit carries a REJECTED review.
		e.emitAutoAudit(ctx, ev, risk, d)
		repeat := e.repeatedRejection(ctx, ev)
		if repeat > 1 {
			timer := time.NewTimer(time.Duration(min(repeat-1, 8)) * 250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return denied("fence invocation canceled"), nil
			case <-timer.C:
			}
		}
		return denied(fmt.Sprintf("Guardrail intercepted this tool invocation (%d identical attempts in this turn); the tool was not executed. Reason: ", repeat) + d.Reason +
			" Do not repeat the same invocation. Reassess the risk and choose a safer next action or explain the limitation. Every new tool call is checked again."), nil
	}
	// Safe mode holds every risky judgment on the ordinary approval lifecycle;
	// only the operator's refusal or the failed-judgment path above denies.
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
// handles panics. Sentinels that describe the policy shape (no judgment, no
// second stage) pass through so the caller can distinguish them from
// provider failures.
func evaluatePolicy(ctx context.Context, fn func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error), ev toolhooks.CallEvent) (*guardrailext.Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := fn(ctx, cloneCallEvent(ev))
	if err != nil {
		if errors.Is(err, policy.ErrNoPolicy) || errors.Is(err, policy.ErrNoConsequence) {
			return nil, err
		}
		return nil, errors.New("fence check failed")
	}
	if d == nil || d.Action < guardrailext.Action_ACTION_RECORD || d.Action > guardrailext.Action_ACTION_BLOCK {
		return nil, errors.New("fence check failed")
	}
	return d, nil
}

func cloneCallEvent(ev toolhooks.CallEvent) toolhooks.CallEvent {
	if ev.Call != nil {
		ev.Call = proto.Clone(ev.Call).(*aop.ToolCall)
	}
	if ev.Operation != nil {
		ev.Operation = proto.Clone(ev.Operation).(*operationpb.Ref)
	}
	return ev
}

// emitAutoAudit publishes the auto-mode audit review (REJECTED for every
// risky judgment; APPROVED when the consequence stage downgraded to record),
// the shape the old guardrail Admit emitted with ResolutionSource "auto".
func (e *Extension) emitAutoAudit(ctx context.Context, ev toolhooks.CallEvent, risk, d *guardrailext.Decision) {
	audit := proto.Clone(risk).(*guardrailext.Decision)
	if d != risk {
		audit.Reason += "\nConsequence assessment: " + d.Reason
	}
	state := guardrailext.ReviewState_REVIEW_STATE_REJECTED
	if d.Action == guardrailext.Action_ACTION_RECORD {
		state = guardrailext.ReviewState_REVIEW_STATE_APPROVED
	}
	review := &guardrailext.Review{Call: guardrailext.SanitizeCall(ev.Call), Operation: ev.Operation,
		SessionId: operation.InvocationFromContext(ctx).SessionID, Decision: audit,
		State: state, ResolutionSource: "auto"}
	e.emitDecision(ctx, review, ev)
}

// repeatedRejection counts identical attempts within one turn, the bounded
// diagnostic state behind the auto-mode backoff (upstream keeps the same map
// on its runtime).
func (e *Extension) repeatedRejection(ctx context.Context, ev toolhooks.CallEvent) int {
	inv := operation.InvocationFromContext(ctx)
	if inv.SessionID == "" || inv.TurnID == "" {
		return 1
	}
	args := string(ev.Call.GetArguments().GetData())
	var value any
	if json.Unmarshal([]byte(args), &value) == nil {
		if canonical, jerr := json.Marshal(value); jerr == nil {
			args = string(canonical)
		}
	}
	key, _ := json.Marshal([]string{inv.SessionID, inv.TurnID, ev.Call.GetName(), ev.Call.GetWorkingDirectory(), args})
	hash := sha256.Sum256(key)
	e.rejectionsMu.Lock()
	defer e.rejectionsMu.Unlock()
	if e.rejections == nil {
		e.rejections = make(map[[32]byte]int)
	}
	if _, exists := e.rejections[hash]; !exists && len(e.rejections) >= 1024 {
		for old := range e.rejections {
			delete(e.rejections, old)
			break
		}
	}
	e.rejections[hash]++
	return e.rejections[hash]
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
		jev := policy.NewJEV(e.jevRules, client, policy.UsageReporter(stream, policy.EmitterJEV))
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
