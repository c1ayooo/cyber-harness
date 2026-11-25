package guardrail

import (
	"context"
	"errors"
	"fmt"

	toolhooks "github.com/c1ayooo/cyber/core/tool/hooks"
	"google.golang.org/protobuf/proto"
)

// confidencePolicy is an optional Policy capability. A policy that can express
// its own confidence lets hybrid recognize an on_error decision (negative
// confidence) and keep it final instead of escalating it.
type confidencePolicy interface {
	Policy
	CheckWithConfidence(context.Context, toolhooks.CallEvent) (*Decision, float64, error)
}

// hybridPolicy runs the cheap LLM judge first and spends a JEV review only for
// an explicit REVIEW decision. Low-confidence or uncalibrated answers are
// already mapped to ALLOW by the LLM policy's uncertainty-is-allow rule, so they
// never trigger JEV. It is the same Policy interface, so the runtime and
// configuration remain provider-agnostic. Both stages are injected, which keeps
// hybrid tests independent of any real provider.
type hybridPolicy struct {
	llm Policy
	jev Policy
}

func newHybridPolicy(llm, jev Policy) *hybridPolicy {
	return &hybridPolicy{llm: llm, jev: jev}
}

// Check implements the documented escalation table: ALLOW and BLOCK from the
// LLM are final, and only an explicit REVIEW is confirmed by JEV. The JEV
// decision maps straight through: record permits execution, block denies it,
// review reaches the human (or auto-mode rejection).
func (h *hybridPolicy) Check(ctx context.Context, ev toolhooks.CallEvent) (*Decision, error) {
	llmDecision, confidence, err := hybridLLMDecision(h.llm, ctx, ev)
	if err != nil {
		return nil, err
	}
	// A negative confidence means the LLM stage answered through its on_error
	// policy (allow/review/block). That decision is already the operator's
	// failure policy, so hybrid must not override it with a JEV review.
	if confidence < 0 {
		return llmDecision, nil
	}
	if llmDecision.Action != Action_ACTION_REVIEW {
		return llmDecision, nil
	}
	reviewed, err := h.jev.Check(ctx, ev)
	if err != nil {
		return nil, err
	}
	if reviewed == nil {
		return nil, errors.New("JEV review returned no decision")
	}
	out := proto.Clone(reviewed).(*Decision)
	out.Reason = fmt.Sprintf("%s\nHybrid JEV review (explicit REVIEW): %s", llmDecision.Reason, reviewed.Reason)
	return out, nil
}

// Confirm has no second stage: hybrid already escalated to JEV inside Check, so
// auto mode keeps the combined verdict instead of calling the providers again.
func (h *hybridPolicy) Confirm(context.Context, toolhooks.CallEvent) (*Decision, error) {
	return nil, errNoConsequence
}

func hybridLLMDecision(llm Policy, ctx context.Context, ev toolhooks.CallEvent) (*Decision, float64, error) {
	if policy, ok := llm.(confidencePolicy); ok {
		return policy.CheckWithConfidence(ctx, ev)
	}
	decision, err := llm.Check(ctx, ev)
	if err != nil {
		return nil, 0, err
	}
	return decision, 1, nil
}
