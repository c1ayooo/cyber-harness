package guardrail

import (
	"context"
	"errors"
	"fmt"

	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"google.golang.org/protobuf/proto"
)

// confidencePolicy is an optional Policy capability. A policy that can express
// its own confidence lets hybrid distinguish a decisive ALLOW from a guess.
type confidencePolicy interface {
	Policy
	CheckWithConfidence(context.Context, toolhooks.CallEvent) (*Decision, float64, error)
}

// hybridPolicy runs the cheap LLM judge first and spends a JEV review only for
// REVIEW decisions and low-confidence ALLOWs. It is the same Policy interface,
// so the runtime and configuration remain provider-agnostic. Both stages are
// injected, which keeps hybrid tests independent of any real provider.
type hybridPolicy struct {
	llm Policy
	jev Policy
}

func newHybridPolicy(llm, jev Policy) *hybridPolicy {
	return &hybridPolicy{llm: llm, jev: jev}
}

// Check implements the documented escalation table: a confident ALLOW and a
// BLOCK are final, everything else is confirmed by JEV. The JEV decision maps
// straight through: record permits execution, block denies it, review reaches
// the human (or auto-mode rejection).
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
	if llmDecision.Action == Action_ACTION_BLOCK {
		return llmDecision, nil
	}
	if llmDecision.Action == Action_ACTION_RECORD && confidence >= llmConfidenceThreshold {
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
	escalation := "review"
	if llmDecision.Action == Action_ACTION_RECORD {
		escalation = "low confidence"
	}
	out.Reason = fmt.Sprintf("%s\nHybrid JEV review (%s): %s", llmDecision.Reason, escalation, reviewed.Reason)
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
