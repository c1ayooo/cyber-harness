package evaluator

import (
	"context"
	"testing"

	"github.com/chainreactors/cyber/agent"
	provider "github.com/chainreactors/cyber/agent/provider"
	aop "github.com/chainreactors/cyber/aop"
)

// seqProvider answers from a queue so the executor call and the judgement call
// can report different usage, which is the whole point of these cases.
type seqProvider struct {
	responses []*provider.ChatCompletionResponse
	calls     int
}

func (p *seqProvider) Name() string { return "seq" }

func (p *seqProvider) ChatCompletion(_ context.Context, _ *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error) {
	if p.calls >= len(p.responses) {
		p.calls++
		return p.responses[len(p.responses)-1], nil
	}
	response := p.responses[p.calls]
	p.calls++
	return response, nil
}

func verdictReply(usage *aop.TokenUsage, model string) *provider.ChatCompletionResponse {
	args := `{"pass":true,"continue":false,"reason":"met","feedback":"","inherit_context":true}`
	return &provider.ChatCompletionResponse{
		Model: model,
		Choices: []provider.Choice{{Message: &aop.Message{
			Role: "assistant",
			Content: []*aop.Content{{Value: &aop.Content_ToolCall{ToolCall: &aop.ToolCall{
				Id: "verdict-1", Name: "verdict", Kind: "function",
				Arguments: &aop.EncodedValue{Data: []byte(args), MediaType: aop.JSONMediaType},
			}}}},
		}}},
		Usage: usage,
	}
}

func executorReply(usage *aop.TokenUsage) *provider.ChatCompletionResponse {
	return &provider.ChatCompletionResponse{
		Choices: []provider.Choice{{Message: provider.TextMessage("assistant", "done")}},
		Usage:   usage,
	}
}

func runDiagTurn(t *testing.T, judge *provider.ChatCompletionResponse) *agent.Result {
	t.Helper()
	seq := &seqProvider{responses: []*provider.ChatCompletionResponse{
		executorReply(&aop.TokenUsage{InputTokens: 1000, OutputTokens: 100, TotalTokens: 1100, Detail: map[string]uint64{}}),
		judge,
	}}
	ag := agent.NewAgent(agent.Config{Loop: agent.StandardLoop{}, Provider: seq, Model: "test"})
	result, _, err := RunWithEval(context.Background(), ag,
		NewLoopConfig(seq, "test", nil, evaluatorTestPrompts{}, "finish the task", "finish the task", "1"))
	if err != nil {
		t.Fatalf("RunWithEval() error = %v", err)
	}
	if result == nil || result.TotalUsage == nil {
		t.Fatalf("run carried no usage: %+v", result)
	}
	if seq.calls != 2 {
		t.Fatalf("provider calls = %d, want one executor run and one judgement", seq.calls)
	}
	return result
}

// A judgement can come back without a usage field. The turn must then report
// the executor's tokens only, and say so: "the fix ran but had nothing to count"
// must not look like "the fix never ran". The routed model is recorded too,
// because that is what explains the missing field.
func TestRunWithEvalMarksMissingEvaluatorUsage(t *testing.T) {
	result := runDiagTurn(t, verdictReply(nil, "route/quiet"))
	usage := result.TotalUsage
	if usage.TotalTokens != 1100 {
		t.Fatalf("total tokens = %d, want only the executor's 1100", usage.TotalTokens)
	}
	if got := usage.Detail["usage_missing"]; got != 1 {
		t.Fatalf("usage_missing = %d, want 1", got)
	}
	if got := usage.Detail["eval_model_hash"]; got != fnv64a("route/quiet") {
		t.Fatalf("eval_model_hash = %d, want the hash of the routed model", got)
	}
}

// When the judgement does report usage, it is counted and nothing is marked
// missing; the route is still recorded so a later missing field has a baseline.
func TestRunWithEvalRecordsEvaluatorRoute(t *testing.T) {
	result := runDiagTurn(t, verdictReply(
		&aop.TokenUsage{InputTokens: 50, OutputTokens: 10, TotalTokens: 60, Detail: map[string]uint64{}},
		"route/loud",
	))
	usage := result.TotalUsage
	if usage.TotalTokens != 1160 {
		t.Fatalf("total tokens = %d, want 1160 (1100 + 60)", usage.TotalTokens)
	}
	if got := usage.Detail["usage_missing"]; got != 0 {
		t.Fatalf("usage_missing = %d, want none", got)
	}
	if got := usage.Detail["eval_model_hash"]; got != fnv64a("route/loud") {
		t.Fatalf("eval_model_hash = %d, want the hash of the routed model", got)
	}
}
