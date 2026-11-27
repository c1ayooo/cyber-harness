package session

import (
	"context"
	"testing"
	"time"

	"github.com/chainreactors/cyber/agent/provider"
	aop "github.com/chainreactors/cyber/aop"
	types "github.com/chainreactors/cyber/core/types"
	"google.golang.org/protobuf/types/known/anypb"
)

// The evaluator is a second model call inside the same turn, and its tokens
// belong to the turn's usage. TurnEnded is the only place the control plane
// reads a turn's final usage, so the sum has to be visible there: an evaluator
// call left out of it makes every evaluated turn report a cost that is too low.
//
// Numbers are fixed so the assertion can be rechecked by hand: the executor
// spends 1000/100/1100 (cache_read 200) and the evaluator 50/10/60.
func TestTurnEndedUsageIncludesEvaluator(t *testing.T) {
	agentResponse := &provider.ChatCompletionResponse{
		Choices: []provider.Choice{{Message: provider.TextMessage("assistant", "finished the work")}},
		Usage:   &aop.TokenUsage{InputTokens: 1000, OutputTokens: 100, TotalTokens: 1100, Detail: map[string]uint64{"cache_read": 200}},
	}
	verdict := testVerdict(true)
	verdict.Usage = &aop.TokenUsage{InputTokens: 50, OutputTokens: 10, TotalTokens: 60, Detail: map[string]uint64{}}

	scripted := &scriptedProvider{responses: []*provider.ChatCompletionResponse{agentResponse, verdict}}
	rt := newBareRuntime(t, nil, scripted)
	if opened := rt.OpenAOPSession(&aop.OpenSessionRequest{SessionId: "session-1"}); opened.GetAccepted() == nil {
		t.Fatalf("OpenAOPSession = %v", opened)
	}
	ended := make(chan *aop.TurnEnded, 1)
	unsubscribe := rt.Observe(func(event *aop.Event) {
		if event.GetTurnId() == "turn-1" && event.GetTurnEnded() != nil {
			select {
			case ended <- event.GetTurnEnded():
			default:
			}
		}
	})
	defer unsubscribe.Cancel()

	runOptions, err := anypb.New(&types.AgentRunOptions{EvalCriteria: "the work is finished"})
	if err != nil {
		t.Fatal(err)
	}
	response := rt.RunAOPTurn(context.Background(), &aop.RunTurnRequest{
		SessionId: "session-1", TurnId: "turn-1",
		Input:      &aop.Message{Id: "m-1", Role: "user", Content: []*aop.Content{aop.Text("do the work")}},
		Extensions: []*anypb.Any{runOptions},
	})
	if response.GetAccepted() == nil {
		t.Fatalf("RunAOPTurn = %v", response)
	}

	var turnEnded *aop.TurnEnded
	select {
	case turnEnded = <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("eval run did not finish")
	}
	if turnEnded.GetError() != nil {
		t.Fatalf("eval run failed: %v", turnEnded.GetError())
	}
	if len(scripted.requests) != 2 {
		t.Fatalf("provider calls = %d, want one executor run and one evaluation", len(scripted.requests))
	}
	usage := turnEnded.GetUsage()
	if usage.GetInputTokens() != 1050 {
		t.Fatalf("turn input tokens = %d, want 1050 (executor 1000 + evaluator 50)", usage.GetInputTokens())
	}
	if usage.GetOutputTokens() != 110 {
		t.Fatalf("turn output tokens = %d, want 110 (executor 100 + evaluator 10)", usage.GetOutputTokens())
	}
	if usage.GetTotalTokens() != 1160 {
		t.Fatalf("turn total tokens = %d, want 1160 (executor 1100 + evaluator 60)", usage.GetTotalTokens())
	}
	if got := usage.GetDetail()["cache_read"]; got != 200 {
		t.Fatalf("turn cache_read = %d, want 200 from the executor only", got)
	}
}
