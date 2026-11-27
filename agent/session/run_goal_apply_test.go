package session

// The runtime applies the composition's turn decorators (seam G1, docs/19
// appendix A): this test drives RunAOPTurn through a runtime whose
// TurnDecorators are the 4zsession block's, and checks the evaluator's goal
// and pacing come from the control-plane extension.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/cyber/agent/provider"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	types "github.com/chainreactors/cyber/core/types"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestRunAOPTurnRunGoalShapesEvaluatorGoal(t *testing.T) {
	for _, test := range []struct {
		name       string
		extension  *anypb.Any
		wantGoal   string
		wantRounds string
	}{
		{
			name:       "extension goal and rounds",
			extension:  &anypb.Any{TypeUrl: payloads.RunGoalURLs[0], Value: []byte(`{"goal":"verify admin access","eval_rounds":"2"}`)},
			wantGoal:   "## Goal\nverify admin access",
			wantRounds: "hard ceiling 2,",
		},
		{
			name:       "absent extension keeps the input as goal",
			wantGoal:   "## Goal\ndo the work",
			wantRounds: "hard ceiling 20,",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runOptions, err := anypb.New(&types.AgentRunOptions{EvalCriteria: "the admin page returns 200"})
			if err != nil {
				t.Fatal(err)
			}
			scripted := &scriptedProvider{responses: []*provider.ChatCompletionResponse{
				{Choices: []provider.Choice{{Message: provider.TextMessage("assistant", "finished the admin check")}}},
				testVerdict(true),
			}}
			rt := newBareRuntime(t, nil, scripted)
			// Mirror 4zsession's run-goal decorator inline: the test package
			// cannot import the block (it imports agent/session), and what
			// matters here is that a decorator's EvalGoal/EvalRounds shape
			// the evaluator request.
			rt.config.TurnDecorators = []RunTurnDecorator{func(req *aop.RunTurnRequest, input *RunInput) error {
				if payload, ok := payloads.ParseRunGoal(payloads.ExtensionWithURL(req.GetExtensions(), payloads.RunGoalURLs)); ok {
					goal, rounds := strings.TrimSpace(payload.Goal), payloads.EvalRoundsText(payload.EvalRounds)
					if goal != "" || rounds != "" {
						input.EvalGoal, input.EvalRounds = goal, rounds
					}
				}
				return nil
			}}
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
			extensions := []*anypb.Any{runOptions}
			if test.extension != nil {
				extensions = append(extensions, test.extension)
			}
			response := rt.RunAOPTurn(context.Background(), &aop.RunTurnRequest{
				SessionId: "session-1", TurnId: "turn-1",
				Input:      &aop.Message{Id: "m-1", Role: "user", Content: []*aop.Content{aop.Text("do the work")}},
				Extensions: extensions,
			})
			if response.GetAccepted() == nil {
				t.Fatalf("RunAOPTurn = %v", response)
			}
			select {
			case turnEnded := <-ended:
				if turnEnded.GetError() != nil {
					t.Fatalf("eval run failed: %v", turnEnded.GetError())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("eval run did not finish")
			}
			if len(scripted.requests) != 2 {
				t.Fatalf("provider calls = %d, want one agent run and one evaluation", len(scripted.requests))
			}
			// The first request is the executor: the turn message must be preserved.
			if agentInput := requestText(scripted.requests[0]); !strings.Contains(agentInput, "do the work") {
				t.Fatalf("executor input lost the turn message: %s", agentInput)
			}
			// The second request is the evaluator: its goal and pacing come from
			// the control plane extension when present.
			evaluation := requestText(scripted.requests[1])
			if !strings.Contains(evaluation, test.wantGoal) {
				t.Fatalf("evaluation prompt goal = %s", evaluation)
			}
			if !strings.Contains(evaluation, test.wantRounds) {
				t.Fatalf("evaluation prompt pacing = %s", evaluation)
			}
		})
	}
}

func testVerdict(pass bool) *provider.ChatCompletionResponse {
	arguments := `{"pass":false,"continue":false,"reason":"not met","feedback":"","inherit_context":true}`
	if pass {
		arguments = `{"pass":true,"continue":false,"reason":"met","feedback":"","inherit_context":true}`
	}
	return &provider.ChatCompletionResponse{Choices: []provider.Choice{{Message: &aop.Message{
		Role: "assistant",
		Content: []*aop.Content{{Value: &aop.Content_ToolCall{ToolCall: &aop.ToolCall{
			Id: "verdict-1", Name: "verdict", Kind: "function",
			Arguments: &aop.EncodedValue{Data: []byte(arguments), MediaType: aop.JSONMediaType},
		}}}},
	}}}}
}

func requestText(request *provider.ChatCompletionRequest) string {
	var text strings.Builder
	for _, message := range request.Messages {
		text.WriteString(provider.MessageText(message))
		text.WriteByte('\n')
	}
	return text.String()
}
