package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/cyber/agent/provider"
	aop "github.com/chainreactors/cyber/aop"
	types "github.com/chainreactors/cyber/core/types"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestTurnRunGoalExtension(t *testing.T) {
	extension := func(typeURL, value string) *anypb.Any {
		return &anypb.Any{TypeUrl: typeURL, Value: []byte(value)}
	}
	request := func(extensions ...*anypb.Any) *aop.RunTurnRequest {
		return &aop.RunTurnRequest{Extensions: extensions}
	}
	for _, test := range []struct {
		name   string
		req    *aop.RunTurnRequest
		goal   string
		rounds string
	}{
		{name: "absent", req: request()},
		{name: "nil request"},
		{
			name:   "trimmed goal and rounds",
			req:    request(extension(forkRunGoalExtensionURL(), `{"goal":" verify admin access ","eval_rounds":" 2 "}`)),
			goal:   "verify admin access",
			rounds: "2",
		},
		{
			name:   "numeric rounds",
			req:    request(extension(forkRunGoalExtensionURL(), `{"goal":"verify admin access","eval_rounds":3}`)),
			goal:   "verify admin access",
			rounds: "3",
		},
		{
			name: "goal only",
			req:  request(extension(forkRunGoalExtensionURL(), `{"goal":"verify admin access"}`)),
			goal: "verify admin access",
		},
		{
			name: "other extensions are ignored",
			req: request(
				extension(forkWorkDirExtensionURL(), `{"work_dir":"C:\\case"}`),
				extension(forkRunGoalExtensionURL(), `{"goal":"verify admin access"}`),
			),
			goal: "verify admin access",
		},
		{name: "malformed value", req: request(extension(forkRunGoalExtensionURL(), `{`))},
		{name: "empty value", req: request(extension(forkRunGoalExtensionURL(), `{"goal":"","eval_rounds":""}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			goal, rounds := turnRunGoal(test.req)
			if goal != test.goal || rounds != test.rounds {
				t.Fatalf("turnRunGoal() = (%q, %q), want (%q, %q)", goal, rounds, test.goal, test.rounds)
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

// The RunGoal extension is the control plane's evaluator contract: the
// evaluator judges the intent's short goal while the executor still receives
// the turn message as its first input. Without the extension the upstream
// derivation (the input text) must remain in force.
func TestRunAOPTurnRunGoalShapesEvaluatorGoal(t *testing.T) {
	for _, test := range []struct {
		name       string
		extension  *anypb.Any
		wantGoal   string
		wantRounds string
	}{
		{
			name:       "extension goal and rounds",
			extension:  &anypb.Any{TypeUrl: forkRunGoalExtensionURL(), Value: []byte(`{"goal":"verify admin access","eval_rounds":"2"}`)},
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
