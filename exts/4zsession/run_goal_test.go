package zsession

import (
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
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
			req:    request(extension(payloads.RunGoalURLs[0], `{"goal":" verify admin access ","eval_rounds":" 2 "}`)),
			goal:   "verify admin access",
			rounds: "2",
		},
		{
			name:   "numeric rounds",
			req:    request(extension(payloads.RunGoalURLs[0], `{"goal":"verify admin access","eval_rounds":3}`)),
			goal:   "verify admin access",
			rounds: "3",
		},
		{
			name: "goal only",
			req:  request(extension(payloads.RunGoalURLs[0], `{"goal":"verify admin access"}`)),
			goal: "verify admin access",
		},
		{
			name: "other extensions are ignored",
			req: request(
				extension(payloads.WorkDirURLs[0], `{"work_dir":"C:\\case"}`),
				extension(payloads.RunGoalURLs[0], `{"goal":"verify admin access"}`),
			),
			goal: "verify admin access",
		},
		{name: "malformed value", req: request(extension(payloads.RunGoalURLs[0], `{`))},
		{name: "empty value", req: request(extension(payloads.RunGoalURLs[0], `{"goal":"","eval_rounds":""}`))},
	} {
		t.Run(test.name, func(t *testing.T) {
			goal, rounds := turnRunGoal(test.req)
			if goal != test.goal || rounds != test.rounds {
				t.Fatalf("turnRunGoal() = (%q, %q), want (%q, %q)", goal, rounds, test.goal, test.rounds)
			}
		})
	}
}

// The RunGoal extension is the control plane's evaluator contract: the
// evaluator judges the intent's short goal while the executor still receives
// the turn message as its first input. Without the extension the upstream
// derivation (the input text) must remain in force.
