package zsession

import (
	"encoding/json"
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"google.golang.org/protobuf/types/known/anypb"
)

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Since the control plane renamed its fork namespace (tianwu.* → 4zrcin.*),
// every extension it sends carries the new type URL while the pre-rename
// harness only matched the old one — the host silently ignored the payload.
// Both spellings must work for every fork extension.
func TestForkExtensionsAcceptBothNamespaces(t *testing.T) {
	newRequest := func(url string, payload []byte) *aop.RunTurnRequest {
		return &aop.RunTurnRequest{Extensions: []*anypb.Any{{
			TypeUrl: url, Value: payload,
		}}}
	}
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		t.Run(namespace, func(t *testing.T) {
			if got := turnWorkDir(newRequest("type.googleapis.com/"+namespace+".WorkDir",
				mustJSON(t, payloads.WorkDirPayload{WorkDir: "/tmp/case"}))); got != "/tmp/case" {
				t.Fatalf("WorkDir = %q", got)
			}
			goal, rounds := turnRunGoal(newRequest("type.googleapis.com/"+namespace+".RunGoal",
				mustJSON(t, payloads.RunGoalPayload{Goal: "g", EvalRounds: json.RawMessage(`"2x"`)})))
			if goal != "g" || rounds != "2x" {
				t.Fatalf("RunGoal = %q/%q", goal, rounds)
			}
			if env := turnToolEnv(newRequest("type.googleapis.com/"+namespace+".ToolEnv",
				mustJSON(t, payloads.ToolEnvPayload{Env: map[string]string{"K": "V"}}))); len(env) != 1 || env[0] != "K=V" {
				t.Fatalf("ToolEnv = %v", env)
			}
		})
	}
}
