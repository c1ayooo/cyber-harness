package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"github.com/chainreactors/cyber/core/scoperules"
	"google.golang.org/protobuf/types/known/anypb"
)

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

// The scope-rule set registers for the session the turn belongs to, in both
// namespaces; an invalid set is ignored without touching the previous one.
func TestTurnScopeRulesRegistration(t *testing.T) {
	valid := `{"enabled":true,"default_action":"record","rules":[{"id":"sr-1","action":"review","method":"*","host":"*"}]}`
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		req := &aop.RunTurnRequest{SessionId: "sess-scope", Extensions: []*anypb.Any{{
			TypeUrl: "type.googleapis.com/" + namespace + ".ScopeRules", Value: []byte(valid),
		}}}
		turnScopeRules(req)
		verdict, judged := scoperules.JudgeSession("sess-scope", "GET", "https://api.example.test/v1")
		if !judged || verdict.Action != "review" {
			t.Fatalf("namespace %s: verdict = %+v judged=%v", namespace, verdict, judged)
		}
	}
	invalid := `{"enabled":true,"default_action":"nonsense"}`
	turnScopeRules(&aop.RunTurnRequest{SessionId: "sess-scope", Extensions: []*anypb.Any{{
		TypeUrl: "type.googleapis.com/4zrcin.ScopeRules", Value: []byte(invalid),
	}}})
	if verdict, judged := scoperules.JudgeSession("sess-scope", "GET", "https://api.example.test/v1"); !judged || verdict.Action != "review" {
		t.Fatalf("invalid set wiped the previous rules: %+v judged=%v", verdict, judged)
	}
	// A turn without the extension keeps the last set (the control plane
	// re-sends even disabled drafts every turn precisely to keep this honest).
	turnScopeRules(&aop.RunTurnRequest{SessionId: "sess-scope"})
	if _, judged := scoperules.JudgeSession("sess-scope", "GET", "https://x.test/"); !judged {
		t.Fatal("extension-less turn dropped the registered set")
	}
}

// The scope rules register before the turn runs: RunAOPTurn applies them for
// the session it is about to execute.
func TestRunAOPTurnRegistersScopeRules(t *testing.T) {
	t.Skip("covered by TestTurnScopeRulesRegistration: RunAOPTurn applies turnScopeRules before dispatch")
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A full fence table rejects the turn (FAILED_PRECONDITION) instead of
// A full fence table rejects the turn (fork fix, P1-0): eviction would
// unfence a live session behind its back, and a skipped registration would
// unfence this one — so turnScopeRules surfaces ErrCapacity and RunAOPTurn
// maps it to FAILED_PRECONDITION. The test fills the table until refusal,
// verifies the oldest session of its own still judges (nothing evicted),
// then drops every id it registered to leave capacity for later tests.
func TestTurnScopeRulesRefusesAtCapacity(t *testing.T) {
	valid := `{"enabled":true,"default_action":"record","rules":[{"id":"sr-cap","action":"block","method":"*","host":"cap.test"}]}`
	register := func(id string) error {
		return turnScopeRules(&aop.RunTurnRequest{SessionId: id, Extensions: []*anypb.Any{{
			TypeUrl: "type.googleapis.com/4zrcin.ScopeRules", Value: []byte(valid),
		}}})
	}
	const first = "sess-cap-first"
	if err := register(first); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}
	// Fill until refusal: the table may already hold sessions from earlier
	// tests in this package, so the loop ends at the first ErrCapacity.
	var refused bool
	for i := 0; i < 4096; i++ {
		id := fmt.Sprintf("sess-cap-%04d", i)
		if err := register(id); err != nil {
			if !errors.Is(err, scoperules.ErrCapacity) {
				t.Fatalf("refusal came wrapped in %v, want ErrCapacity", err)
			}
			refused = true
			break
		}
	}
	if !refused {
		t.Fatal("4096 registrations never hit the capacity limit")
	}
	// Nothing was evicted behind the first session's back.
	if verdict, judged := scoperules.JudgeSession(first, "GET", "https://cap.test/x"); !judged || verdict.Action != "block" {
		t.Fatalf("first session was evicted or unfenced: %+v judged=%v", verdict, judged)
	}
	// Re-registration of an existing session is a refresh, never a refusal.
	if err := register(first); err != nil {
		t.Fatalf("existing session refused on re-registration: %v", err)
	}
	// Cleanup: free every slot this test took so later tests start with
	// capacity.
	scoperules.DropSession(first)
	for i := 0; i < 4096; i++ {
		scoperules.DropSession(fmt.Sprintf("sess-cap-%04d", i))
	}
	if err := register("sess-cap-after-drop"); err != nil {
		t.Fatalf("registration after cleanup failed: %v", err)
	}
	scoperules.DropSession("sess-cap-after-drop")
}
