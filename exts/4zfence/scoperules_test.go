package fence

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	agenthooks "github.com/chainreactors/cyber/agent/hooks"
	agentsession "github.com/chainreactors/cyber/agent/session"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/exts/4zfence/egressroutes"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	"google.golang.org/protobuf/types/known/anypb"
)

// testFence is the fence extension the package's tests read and write: the
// turn decorators, the session hooks, the admission and the scope judge all
// act on its own tables (4zdesign/19 E3-4).
var testFence *Extension

// installStores builds the test's fence extension with fresh scope, fence
// and route tables. The real production path is the extension's Load; tests
// get the same tables without constructing the whole extension.
func installStores(t *testing.T) {
	t.Helper()
	testFence = &Extension{scopes: scoperules.NewStore(), globals: globalfence.NewStore(), routes: egressroutes.NewStore()}
	t.Cleanup(func() { testFence = nil })
}

// testFenceWith gives that extension its stream, so what a test registers is
// what its judge and admission read.
func testFenceWith(stream *events.Stream) *Extension {
	testFence.stream = stream
	return testFence
}

// The scope-rule set registers for the session the turn belongs to, in both
// namespaces; an invalid set is ignored without touching the previous one.
func TestTurnScopeRulesRegistration(t *testing.T) {
	installStores(t)
	valid := `{"enabled":true,"default_action":"record","rules":[{"id":"sr-1","action":"review","method":"*","host":"*"}]}`
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		req := &aop.RunTurnRequest{SessionId: "sess-scope", Extensions: []*anypb.Any{{
			TypeUrl: "type.googleapis.com/" + namespace + ".ScopeRules", Value: []byte(valid),
		}}}
		testFence.turnScopeRules(req)
		verdict, judged := testFence.scopes.JudgeSession("sess-scope", "GET", "https://api.example.test/v1")
		if !judged || verdict.Action != "review" {
			t.Fatalf("namespace %s: verdict = %+v judged=%v", namespace, verdict, judged)
		}
	}
	invalid := `{"enabled":true,"default_action":"nonsense"}`
	testFence.turnScopeRules(&aop.RunTurnRequest{SessionId: "sess-scope", Extensions: []*anypb.Any{{
		TypeUrl: "type.googleapis.com/4zrcin.ScopeRules", Value: []byte(invalid),
	}}})
	if verdict, judged := testFence.scopes.JudgeSession("sess-scope", "GET", "https://api.example.test/v1"); !judged || verdict.Action != "review" {
		t.Fatalf("invalid set wiped the previous rules: %+v judged=%v", verdict, judged)
	}
	// A turn without the extension keeps the last set (the control plane
	// re-sends even disabled drafts every turn precisely to keep this honest).
	testFence.turnScopeRules(&aop.RunTurnRequest{SessionId: "sess-scope"})
	if _, judged := testFence.scopes.JudgeSession("sess-scope", "GET", "https://x.test/"); !judged {
		t.Fatal("extension-less turn dropped the registered set")
	}
}

// The scope rules register before the turn runs: RunAOPTurn applies them for
// the session it is about to execute.
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
	installStores(t)
	valid := `{"enabled":true,"default_action":"record","rules":[{"id":"sr-cap","action":"block","method":"*","host":"cap.test"}]}`
	register := func(id string) error {
		return testFence.turnScopeRules(&aop.RunTurnRequest{SessionId: id, Extensions: []*anypb.Any{{
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
	if verdict, judged := testFence.scopes.JudgeSession(first, "GET", "https://cap.test/x"); !judged || verdict.Action != "block" {
		t.Fatalf("first session was evicted or unfenced: %+v judged=%v", verdict, judged)
	}
	// Re-registration of an existing session is a refresh, never a refusal.
	if err := register(first); err != nil {
		t.Fatalf("existing session refused on re-registration: %v", err)
	}
	// Cleanup: free every slot this test took so later tests start with
	// capacity.
	testFence.scopes.DropSession(first)
	for i := 0; i < 4096; i++ {
		testFence.scopes.DropSession(fmt.Sprintf("sess-cap-%04d", i))
	}
	if err := register("sess-cap-after-drop"); err != nil {
		t.Fatalf("registration after cleanup failed: %v", err)
	}
	testFence.scopes.DropSession("sess-cap-after-drop")
}

// The runtime's fence lifecycle handlers (fork fix P1-0): a child session
// inherits its parent's registrations at open — a full table fails the open
// rather than starting the child unfenced — and every close drops them, so
// the tables hold only live sessions.
func TestFenceLifecycleHandlers(t *testing.T) {
	installStores(t)
	if err := testFence.scopes.SetRules("fence-parent", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-x","action":"block","method":"*","host":"x.test","path_prefix":"/"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := testFence.globals.SetRules("fence-parent", []byte(`{"enabled_domains":true,"domains":[{"id":"gf-x","host":"x.test"}]}`)); err != nil {
		t.Fatal(err)
	}

	child := agenthooks.SessionEvent{SessionID: "fence-child", ParentID: "fence-parent"}
	if _, err := testFence.inheritOnOpen(t.Context(), child); err != nil {
		t.Fatalf("inherit: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("fence-child", "GET", "http://x.test/"); !judged {
		t.Fatal("child did not inherit the project fence")
	}
	if _, hit := testFence.globals.DomainHit("fence-child", "www.x.test"); !hit {
		t.Fatal("child did not inherit the instance fence")
	}

	// A root session inherits nothing.
	root := agenthooks.SessionEvent{SessionID: "fence-root"}
	if _, err := testFence.inheritOnOpen(t.Context(), root); err != nil {
		t.Fatalf("root inherit: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("fence-root", "GET", "http://x.test/"); judged {
		t.Fatal("a root session inherited a fence that does not exist")
	}

	// Close drops both tables; a second drop is a no-op.
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "fence-child"}); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("fence-child", "GET", "http://x.test/"); judged {
		t.Fatal("closed child still holds the project fence")
	}
	if _, hit := testFence.globals.DomainHit("fence-child", "www.x.test"); hit {
		t.Fatal("closed child still holds the instance fence")
	}
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "fence-child"}); err != nil {
		t.Fatalf("second drop: %v", err)
	}

	testFence.scopes.DropSession("fence-parent")
	testFence.globals.DropSession("fence-parent")
}

// Session.rotate closes the old session before it opens the continuation
// (agent/session rotate), so a rotation close must park the registrations
// for the child's inheritance instead of dropping them — otherwise /clear,
// /compact and resume each run one turn with the child unfenced (4zdesign/19
// appendix E2-2, fork fix 已决 18). Non-rotation closes still drop.
func TestFenceRotationCloseParksForContinuation(t *testing.T) {
	installStores(t)
	if err := testFence.scopes.SetRules("rot-parent", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-r","action":"block","method":"*","host":"blocked.test","path_prefix":"/"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := testFence.globals.SetRules("rot-parent", []byte(`{"enabled_domains":true,"domains":[{"id":"gf-r","host":"gov.cn"}]}`)); err != nil {
		t.Fatal(err)
	}

	// The rotate order, reproduced: SessionEnd for the old id first...
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "rot-parent", Reason: string(agentsession.SessionCloseCleared)}); err != nil {
		t.Fatalf("rotate close: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("rot-parent", "GET", "http://blocked.test/"); judged {
		t.Fatal("rotated-out parent still holds a live registration")
	}
	// ...then SessionStart for the continuation, whose parent is already
	// gone from the live tables and must inherit from the park.
	if _, err := testFence.inheritOnOpen(t.Context(), agenthooks.SessionEvent{SessionID: "rot-child", ParentID: "rot-parent"}); err != nil {
		t.Fatalf("continuation inherit: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("rot-child", "GET", "http://blocked.test/x"); !judged {
		t.Fatal("continuation did not inherit the project fence across rotation")
	}
	if _, hit := testFence.globals.DomainHit("rot-child", "www.gov.cn"); !hit {
		t.Fatal("continuation did not inherit the instance fence across rotation")
	}

	// A second hop parks and inherits the same way.
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "rot-child", Reason: string(agentsession.SessionCloseCompacted)}); err != nil {
		t.Fatalf("second rotate close: %v", err)
	}
	if _, err := testFence.inheritOnOpen(t.Context(), agenthooks.SessionEvent{SessionID: "rot-grandchild", ParentID: "rot-child"}); err != nil {
		t.Fatalf("second continuation inherit: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("rot-grandchild", "GET", "http://blocked.test/x"); !judged {
		t.Fatal("second continuation did not inherit the project fence")
	}

	// A non-rotation close drops without parking: a later open with that
	// parent id inherits nothing.
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "rot-grandchild", Reason: string(agentsession.SessionCloseCompleted)}); err != nil {
		t.Fatalf("final close: %v", err)
	}
	if _, err := testFence.inheritOnOpen(t.Context(), agenthooks.SessionEvent{SessionID: "rot-after", ParentID: "rot-grandchild"}); err != nil {
		t.Fatalf("inherit after final close: %v", err)
	}
	if _, judged := testFence.scopes.JudgeSession("rot-after", "GET", "http://blocked.test/x"); judged {
		t.Fatal("a completed close leaked its registrations into the park")
	}

	testFence.scopes.DropSession("rot-child")
	testFence.globals.DropSession("rot-child")
	testFence.scopes.DropSession("rot-after")
	testFence.globals.DropSession("rot-after")
}
