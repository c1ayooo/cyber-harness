package globalfence

import (
	"errors"
	"fmt"
	"testing"
)

const validSet = `{
  "enabled_commands": true,
  "commands": [
    {"id": "gf-1", "pattern": "rm\\s+-rf\\s+/", "desc": "递归强删根目录", "action": "deny"},
    {"id": "gf-2", "pattern": "^curl\\b", "desc": "外联 curl", "action": "review"}
  ],
  "enabled_domains": true,
  "domains": [
    {"id": "gf-10", "host": "gov.cn"},
    {"id": "gf-11", "host": "10.0.0.0/8"}
  ]
}`

// One instance fence registers per session the turn belongs to; a disabled
// list keeps its rows but hits nothing, and the judges read the newest set.
func TestParseAndJudge(t *testing.T) {
	if err := testStore.SetRules("sess-g", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	if rule, hit := testStore.JudgeCommand("sess-g", "rm -rf / --no-preserve-root"); !hit || rule.ID != "gf-1" || rule.Action != ActionDeny {
		t.Fatalf("command deny = %+v hit=%v", rule, hit)
	}
	if rule, hit := testStore.JudgeCommand("sess-g", "curl https://example.test"); !hit || rule.Action != ActionReview {
		t.Fatalf("command review = %+v hit=%v", rule, hit)
	}
	if _, hit := testStore.JudgeCommand("sess-g", "gogo -i 10.0.0.1"); hit {
		t.Fatal("unmatched command hit")
	}
	if rule, hit := testStore.DomainHit("sess-g", "www.gov.cn"); !hit || rule.ID != "gf-10" {
		t.Fatalf("subdomain of a denied domain: %+v hit=%v", rule, hit)
	}
	if rule, hit := testStore.DomainHit("sess-g", "gov.cn"); !hit || rule.ID != "gf-10" {
		t.Fatalf("bare denied domain: %+v hit=%v", rule, hit)
	}
	if rule, hit := testStore.DomainHit("sess-g", "10.9.9.9"); !hit || rule.ID != "gf-11" {
		t.Fatalf("CIDR-denied literal: %+v hit=%v", rule, hit)
	}
	if _, hit := testStore.DomainHit("sess-g", "notgov.cn"); hit {
		t.Fatal("suffix-only domain hit")
	}
}

// The switches are the operator's red-line switches: off means the list keeps
// its rows but judges nothing — the same honesty the project fence's draft
// mode has.
func TestSwitchesGateTheLists(t *testing.T) {
	disabled := `{"enabled_commands": false, "commands": [{"id": "gf-1", "pattern": "rm -rf /", "action": "deny"}], "enabled_domains": false, "domains": [{"id": "gf-10", "host": "gov.cn"}]}`
	if err := testStore.SetRules("sess-off", []byte(disabled)); err != nil {
		t.Fatal(err)
	}
	if _, hit := testStore.JudgeCommand("sess-off", "rm -rf /"); hit {
		t.Fatal("disabled command list hit")
	}
	if _, hit := testStore.DomainHit("sess-off", "gov.cn"); hit {
		t.Fatal("disabled domain list hit")
	}
}

// An invalid set is refused and leaves the previous one untouched: the control
// plane re-sends every turn, so one malformed payload must not open a hole.
func TestInvalidSetKeepsThePrevious(t *testing.T) {
	if err := testStore.SetRules("sess-k", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	broken := []string{
		`{"enabled_commands":true,"commands":[{"id":"x","pattern":"(","action":"deny"}]}`,
		`{"enabled_commands":true,"commands":[{"id":"x","pattern":"ok","action":"nuke"}]}`,
		`{"enabled_domains":true,"domains":[{"id":"x","host":"a..example"}]}`,
	}
	for _, raw := range broken {
		if err := testStore.SetRules("sess-k", []byte(raw)); err == nil {
			t.Fatalf("invalid set accepted: %s", raw)
		}
	}
	if _, hit := testStore.JudgeCommand("sess-k", "rm -rf /"); !hit {
		t.Fatal("invalid sets wiped the previous fence")
	}
}

// Unregistered sessions are never fenced: the proxy must not inherit one
// session's red lines into another's traffic.
func TestUnknownSessionIsUnfenced(t *testing.T) {
	if err := testStore.SetRules("sess-u", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	if _, hit := testStore.JudgeCommand("sess-other", "rm -rf /"); hit {
		t.Fatal("unregistered session inherited the command fence")
	}
	if _, hit := testStore.DomainHit("sess-other", "gov.cn"); hit {
		t.Fatal("unregistered session inherited the domain fence")
	}
}

// A child session inherits the parent's registered fence (fork patch 33), the
// same mechanism the project scope rules use: a subagent's fresh session id
// never sees a RunTurnRequest, so without the copy its commands and tunnels
// would fence nothing.
func TestInheritSessionRules(t *testing.T) {
	if err := testStore.SetRules("sess-parent", []byte(`{
		"enabled_commands": true,
		"commands": [{"id": "gf-1", "pattern": "shutdown\\s+-h\\b", "action": "deny"}],
		"enabled_domains": true,
		"domains": [{"id": "gf-10", "host": "gov.cn"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	testStore.InheritSessionRules("sess-parent", "sess-child")
	if _, hit := testStore.JudgeCommand("sess-child", "shutdown -h now"); !hit {
		t.Fatal("child command judged nothing")
	}
	if _, hit := testStore.DomainHit("sess-child", "www.gov.cn"); !hit {
		t.Fatal("child domain judged nothing")
	}

	testStore.InheritSessionRules("sess-ghost", "sess-orphan")
	if _, hit := testStore.JudgeCommand("sess-orphan", "shutdown -h now"); hit {
		t.Fatal("unknown parent fenced the child")
	}
	if _, hit := testStore.DomainHit("sess-orphan", "www.gov.cn"); hit {
		t.Fatal("unknown parent fenced the child domain")
	}
}

// The default-allow list sits between the deny list and the project fence
// (fork patch 37): infrastructure the operator always permits is exempt from
// both, and a deny red line on the same name still wins.
func TestAllowDomainHit(t *testing.T) {
	if err := testStore.SetRules("sess-allow", []byte(`{
		"enabled_domains": true,
		"domains": [{"id": "gf-deny", "host": "gov.cn"}],
		"enabled_allow_domains": true,
		"allow_domains": [{"id": "gf-allow", "host": "dns.alidns.com"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	if _, hit := testStore.AllowDomainHit("sess-allow", "dns.alidns.com"); !hit {
		t.Fatal("allow list did not match")
	}
	if _, hit := testStore.AllowDomainHit("sess-allow", "sub.dns.alidns.com"); !hit {
		t.Fatal("allow list did not cover the subdomain")
	}
	// An unlisted host matches neither list.
	if _, hit := testStore.AllowDomainHit("sess-allow", "target.example"); hit {
		t.Fatal("allow list matched an unlisted host")
	}
	// The deny list outranks the allow list when both name the host.
	if err := testStore.SetRules("sess-both", []byte(`{
		"enabled_domains": true,
		"domains": [{"id": "gf-deny", "host": "dns.alidns.com"}],
		"enabled_allow_domains": true,
		"allow_domains": [{"id": "gf-allow", "host": "dns.alidns.com"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	if _, hit := testStore.DomainHit("sess-both", "dns.alidns.com"); !hit {
		t.Fatal("deny list lost to the allow list")
	}
	// A disabled allow switch judges nothing.
	if err := testStore.SetRules("sess-off", []byte(`{"enabled_allow_domains": false, "allow_domains": [{"id": "gf-a", "host": "dns.alidns.com"}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, hit := testStore.AllowDomainHit("sess-off", "dns.alidns.com"); hit {
		t.Fatal("disabled allow list matched")
	}
}

// The fence table holds only live sessions (fork fix, P1-0): a NEW session
// beyond the capacity is refused with ErrCapacity instead of silently evicting
// the oldest entry, and closing a session frees its slot.
// drainSessionStore swaps in a fresh store so a capacity test starts from a
// known state (4zdesign/19 E3-4: no package-level table to empty).
func drainSessionStore(t *testing.T) {
	testStore = NewStore()
	// The cleanup restores a fresh store for the tests that follow.
	t.Cleanup(func() { testStore = NewStore() })
}

func TestCapacityRefusesNewSessionInsteadOfEvicting(t *testing.T) {
	drainSessionStore(t)
	raw := []byte(`{"enabled_commands": true, "commands": [{"id": "gf-cap", "pattern": "shutdown\\s+-h\\b", "action": "deny"}]}`)
	first := "gf-sess-000"
	for i := 0; i < maxSessions; i++ {
		if err := testStore.SetRules(fmt.Sprintf("gf-sess-%03d", i), raw); err != nil {
			t.Fatalf("registration %d failed: %v", i, err)
		}
	}
	// The first session still fences: nothing was evicted behind its back.
	if _, hit := testStore.JudgeCommand(first, "shutdown -h now"); !hit {
		t.Fatal("oldest session was evicted or unfenced")
	}
	if err := testStore.SetRules("gf-sess-overflow", raw); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow error = %v, want ErrCapacity", err)
	}
	if err := testStore.SetRules(first, raw); err != nil {
		t.Fatalf("existing session refused on re-registration: %v", err)
	}

	testStore.DropSession(first)
	if _, hit := testStore.JudgeCommand(first, "shutdown -h now"); hit {
		t.Fatal("dropped session still fences")
	}
	if err := testStore.SetRules("gf-sess-overflow", raw); err != nil {
		t.Fatalf("registration after a drop failed: %v", err)
	}
	if _, hit := testStore.JudgeCommand("gf-sess-overflow", "shutdown -h now"); !hit {
		t.Fatal("overflow session after a drop fenced nothing")
	}
	for i := 0; i < maxSessions; i++ {
		testStore.DropSession(fmt.Sprintf("gf-sess-%03d", i))
	}
	testStore.DropSession("gf-sess-overflow")
}

// Inheritance beyond the table's capacity is an error, not a silent skip: the
// subagent tool fails the child's creation, so a delegated direction never
// starts unfenced.
func TestInheritSessionRulesRefusesAtCapacity(t *testing.T) {
	drainSessionStore(t)
	raw := []byte(`{"enabled_commands": true, "commands": [{"id": "gf-ih", "pattern": "shutdown\\s+-h\\b", "action": "deny"}]}`)
	if err := testStore.SetRules("gf-inherit-parent", raw); err != nil {
		t.Fatal(err)
	}
	// The parent occupies one slot; exactly maxSessions-1 fillers fill the
	// table, so the child's inherit is the refused (maxSessions+1)th entry.
	for i := 0; i < maxSessions-1; i++ {
		id := fmt.Sprintf("gf-inherit-%03d", i)
		if err := testStore.SetRules(id, raw); err != nil {
			t.Fatalf("registration %d failed: %v", i, err)
		}
	}
	if err := testStore.InheritSessionRules("gf-inherit-parent", "gf-inherit-child"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("inherit error = %v, want ErrCapacity", err)
	}
	if _, hit := testStore.JudgeCommand("gf-inherit-child", "shutdown -h now"); hit {
		t.Fatal("an unregistered child fenced anything")
	}
	for i := 0; i < maxSessions-1; i++ {
		testStore.DropSession(fmt.Sprintf("gf-inherit-%03d", i))
	}
	testStore.DropSession("gf-inherit-parent")
}
