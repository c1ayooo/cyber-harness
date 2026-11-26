package globalfence

import (
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
	if err := SetRules("sess-g", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	if rule, hit := JudgeCommand("sess-g", "rm -rf / --no-preserve-root"); !hit || rule.ID != "gf-1" || rule.Action != ActionDeny {
		t.Fatalf("command deny = %+v hit=%v", rule, hit)
	}
	if rule, hit := JudgeCommand("sess-g", "curl https://example.test"); !hit || rule.Action != ActionReview {
		t.Fatalf("command review = %+v hit=%v", rule, hit)
	}
	if _, hit := JudgeCommand("sess-g", "gogo -i 10.0.0.1"); hit {
		t.Fatal("unmatched command hit")
	}
	if rule, hit := DomainHit("sess-g", "www.gov.cn"); !hit || rule.ID != "gf-10" {
		t.Fatalf("subdomain of a denied domain: %+v hit=%v", rule, hit)
	}
	if rule, hit := DomainHit("sess-g", "gov.cn"); !hit || rule.ID != "gf-10" {
		t.Fatalf("bare denied domain: %+v hit=%v", rule, hit)
	}
	if rule, hit := DomainHit("sess-g", "10.9.9.9"); !hit || rule.ID != "gf-11" {
		t.Fatalf("CIDR-denied literal: %+v hit=%v", rule, hit)
	}
	if _, hit := DomainHit("sess-g", "notgov.cn"); hit {
		t.Fatal("suffix-only domain hit")
	}
}

// The switches are the operator's red-line switches: off means the list keeps
// its rows but judges nothing — the same honesty the project fence's draft
// mode has.
func TestSwitchesGateTheLists(t *testing.T) {
	disabled := `{"enabled_commands": false, "commands": [{"id": "gf-1", "pattern": "rm -rf /", "action": "deny"}], "enabled_domains": false, "domains": [{"id": "gf-10", "host": "gov.cn"}]}`
	if err := SetRules("sess-off", []byte(disabled)); err != nil {
		t.Fatal(err)
	}
	if _, hit := JudgeCommand("sess-off", "rm -rf /"); hit {
		t.Fatal("disabled command list hit")
	}
	if _, hit := DomainHit("sess-off", "gov.cn"); hit {
		t.Fatal("disabled domain list hit")
	}
}

// An invalid set is refused and leaves the previous one untouched: the control
// plane re-sends every turn, so one malformed payload must not open a hole.
func TestInvalidSetKeepsThePrevious(t *testing.T) {
	if err := SetRules("sess-k", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	broken := []string{
		`{"enabled_commands":true,"commands":[{"id":"x","pattern":"(","action":"deny"}]}`,
		`{"enabled_commands":true,"commands":[{"id":"x","pattern":"ok","action":"nuke"}]}`,
		`{"enabled_domains":true,"domains":[{"id":"x","host":"a..example"}]}`,
	}
	for _, raw := range broken {
		if err := SetRules("sess-k", []byte(raw)); err == nil {
			t.Fatalf("invalid set accepted: %s", raw)
		}
	}
	if _, hit := JudgeCommand("sess-k", "rm -rf /"); !hit {
		t.Fatal("invalid sets wiped the previous fence")
	}
}

// Unregistered sessions are never fenced: the proxy must not inherit one
// session's red lines into another's traffic.
func TestUnknownSessionIsUnfenced(t *testing.T) {
	if err := SetRules("sess-u", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	if _, hit := JudgeCommand("sess-other", "rm -rf /"); hit {
		t.Fatal("unregistered session inherited the command fence")
	}
	if _, hit := DomainHit("sess-other", "gov.cn"); hit {
		t.Fatal("unregistered session inherited the domain fence")
	}
}

// A child session inherits the parent's registered fence (fork patch 33), the
// same mechanism the project scope rules use: a subagent's fresh session id
// never sees a RunTurnRequest, so without the copy its commands and tunnels
// would fence nothing.
func TestInheritSessionRules(t *testing.T) {
	if err := SetRules("sess-parent", []byte(`{
		"enabled_commands": true,
		"commands": [{"id": "gf-1", "pattern": "shutdown\\s+-h\\b", "action": "deny"}],
		"enabled_domains": true,
		"domains": [{"id": "gf-10", "host": "gov.cn"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	InheritSessionRules("sess-parent", "sess-child")
	if _, hit := JudgeCommand("sess-child", "shutdown -h now"); !hit {
		t.Fatal("child command judged nothing")
	}
	if _, hit := DomainHit("sess-child", "www.gov.cn"); !hit {
		t.Fatal("child domain judged nothing")
	}

	InheritSessionRules("sess-ghost", "sess-orphan")
	if _, hit := JudgeCommand("sess-orphan", "shutdown -h now"); hit {
		t.Fatal("unknown parent fenced the child")
	}
	if _, hit := DomainHit("sess-orphan", "www.gov.cn"); hit {
		t.Fatal("unknown parent fenced the child domain")
	}
}
