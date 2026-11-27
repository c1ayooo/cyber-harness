package scoperules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestMain mounts one store for the package's function-level tests; the
// production install path is the fence extension's Load, and tests that need
// isolation mount a fresh store themselves (drainSessionStore).
func TestMain(m *testing.M) {
	Install(NewStore())
	code := m.Run()
	Uninstall()
	os.Exit(code)
}

const validSet = `{
  "enabled": true,
  "default_action": "review",
  "shadow": false,
  "rules": [
    {"id": "sr-1", "action": "record", "method": "GET", "host": "api.example.com", "path_prefix": "/v1/"},
    {"id": "sr-2", "action": "block", "method": "*", "host": "*.internal.example", "path_prefix": ""},
    {"id": "sr-3", "action": "review", "method": "POST|DELETE", "host": "*", "path_prefix": "/admin"}
  ]
}`

func TestParseAcceptsAndNormalizes(t *testing.T) {
	set, err := Parse([]byte(validSet))
	if err != nil {
		t.Fatal(err)
	}
	if !set.Enabled || len(set.Rules) != 3 {
		t.Fatalf("set = %+v", set)
	}
	if set.Rules[2].Method != "POST|DELETE" {
		t.Fatalf("method not normalized: %q", set.Rules[2].Method)
	}
}

func TestParseRejectsInvalidSets(t *testing.T) {
	for name, raw := range map[string]string{
		"malformed json":     `{`,
		"bad default action": `{"enabled":true,"default_action":"steal"}`,
		"bad row action":     `{"enabled":true,"default_action":"record","rules":[{"id":"x","action":"hold","host":"a.com"}]}`,
		"row without host":   `{"enabled":true,"default_action":"record","rules":[{"id":"x","action":"record"}]}`,
		"path without slash": `{"enabled":true,"default_action":"record","rules":[{"id":"x","action":"record","host":"a.com","path_prefix":"api"}]}`,
		// manyRules closes the array itself; appending another "]" here would
		// fail on JSON syntax instead of the row cap (the old case did).
		"too many rows": `{"enabled":true,"default_action":"record","rules":[` + manyRules(maxRules+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatalf("Parse accepted %s", name)
			}
		})
	}
}

func manyRules(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		row, _ := json.Marshal(Rule{ID: "r", Action: ActionRecord, Host: "a.com"})
		out += string(row)
	}
	return out + "]}"
}

func TestJudgeFirstHitWins(t *testing.T) {
	set, err := Parse([]byte(validSet))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, url string
		wantAction  string
		wantRule    string
	}{
		{"GET", "https://api.example.com/v1/users", ActionRecord, "sr-1"},
		{"GET", "https://api.example.com/v2/users", ActionReview, ""},  // miss row 1 → default
		{"POST", "https://api.example.com/v1/users", ActionReview, ""}, // method mismatch → default
		{"POST", "http://other.internal.example/x", ActionBlock, "sr-2"},
		// One domain row covers the bare host too (fork patch 26): the operator
		// fencing *.internal.example fenced internal.example with it.
		{"GET", "http://internal.example/x", ActionBlock, "sr-2"},
		{"POST", "https://anything.test/admin/login", ActionReview, "sr-3"},
		{"DELETE", "https://anything.test/admin", ActionReview, "sr-3"},
		{"DELETE", "https://anything.test/administrator", ActionReview, "sr-3"}, // prefix, not segment match
		{"PUT", "https://anything.test/other", ActionReview, ""},
	}
	for _, tc := range cases {
		verdict, judged := set.Judge(tc.method, tc.url)
		if !judged {
			t.Fatalf("%s %s: not judged", tc.method, tc.url)
		}
		if verdict.Action != tc.wantAction || verdict.RuleID != tc.wantRule {
			t.Errorf("%s %s = %s/%q, want %s/%q", tc.method, tc.url, verdict.Action, verdict.RuleID, tc.wantAction, tc.wantRule)
		}
	}
}

// One domain row covers the bare host and every subdomain (fork patch 26),
// whatever spelling the row carried: an exact host, the "*." form and the
// legacy "." form all land on the same comparison, so the control plane can
// canonicalize "*.example.com" onto "example.com" without changing behavior.
func TestJudgeHostForms(t *testing.T) {
	set := func(host string) *Set {
		return &Set{Enabled: true, DefaultAction: ActionRecord, Rules: []Rule{
			{ID: "row", Action: ActionBlock, Method: "*", Host: host},
		}}
	}
	for _, host := range []string{"example.com", "*.example.com", ".example.com"} {
		s := set(host)
		if verdict, _ := s.Judge("GET", "https://example.com/x"); verdict.Action != ActionBlock {
			t.Fatalf("row %q did not match the bare host: %+v", host, verdict)
		}
		if verdict, _ := s.Judge("GET", "https://sub.example.com/x"); verdict.Action != ActionBlock {
			t.Fatalf("row %q did not match a subdomain: %+v", host, verdict)
		}
		if verdict, _ := s.Judge("GET", "https://example.org/x"); verdict.Action != ActionRecord {
			t.Fatalf("row %q leaked outside its domain: %+v", host, verdict)
		}
		// A longer domain sharing the textual suffix is not a subdomain.
		if verdict, _ := s.Judge("GET", "https://notexample.com/x"); verdict.Action != ActionRecord {
			t.Fatalf("row %q matched a suffix-only domain: %+v", host, verdict)
		}
	}
}

// The row cap mirrors the control plane's rule-table limit; 512 rows parse.
func TestParseAcceptsUpToTheCap(t *testing.T) {
	raw := `{"enabled":true,"default_action":"record","rules":[` + manyRules(maxRules)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatalf("Parse rejected a %d-row set: %v", maxRules, err)
	}
}

// The default-miss verdict carries the flag the control plane routes on
// (spec #1 工单4): a miss refuses and queues the asset for the operator's
// decision, so the sidecar must say "this was the fallback" — a refusal that
// looks like an explicit row's verdict would be indistinguishable from one
// the operator wrote by hand.
func TestJudgeMarksDefaultMiss(t *testing.T) {
	set := &Set{Enabled: true, DefaultAction: ActionReview, Rules: []Rule{
		{ID: "row", Action: ActionRecord, Method: "*", Host: "allowed.test"},
	}}
	verdict, judged := set.Judge("GET", "https://allowed.test/x")
	if !judged || verdict.DefaultMissed || verdict.RuleID != "row" {
		t.Fatalf("hit verdict = %+v judged=%v", verdict, judged)
	}
	verdict, judged = set.Judge("GET", "https://unknown.test/x")
	if !judged || verdict.Action != ActionReview || verdict.RuleID != "" || !verdict.DefaultMissed {
		t.Fatalf("miss verdict = %+v judged=%v", verdict, judged)
	}
}

// The CONNECT judge is host-form: a row passes the tunnel on its host alone
// (whatever method/path it refines — the tunnel cannot see them), CIDR rows
// match literal IPs directly and hostnames through the cached resolver, and
// an unmatched tunnel takes the default action with the default-miss flag
// (fork patch 31).
func TestJudgeConnectHostForm(t *testing.T) {
	set := &Set{Enabled: true, DefaultAction: ActionReview, Rules: []Rule{
		{ID: "host-row", Action: ActionRecord, Method: "GET", Host: "allowed.test"},
		{ID: "cidr-row", Action: ActionRecord, Method: "*", Host: "10.0.0.0/8"},
	}}
	verdict, judged := set.JudgeConnect("allowed.test:443")
	if !judged || verdict.Action != ActionRecord || verdict.RuleID != "host-row" || verdict.DefaultMissed {
		t.Fatalf("hostname row: verdict=%+v judged=%v", verdict, judged)
	}
	verdict, judged = set.JudgeConnect("10.1.2.3:443")
	if !judged || verdict.Action != ActionRecord || verdict.RuleID != "cidr-row" {
		t.Fatalf("literal IP against a CIDR row: verdict=%+v judged=%v", verdict, judged)
	}
	verdict, judged = set.JudgeConnect("unknown.test:443")
	if !judged || verdict.Action != ActionReview || !verdict.DefaultMissed {
		t.Fatalf("unmatched tunnel: verdict=%+v judged=%v", verdict, judged)
	}
}

func TestJudgeDisabledAndShadow(t *testing.T) {
	disabled := &Set{Enabled: false, DefaultAction: ActionBlock}
	if _, judged := disabled.Judge("GET", "https://a.com/"); judged {
		t.Fatal("disabled set judged a request")
	}
	shadow := &Set{Enabled: true, Shadow: true, DefaultAction: ActionBlock}
	verdict, judged := shadow.Judge("GET", "https://a.com/")
	if !judged || verdict.Action != ActionBlock || !verdict.Shadow {
		t.Fatalf("shadow verdict = %+v judged=%v", verdict, judged)
	}
}

func TestSessionStoreReplacesPerTurn(t *testing.T) {
	if err := SetRules("sess-1", []byte(validSet)); err != nil {
		t.Fatal(err)
	}
	if verdict, judged := JudgeSession("sess-1", "GET", "https://api.example.com/v1/x"); !judged || verdict.Action != ActionRecord {
		t.Fatalf("registered set not judged: %+v judged=%v", verdict, judged)
	}
	// The control plane re-sends the set every turn; the newest one wins.
	next := `{"enabled":true,"default_action":"record","rules":[]}`
	if err := SetRules("sess-1", []byte(next)); err != nil {
		t.Fatal(err)
	}
	if verdict, judged := JudgeSession("sess-1", "GET", "https://api.example.com/v1/x"); !judged || verdict.Action != ActionRecord {
		t.Fatalf("replaced set not judged: %+v judged=%v", verdict, judged)
	}
	// An invalid set is refused and leaves the previous one untouched.
	if err := SetRules("sess-1", []byte(`{"enabled":true,"default_action":"nope"}`)); err == nil {
		t.Fatal("invalid set accepted")
	}
	if _, judged := JudgeSession("sess-1", "GET", "https://api.example.com/v1/x"); !judged {
		t.Fatal("invalid set wiped the previous rules")
	}
	// Unknown sessions are never judged.
	if _, judged := JudgeSession("sess-unknown", "GET", "https://a.com/"); judged {
		t.Fatal("unregistered session judged")
	}
}

func TestVerdictRegistryTakeAndBound(t *testing.T) {
	RecordVerdict("flow-1", Verdict{Action: ActionBlock, RuleID: "sr-2"})
	verdict, ok := TakeVerdict("flow-1")
	if !ok || verdict.Action != ActionBlock {
		t.Fatalf("verdict = %+v ok=%v", verdict, ok)
	}
	if _, ok := TakeVerdict("flow-1"); ok {
		t.Fatal("verdict not consumed")
	}
	// The registry stays bounded: overwriting it with maxVerdicts+1 entries
	// must never grow past the cap.
	for i := 0; i < maxVerdicts+10; i++ {
		RecordVerdict("flow-many", Verdict{Action: ActionRecord})
		RecordVerdict(string(rune('a'+i%26))+string(rune(i)), Verdict{})
	}
	// The registry stays bounded: overwriting it with maxVerdicts+1 entries
	// must never grow past the cap. A fresh store answers without the noise of
	// whatever earlier tests left in the mounted one.
	store := NewStore()
	for i := 0; i < maxVerdicts+10; i++ {
		store.RecordVerdict("flow-many", Verdict{Action: ActionRecord})
		store.RecordVerdict(string(rune('a'+i%26))+string(rune(i)), Verdict{})
	}
	if len(store.verdictByFlow) > maxVerdicts {
		t.Fatalf("registry grew to %d", len(store.verdictByFlow))
	}
}

// The CIDR branch (fork patch 23a): "10.0.0.0/8" rows match the target's
// resolved address; every failure mode is a miss, never an invented verdict.
func TestJudgeCIDRHosts(t *testing.T) {
	t.Cleanup(func() {
		lookupHost = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	})

	set := func(host string) *Set {
		s, err := Parse([]byte(`{"enabled":true,"default_action":"record","rules":[{"id":"c1","action":"block","method":"*","host":"` + host + `","path_prefix":"/"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	verdict := func(host string) (Verdict, bool) {
		return set("10.0.0.0/8").Judge("GET", "http://"+host+"/a")
	}

	// IP-literal hosts match directly, in and out of the block.
	if v, judged := verdict("10.1.2.3"); !judged || v.Action != "block" {
		t.Fatalf("in-block literal: verdict=%+v judged=%v", v, judged)
	}
	if v, judged := verdict("192.168.1.1"); !judged || v.Action != "record" {
		t.Fatalf("out-of-block literal must fall through to default: verdict=%+v judged=%v", v, judged)
	}
	// Hostnames resolve: a resolved address inside the block matches.
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.9.9.9"}, nil
	}
	if v, judged := verdict("target.example.com"); !judged || v.Action != "block" {
		t.Fatalf("resolved in-block: verdict=%+v judged=%v", v, judged)
	}
	// Resolution failure is a miss, not an error verdict.
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return nil, context.DeadlineExceeded
	}
	if v, judged := verdict("dark.example.com"); !judged || v.Action != "record" {
		t.Fatalf("unresolvable host must fall through: verdict=%+v judged=%v", v, judged)
	}
	// IPv6 blocks and zones.
	s6, err := Parse([]byte(`{"enabled":true,"default_action":"record","rules":[{"id":"c6","action":"block","method":"*","host":"fe80::/16","path_prefix":"/"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if v, judged := s6.Judge("GET", "http://[fe80::1]:8080/x"); !judged || v.Action != "block" {
		t.Fatalf("ipv6 in-block: verdict=%+v judged=%v", v, judged)
	}
	// An unparseable row falls back to the exact-hostname comparison — it can
	// only miss against real request hosts (version-mismatch safety).
	if v, judged := set("not-a-cidr/x").Judge("GET", "http://10.0.0.1/"); !judged || v.Action != "record" {
		t.Fatalf("malformed row must fall through: verdict=%+v judged=%v", v, judged)
	}
}

// The DNS cache behind the CIDR branch: repeated lookups hit the cache (the
// stub is called once), entries expire, and the cache is bounded.
func TestResolveHostCache(t *testing.T) {
	original := lookupHost
	t.Cleanup(func() { lookupHost = original })
	dnsMu.Lock()
	dnsCache = map[string]dnsEntry{}
	dnsRing = nil
	dnsMu.Unlock()

	calls := 0
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		calls++
		return []string{"10.0.0.1"}, nil
	}
	for i := 0; i < 3; i++ {
		if addrs := resolveHost("cached.example.com"); len(addrs) != 1 {
			t.Fatalf("resolve %d returned %v", i, addrs)
		}
	}
	if calls != 1 {
		t.Fatalf("cache miss on repeat lookup: calls=%d", calls)
	}
	dnsMu.Lock()
	dnsCache["cached.example.com"] = dnsEntry{expires: time.Now().Add(-time.Minute)}
	dnsMu.Unlock()
	resolveHost("cached.example.com")
	if calls != 2 {
		t.Fatalf("expired entry did not re-resolve: calls=%d", calls)
	}
}

// A child session (a subagent's fresh id) inherits the parent's registered
// rule set (fork patch 33): the control plane registers per session at
// RunTurnRequest time, a channel the child's turns never see. A parent with
// nothing registered inherits nothing, and empty/self ids are no-ops.
func TestInheritSessionRules(t *testing.T) {
	if err := SetRules("sess-parent", []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-1","action":"block","method":"*","host":"blocked.test"}]}`)); err != nil {
		t.Fatal(err)
	}
	InheritSessionRules("sess-parent", "sess-child")
	verdict, judged := JudgeSession("sess-child", "GET", "http://blocked.test/x")
	if !judged || verdict.Action != ActionBlock || verdict.RuleID != "sr-1" {
		t.Fatalf("child verdict = %+v judged=%v", verdict, judged)
	}
	if v, judged := JudgeSession("sess-child", "GET", "http://other.test/x"); !judged || !v.DefaultMissed {
		t.Fatalf("child fallback = %+v judged=%v", v, judged)
	}

	// A parent that never registered fences nothing.
	InheritSessionRules("sess-ghost", "sess-orphan")
	if _, judged := JudgeSession("sess-orphan", "GET", "http://x/"); judged {
		t.Fatal("unknown parent registered rules on the child")
	}

	// Empty and self ids are no-ops, not panics and not registrations.
	InheritSessionRules("", "sess-x")
	InheritSessionRules("sess-parent", "")
	InheritSessionRules("sess-parent", "sess-parent")
	if _, judged := JudgeSession("sess-x", "GET", "http://x/"); judged {
		t.Fatal("empty parent registered rules")
	}
}

// The table holds only live sessions (fork fix, P1-0): a NEW session beyond
// the capacity is refused with ErrCapacity instead of silently evicting the
// oldest entry — eviction unfenced a live session with no log. An existing
// session re-registering is never refused, and DropSession frees the slot so
// a later session fits again.
// drainSessionStore mounts a fresh store so a capacity test starts from a
// known state (docs/19 E3-4: no package-level table to empty).
func drainSessionStore(t *testing.T) {
	Install(NewStore())
	// The cleanup remounts a fresh store instead of uninstalling: TestMain's
	// package-wide store must survive for the tests that follow.
	t.Cleanup(func() { Install(NewStore()) })
}

func TestCapacityRefusesNewSessionInsteadOfEvicting(t *testing.T) {
	drainSessionStore(t)
	raw := []byte(`{"enabled":true,"default_action":"record","rules":[{"id":"sr-cap","action":"block","method":"*","host":"cap.test"}]}`)
	first := "sess-cap-000"
	for i := 0; i < maxSessions; i++ {
		if err := SetRules(fmt.Sprintf("sess-cap-%03d", i), raw); err != nil {
			t.Fatalf("registration %d failed: %v", i, err)
		}
	}
	// The first session still judges: nothing was evicted behind its back.
	if verdict, judged := JudgeSession(first, "GET", "https://cap.test/x"); !judged || verdict.Action != ActionBlock {
		t.Fatalf("oldest session was evicted or unfenced: %+v judged=%v", verdict, judged)
	}
	if err := SetRules("sess-cap-overflow", raw); !errors.Is(err, ErrCapacity) {
		t.Fatalf("overflow error = %v, want ErrCapacity", err)
	}
	// An existing session re-registering past the (full) ring is a refresh,
	// never a refusal.
	if err := SetRules(first, raw); err != nil {
		t.Fatalf("existing session refused on re-registration: %v", err)
	}

	// Closing the first session frees its slot; the overflow session fits and
	// judges, and the closed one stops.
	DropSession(first)
	if _, judged := JudgeSession(first, "GET", "https://cap.test/x"); judged {
		t.Fatal("dropped session still judges")
	}
	if err := SetRules("sess-cap-overflow", raw); err != nil {
		t.Fatalf("registration after a drop failed: %v", err)
	}
	if verdict, judged := JudgeSession("sess-cap-overflow", "GET", "https://cap.test/x"); !judged || verdict.Action != ActionBlock {
		t.Fatalf("overflow session after a drop = %+v judged=%v", verdict, judged)
	}
	// Cleanup: drop everything this test registered so later tests start clean.
	for i := 0; i < maxSessions; i++ {
		DropSession(fmt.Sprintf("sess-cap-%03d", i))
	}
	DropSession("sess-cap-overflow")
}
