package scoperules

import (
	"encoding/json"
	"testing"
)

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
		"too many rows":      `{"enabled":true,"default_action":"record","rules":[` + manyRules(65) + `]}`,
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
		{"GET", "http://internal.example/x", ActionReview, ""}, // wildcard does not match base host
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

func TestJudgeHostForms(t *testing.T) {
	set := &Set{Enabled: true, DefaultAction: ActionRecord, Rules: []Rule{
		{ID: "dot", Action: ActionBlock, Method: "*", Host: ".example.com"},
	}}
	if verdict, _ := set.Judge("GET", "https://sub.example.com/x"); verdict.Action != ActionBlock {
		t.Fatalf("legacy dot form did not match subdomain: %+v", verdict)
	}
	if verdict, _ := set.Judge("GET", "https://example.com/x"); verdict.Action != ActionRecord {
		t.Fatalf("dot form matched the base host: %+v", verdict)
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
	if len(verdictByFlow) > maxVerdicts {
		t.Fatalf("registry grew to %d", len(verdictByFlow))
	}
}
