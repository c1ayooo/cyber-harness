package fence

import (
	"encoding/json"
	"net/http"
	"testing"

	aop "github.com/chainreactors/cyber/aop"

	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
)

// The scope-judge policy pieces that moved here in E3 (the proxy keeps only
// the seam): the control-plane exemption, the passive Sec-Fetch-Dest
// reading, and the 403 refusal body. They were upstream-adjacent behavior in
// tools/proxy before; the tables below pin the semantics that did not move.

func TestControlPlaneExemptionIsPlatformPlumbing(t *testing.T) {
	// The test target lives on 127.0.0.1; naming that host as the control
	// plane exempts the whole loopback family — the executor's API base and
	// the scan share one node, spelled 127.0.0.1, localhost and ::1.
	exempt := ControlPlaneExemption("127.0.0.1")
	if !exempt("127.0.0.1") || !exempt("localhost") || !exempt("[::1]") || !exempt(" 127.0.0.1 ") {
		t.Fatalf("loopback family not exempt")
	}
	if exempt("in-range.test") || exempt("example.com") {
		t.Fatalf("unrelated host exempt")
	}
	// A different node's control plane does not leak: empty exempts nothing,
	// and a named non-loopback host matches only itself.
	none := ControlPlaneExemption("")
	if none("127.0.0.1") {
		t.Fatalf("empty control plane exempted a host")
	}
	named := ControlPlaneExemption("ctrl.example")
	if !named("ctrl.example") || named("other.example") || named("localhost") {
		t.Fatalf("named control plane matched the wrong hosts")
	}
}

func TestScopeRequestPassiveReadsFetchDest(t *testing.T) {
	call := func(arguments string) *aop.ToolCall {
		return &aop.ToolCall{Arguments: &aop.EncodedValue{Data: []byte(arguments)}}
	}
	for arguments, want := range map[string]bool{
		`{"dest":"script"}`:   true,
		`{"dest":"STYLE"}`:    true,
		`{"dest":" image "}`:  true,
		`{"dest":"document"}`: false,
		`{"dest":""}`:         false,
		// The legacy wire format carries the judge's verdict directly.
		`{"passive":true}`:                   true,
		`{}`:                                 false,
		`{"dest":"document","passive":true}`: false,
	} {
		if got := scopeRequestPassive(call(arguments)); got != want {
			t.Fatalf("scopeRequestPassive(%s) = %v, want %v", arguments, got, want)
		}
	}
}

// The refusal body explains itself (fork patch 34): pending marks the
// allowlist fallback only, and the reason carries the verdict prose.
func TestScopeRefusalBody(t *testing.T) {
	verdict := scoperules.Verdict{Action: scoperules.ActionReview, Reason: "范围外",
		DefaultMissed: true}
	refusal := scopeRefusal("https://outside.test/app.js", verdict)
	if refusal.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", refusal.StatusCode)
	}
	if got, want := refusal.Header.Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("content type = %q, want %q", got, want)
	}
	var body struct {
		Error   string `json:"error"`
		Host    string `json:"host"`
		Reason  string `json:"reason"`
		Pending bool   `json:"pending"`
	}
	if err := json.Unmarshal(refusal.Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Error != "scope_rules_refused" || body.Host != "outside.test" || body.Reason != "范围外" || !body.Pending {
		t.Fatalf("refusal body = %+v", body)
	}
	// An explicit review row is not the allowlist fallback: no pending mark.
	explicit := scoperules.Verdict{Action: scoperules.ActionReview, Reason: "敏感"}
	body = struct {
		Error   string `json:"error"`
		Host    string `json:"host"`
		Reason  string `json:"reason"`
		Pending bool   `json:"pending"`
	}{}
	if err := json.Unmarshal(scopeRefusal("https://inside.test/x", explicit).Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if body.Pending {
		t.Fatalf("explicit review row marked pending: %+v", body)
	}
}
