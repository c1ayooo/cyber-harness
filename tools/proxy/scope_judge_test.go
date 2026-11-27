package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/cyber/core/operation"
	mitmproxy "github.com/chainreactors/utils/mitmproxy/proxy"
)

// The seam tests run against canned judges: the proxy's contract is to carry
// the decision — verdict verbatim, hold, refusal — not to understand the
// rule tables (those live in the fence and its own tests).

// cannedJudge answers from a static table: host → decision pieces.
type cannedJudge struct {
	// known hosts judge; anything else is "not my business".
	byHost map[string]hostDecision
}

type hostDecision struct {
	action  string
	verdict *ScopeVerdict
	refusal *mitmproxy.Response
	holdOK  bool
}

func (j *cannedJudge) JudgeScopeRequest(req ScopeRequest) ScopeDecision {
	return j.decide(req)
}

func (j *cannedJudge) JudgeScopeConnect(req ScopeRequest) ScopeDecision {
	return j.decide(req)
}

func (j *cannedJudge) decide(req ScopeRequest) ScopeDecision {
	if req.Invocation.SessionID == "" || req.Call == nil {
		return ScopeDecision{}
	}
	var arguments struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(req.Call.GetArguments().GetData(), &arguments) != nil {
		return ScopeDecision{}
	}
	parsed, err := url.Parse(arguments.URL)
	if err != nil {
		return ScopeDecision{}
	}
	host, ok := j.byHost[parsed.Hostname()]
	if !ok {
		return ScopeDecision{}
	}
	decision := ScopeDecision{Judged: true, Action: host.action, Verdict: host.verdict, Refusal: host.refusal}
	if host.action == ActionReview {
		approved := host.holdOK
		decision.Hold = func(context.Context) bool { return approved }
	}
	return decision
}

func refusalFor(host string) *mitmproxy.Response {
	body, _ := json.Marshal(map[string]any{"error": "scope_rules_refused", "host": host, "reason": "范围外"})
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	return &mitmproxy.Response{StatusCode: http.StatusForbidden, Header: header, Body: body}
}

// attributedClient builds a client whose requests carry an egress correlation
// lease attributed to a session — the same path real tool calls take.
func attributedClient(t *testing.T, hub *Hub, sessionID, callID string) *http.Client {
	t.Helper()
	ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{SessionID: sessionID, CallID: callID})
	ctx, cancel := operation.Begin(ctx, "test", "http")
	proxyURL, _, release := hub.Egress(ctx)
	t.Cleanup(func() { release(); cancel(nil) })
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
}

// plainClient reaches the hub without any correlation lease: the host's own
// unattributed plumbing.
func plainClient(t *testing.T, hub *Hub) *http.Client {
	t.Helper()
	parsed, err := url.Parse(hub.ProxyURL())
	if err != nil {
		t.Fatalf("parse hub url: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
}

// TestScopeJudgeBlocksRequest verifies the full block path: the judge's
// refusal is what the tool sees, the target never receives the request, the
// refusal is captured as a flow, and the verdict lands in the sidecar
// registry.
func TestScopeJudgeBlocksRequest(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(&cannedJudge{byHost: map[string]hostDecision{
		"blocked.test": {action: ActionBlock, refusal: refusalFor("blocked.test"),
			verdict: &ScopeVerdict{Action: ActionBlock, RuleID: "sr-1", Reason: "范围外"}},
	}})

	resp, err := attributedClient(t, hub, "sess-x", "tool-1").Get("http://blocked.test/steal")
	if err != nil {
		t.Fatalf("request through hub: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("blocked request reached the target %d times", hits.Load())
	}
	if !containsString(string(body), "scope_rules_refused") {
		t.Fatalf("refusal body = %s", body)
	}
	flows := waitForFlows(t, hub.store, 1)
	if len(flows) == 0 || flows[0].GetResponse().GetStatusCode() != http.StatusForbidden {
		t.Fatalf("captured flow = %+v", flows)
	}
	verdict, ok := TakeVerdict(flows[0].GetId())
	if !ok || verdict.Action != ActionBlock || verdict.RuleID != "sr-1" {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}
}

// TestScopeJudgeRecordForwardsAndCaptures verifies the quiet path: a record
// verdict forwards untouched and still records the verdict sidecar, while a
// request without a session attribution (host plumbing) is never judged.
func TestScopeJudgeRecordForwardsAndCaptures(t *testing.T) {
	target := startTestTarget(64)
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(&cannedJudge{byHost: map[string]hostDecision{
		"127.0.0.1": {action: ActionRecord, verdict: &ScopeVerdict{Action: ActionRecord, RuleID: "sr-ok"}},
	}})

	getThrough(t, attributedClient(t, hub, "sess-x", "tool-1"), target.URL)
	flows := waitForFlows(t, hub.store, 1)
	if len(flows) == 0 || flows[0].GetResponse().GetStatusCode() != http.StatusOK {
		t.Fatalf("recorded flow = %+v", flows)
	}
	if verdict, ok := TakeVerdict(flows[0].GetId()); !ok || verdict.Action != ActionRecord {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}

	// Unattributed traffic is the host's own plumbing: never judged, even on a
	// host a rule would block.
	getThrough(t, plainClient(t, hub), "http://blocked.test/")
	time.Sleep(100 * time.Millisecond)
	for _, flow := range hub.store.Query(Filter{}) {
		if verdict, ok := TakeVerdict(flow.GetId()); ok {
			t.Fatalf("unattributed request judged: %+v", verdict)
		}
	}
}

// TestScopeJudgeWithoutJudgeIsUntouched pins the zero-value behavior: a hub
// without a judge forwards and captures exactly like before the feature.
func TestScopeJudgeWithoutJudgeIsUntouched(t *testing.T) {
	target := startTestTarget(64)
	defer target.Close()
	hub := startHub(t, true)
	getThrough(t, attributedClient(t, hub, "sess-x", "tool-1"), target.URL)
	if flows := waitForFlows(t, hub.store, 1); len(flows) == 0 || flows[0].GetResponse().GetStatusCode() != http.StatusOK {
		t.Fatalf("judgeless hub altered forwarding: %+v", flows)
	}
}

func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The verdict the judge answers with travels verbatim into the sidecar
// registry under the canonical flow id (fork patch 33): a default-miss
// verdict keeps default_missed, the flag the control plane routes the
// asset-pending flow on. The pre-patch behavior reconstructed the verdict
// from the decision's action and dropped the flag.
func TestScopeJudgeVerdictTravelsVerbatim(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(&cannedJudge{byHost: map[string]hostDecision{
		"outside.test": {action: ActionReview, holdOK: false,
			verdict: &ScopeVerdict{Action: ActionReview, Reason: "范围外", DefaultMissed: true},
			refusal: refusalFor("outside.test")},
	}})
	resp, err := attributedClient(t, hub, "sess-miss", "tool-1").Get("http://outside.test/app.js")
	if err != nil {
		t.Fatalf("request through hub: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want the refused review", resp.StatusCode)
	}
	flows := waitForFlows(t, hub.store, 1)
	verdict, ok := TakeVerdict(flows[0].GetId())
	if !ok || verdict.Action != ActionReview || !verdict.DefaultMissed {
		t.Fatalf("sidecar verdict = %+v ok=%v (default_missed lost)", verdict, ok)
	}
	// The refusal reached the requester verbatim.
	if !containsString(string(body), "scope_rules_refused") {
		t.Fatalf("refusal body = %s", body)
	}
}

// A verdict the judge never attached (a bare stub) reconstructs the historical
// three fields: the proxy must not invent default_missed where the judge set
// none.
func TestScopeJudgeVerdictWithoutVerdictReconstructs(t *testing.T) {
	target := startTestTarget(64)
	defer target.Close()
	hub := startHub(t, true)
	hub.SetScopeJudge(&bareJudge{host: "127.0.0.1", action: ActionRecord, ruleID: "", reason: "record"})
	getThrough(t, attributedClient(t, hub, "sess-bare", "tool-1"), target.URL)
	flows := waitForFlows(t, hub.store, 1)
	verdict, ok := TakeVerdict(flows[0].GetId())
	// The reconstruction keeps action/reason but invents no flags.
	if !ok || verdict.Action != ActionRecord || verdict.RuleID != "" || verdict.DefaultMissed || verdict.Passive {
		t.Fatalf("reconstructed verdict = %+v ok=%v", verdict, ok)
	}
}

// bareJudge answers from the action alone, like a judge predating the
// verbatim verdict field.
type bareJudge struct {
	host, action, ruleID, reason string
}

func (j *bareJudge) decision(req ScopeRequest) ScopeDecision {
	if req.Invocation.SessionID == "" || req.Call == nil {
		return ScopeDecision{}
	}
	var arguments struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(req.Call.GetArguments().GetData(), &arguments) != nil {
		return ScopeDecision{}
	}
	parsed, err := url.Parse(arguments.URL)
	if err != nil || parsed.Hostname() != j.host {
		return ScopeDecision{}
	}
	return ScopeDecision{Judged: true, Action: j.action, RuleID: j.ruleID, Reason: j.reason}
}

func (j *bareJudge) JudgeScopeRequest(req ScopeRequest) ScopeDecision { return j.decision(req) }
func (j *bareJudge) JudgeScopeConnect(req ScopeRequest) ScopeDecision { return ScopeDecision{} }

// The exemption hook names the requester's own plumbing (fork patch 36): a
// bookkeeping call to an exempt host is forwarded unjudged and uncaptured,
// even when the judge would hold it. Before the skip, every such call was
// held for review — the operator approved one call per step.
func TestScopeJudgeExemptionIsPlatformPlumbing(t *testing.T) {
	target := startTestTarget(64)
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(&cannedJudge{byHost: map[string]hostDecision{
		"127.0.0.1": {action: ActionReview, holdOK: false,
			verdict: &ScopeVerdict{Action: ActionReview, DefaultMissed: true},
			refusal: refusalFor("127.0.0.1")},
	}})
	// The judge would refuse everything; the exemption forwards the control
	// plane anyway.
	hub.SetRequestExemption(func(host string) bool {
		return host == "127.0.0.1" || host == "localhost" || host == "[::1]" // the loopback family, as the fence's policy spells it
	})
	client := attributedClient(t, hub, "sess-loop", "tool-1")
	if tr, ok := client.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	resp, err := client.Get(localhost(target.URL) + "/api/intents/in_x/run")
	if err != nil {
		t.Fatalf("control-plane call through hub: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("control-plane status = %d, want forwarded 200", resp.StatusCode)
	}
	// Uncaptured: nothing in the flow store, no verdict sidecar.
	time.Sleep(200 * time.Millisecond)
	for _, flow := range hub.store.Query(Filter{}) {
		t.Fatalf("control-plane call captured: %+v", flow)
	}
	// Without the hook nothing is exempt: the same judge refuses.
	other := startHub(t, true)
	other.SetScopeJudge(&cannedJudge{byHost: map[string]hostDecision{
		"localhost": {action: ActionReview, holdOK: false,
			verdict: &ScopeVerdict{Action: ActionReview, Reason: "范围外", DefaultMissed: true},
			refusal: refusalFor("localhost")},
	}})
	resp3, err := attributedClient(t, other, "sess-strict", "tool-3").Get(localhost(target.URL) + "/x")
	if err != nil {
		t.Fatalf("out-of-range call: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden || !containsString(string(body3), "scope_rules_refused") {
		t.Fatalf("without the exemption the miss must refuse: %d %s", resp3.StatusCode, body3)
	}
}
