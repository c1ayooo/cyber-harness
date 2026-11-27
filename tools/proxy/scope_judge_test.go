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

	"github.com/c1ayooo/cyber/core/operation"
	"github.com/c1ayooo/cyber/core/scoperules"
)

// stubScopeJudge is the minimal judge the proxy integration tests use: it
// mirrors the contract the guardrail runtime implements (judge by session set,
// record the verdict for the sidecar, hold reviews until refused) without
// importing that package — an in-package test of proxy cannot import a package
// that imports proxy.
type stubScopeJudge struct{}

func (stubScopeJudge) JudgeScopeRequest(req ScopeRequest) ScopeDecision {
	if req.Invocation.SessionID == "" || req.Call == nil {
		return ScopeDecision{}
	}
	arguments, flowID, ok := scopeCallArguments(req)
	if !ok {
		return ScopeDecision{}
	}
	verdict, judged := scoperules.JudgeSession(req.Invocation.SessionID, arguments.Method, arguments.URL)
	if !judged {
		return ScopeDecision{}
	}
	scoperules.RecordVerdict(flowID, verdict)
	if verdict.Action == scoperules.ActionRecord {
		return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason, Verdict: &verdict}
	}
	return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Hold: func(context.Context) bool { return false }}
}

// JudgeScopeConnect mirrors the real judge's tunnel path: host-form project rules
// via JudgeSessionConnect, with the same quiet-refusal for a default miss.
func (stubScopeJudge) JudgeScopeConnect(req ScopeRequest) ScopeDecision {
	if req.Invocation.SessionID == "" || req.Call == nil {
		return ScopeDecision{}
	}
	arguments, flowID, ok := scopeCallArguments(req)
	if !ok {
		return ScopeDecision{}
	}
	verdict, judged := scoperules.JudgeSessionConnect(req.Invocation.SessionID, arguments.URL)
	if !judged {
		return ScopeDecision{}
	}
	scoperules.RecordVerdict(flowID, verdict)
	if verdict.Action == scoperules.ActionRecord {
		return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason, Verdict: &verdict}
	}
	return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Verdict: &verdict, Hold: func(context.Context) bool { return false }}
}

func scopeCallArguments(req ScopeRequest) (arguments struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	FlowID string `json:"flow_id"`
}, flowID string, ok bool) {
	if json.Unmarshal(req.Call.GetArguments().GetData(), &arguments) != nil {
		return arguments, "", false
	}
	return arguments, arguments.FlowID, true
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

const judgeRules = `{"enabled":true,"default_action":"record","rules":[{"id":"sr-1","action":"block","method":"*","host":"blocked.test"}]}`

// TestScopeJudgeBlocksRequest verifies the full block path: the synthetic 403
// is what the tool sees, the target never receives the request, the refusal is
// captured as a flow, and the verdict lands in the sidecar registry.
func TestScopeJudgeBlocksRequest(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(stubScopeJudge{})
	if err := scoperules.SetRules("sess-x", []byte(judgeRules)); err != nil {
		t.Fatal(err)
	}

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
	verdict, ok := scoperules.TakeVerdict(flows[0].GetId())
	if !ok || verdict.Action != scoperules.ActionBlock || verdict.RuleID != "sr-1" {
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
	hub.SetScopeJudge(stubScopeJudge{})
	if err := scoperules.SetRules("sess-x", []byte(judgeRules)); err != nil {
		t.Fatal(err)
	}

	getThrough(t, attributedClient(t, hub, "sess-x", "tool-1"), target.URL)
	flows := waitForFlows(t, hub.store, 1)
	if len(flows) == 0 || flows[0].GetResponse().GetStatusCode() != http.StatusOK {
		t.Fatalf("recorded flow = %+v", flows)
	}
	if verdict, ok := scoperules.TakeVerdict(flows[0].GetId()); !ok || verdict.Action != scoperules.ActionRecord {
		t.Fatalf("sidecar verdict = %+v ok=%v", verdict, ok)
	}

	// Unattributed traffic is the host's own plumbing: never judged, even on a
	// host a rule would block.
	getThrough(t, plainClient(t, hub), "http://blocked.test/")
	time.Sleep(100 * time.Millisecond)
	for _, flow := range hub.store.Query(Filter{}) {
		if verdict, ok := scoperules.TakeVerdict(flow.GetId()); ok {
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
	hub := startHub(t, true)
	hub.SetScopeJudge(stubScopeJudge{})
	if err := scoperules.SetRules("sess-miss", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
	resp, err := attributedClient(t, hub, "sess-miss", "tool-1").Get("http://outside.test/app.js")
	if err != nil {
		t.Fatalf("request through hub: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want the quiet 403 refusal", resp.StatusCode)
	}
	flows := waitForFlows(t, hub.store, 1)
	verdict, ok := scoperules.TakeVerdict(flows[0].GetId())
	if !ok || verdict.Action != scoperules.ActionReview || !verdict.DefaultMissed {
		t.Fatalf("sidecar verdict = %+v ok=%v (default_missed lost)", verdict, ok)
	}
	// The refusal body explains itself: the model reading its tool output can
	// stop retrying without a round trip (fork patch 34).
	var said struct {
		Error   string `json:"error"`
		Host    string `json:"host"`
		Reason  string `json:"reason"`
		Pending bool   `json:"pending"`
	}
	if json.Unmarshal(body, &said) != nil || said.Error != "scope_rules_refused" || said.Host != "outside.test" || !said.Pending || said.Reason == "" {
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
	hub.SetScopeJudge(bareScopeJudge{})
	if err := scoperules.SetRules("sess-bare", []byte(judgeRules)); err != nil {
		t.Fatal(err)
	}
	getThrough(t, attributedClient(t, hub, "sess-bare", "tool-1"), target.URL)
	flows := waitForFlows(t, hub.store, 1)
	verdict, ok := scoperules.TakeVerdict(flows[0].GetId())
	// The request misses every row and lands on the record default; the
	// reconstruction keeps action/reason but invents no flags.
	if !ok || verdict.Action != scoperules.ActionRecord || verdict.RuleID != "" || verdict.DefaultMissed || verdict.Passive {
		t.Fatalf("reconstructed verdict = %+v ok=%v", verdict, ok)
	}
}

// bareScopeJudge answers from the action alone, like a judge predating the
// verbatim verdict field.
type bareScopeJudge struct{}

func (bareScopeJudge) JudgeScopeRequest(req ScopeRequest) ScopeDecision {
	if req.Invocation.SessionID == "" || req.Call == nil {
		return ScopeDecision{}
	}
	arguments, _, ok := scopeCallArguments(req)
	if !ok {
		return ScopeDecision{}
	}
	verdict, judged := scoperules.JudgeSession(req.Invocation.SessionID, arguments.Method, arguments.URL)
	if !judged {
		return ScopeDecision{}
	}
	return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason}
}

func (bareScopeJudge) JudgeScopeConnect(req ScopeRequest) ScopeDecision {
	return ScopeDecision{}
}

// The control plane is the executor's own management plane (fork patch 36):
// a bookkeeping call to it is forwarded unjudged and uncaptured, even when
// the allowlist fence does not name the host. Before the skip, every such
// call was held for review — the operator approved one call per step.
func TestScopeJudgeControlPlaneIsPlatformPlumbing(t *testing.T) {
	target := startTestTarget(64)
	defer target.Close()

	hub := startHub(t, true)
	hub.SetScopeJudge(stubScopeJudge{})
	// The test target lives on 127.0.0.1; naming that host as the control
	// plane exempts it — exactly the deployment shape this patch serves (the
	// executor's API base and the scan share the node).
	hub.SetControlPlaneHost("127.0.0.1")
	// The allowlist names one host; the target is deliberately NOT on it.
	if err := scoperules.SetRules("sess-loop", []byte(`{"enabled":true,"default_action":"review","rules":[{"id":"sr-ok","action":"record","method":"*","host":"in-range.test","path_prefix":"/"}]}`)); err != nil {
		t.Fatal(err)
	}
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
	// A different session whose control plane is elsewhere still judges this
	// host: the exemption is the node's own plumbing, not the address.
	other := startHub(t, true)
	other.SetScopeJudge(stubScopeJudge{})
	if err := scoperules.SetRules("sess-strict", []byte(`{"enabled":true,"default_action":"review","rules":[]}`)); err != nil {
		t.Fatal(err)
	}
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
