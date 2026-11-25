package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/core/scoperules"
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
	var arguments struct {
		Method string `json:"method"`
		URL    string `json:"url"`
		FlowID string `json:"flow_id"`
	}
	if json.Unmarshal(req.Call.GetArguments().GetData(), &arguments) != nil {
		return ScopeDecision{}
	}
	verdict, judged := scoperules.JudgeSession(req.Invocation.SessionID, arguments.Method, arguments.URL)
	if !judged {
		return ScopeDecision{}
	}
	scoperules.RecordVerdict(arguments.FlowID, verdict)
	if verdict.Action == scoperules.ActionRecord {
		return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason}
	}
	return ScopeDecision{Judged: true, Action: verdict.Action, RuleID: verdict.RuleID, Reason: verdict.Reason,
		Hold: func(context.Context) bool { return false }}
}

// attributedClient builds a client whose requests carry an egress correlation
// lease attributed to a session — the same path real tool calls take.
func attributedClient(t *testing.T, hub *ProxyHub, sessionID, callID string) *http.Client {
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
func plainClient(t *testing.T, hub *ProxyHub) *http.Client {
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
	for _, flow := range hub.store.Query(QueryOpts{}) {
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
