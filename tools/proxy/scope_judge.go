// The scope-judge seam (G2, 4zrcin docs/19 appendix A): the proxy exposes a
// judge interface and delegates each request's verdict to whoever implements
// it — in the fork's composition, the guardrail runtime's LLM judge. This
// file carries the seam wiring plus the 4z-specific support the proxy holds
// (control-plane exemption, argument extraction, refusal shaping), so the
// upstream files hub.go and mitm.go keep only the call lines.
package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	mitmproxy "github.com/chainreactors/utils/mitmproxy/proxy"
)

// httpRequestToolName is the synthetic tool name the scope judge's calls
// carry. It mirrors the value documented in exts/guardrail (the judge cannot
// be imported here without a cycle through agent/session).
const httpRequestToolName = "http.request"

// ---------------------------------------------------------------------------
// MitmCommand — top-level "mitm" command
// ---------------------------------------------------------------------------

type MitmCommand struct {
	store       *FlowStore
	hub         *Hub
	execCommand CommandExecutor
}

// judgeRequest runs the optional test-range judge on one attributed request.
//
// Only requests with a session attribution (a per-execution egress lease) are
// judged: unattributed traffic is the host's own plumbing, not the model's.
// The judge can hold the forwarding goroutine (review) or short-circuit the
// exchange with a synthetic 403 (block) by setting Flow.Response, which the
// mitmproxy engine treats as the final reply. The returned verdict travels on
// the capture state and is keyed by the store's canonical flow id once the
// flow completes, so the observe extension can attach it as the flow's
// TrafficVerdict sidecar.
func (a *captureAddon) judgeRequest(f *mitmproxy.Flow) (scoperules.Verdict, bool) {
	if a.hub == nil || a.hub.scopeJudge == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return scoperules.Verdict{}, false
	}
	if a.hub.controlPlaneExempt(f.Request.URL.Hostname()) {
		return scoperules.Verdict{}, false
	}
	correlation := a.hub.resolveCorrelation(correlationTokenOf(f))
	defer correlation.finish()
	if correlation.invocation.SessionID == "" {
		return scoperules.Verdict{}, false
	}
	call := &aop.ToolCall{Name: httpRequestToolName, Arguments: &aop.EncodedValue{Data: scopeRequestArguments(f)}}
	req := ScopeRequest{Invocation: correlation.invocation, Call: call, Operation: correlation.operation}
	// A CONNECT tunnel is judged on the fence's host form (fork patch 31):
	// the instance fence judges fully, the project fence cannot see a method
	// or path at tunnel setup, and in relay mode this pass/fail IS the fence —
	// an unmatched tunnel refuses instead of passing unjudged. Decrypted
	// inner requests carry the full judgment on their own.
	var decision ScopeDecision
	if strings.EqualFold(f.Request.Method, http.MethodConnect) {
		decision = a.hub.scopeJudge.JudgeScopeConnect(req)
	} else {
		decision = a.hub.scopeJudge.JudgeScopeRequest(req)
	}
	if !decision.Judged {
		return scoperules.Verdict{}, false
	}
	ctx := operation.ContextWithInvocation(context.Background(), correlation.invocation)
	// verdictOf keeps the judge's answer verbatim: the sidecar must carry every
	// field the judge set (default_missed, passive, shadow), not a projection
	// of the action alone. A nil verdict (a stub judge) reconstructs the old
	// three fields.
	verdict := verdictOf(decision)
	switch decision.Action {
	case scoperules.ActionReview:
		if decision.Hold != nil && decision.Hold(ctx) {
			return verdict, true // approved: forward untouched
		}
		f.Response = scopeRefusal(f.Request, decision)
	case scoperules.ActionBlock:
		f.Response = scopeRefusal(f.Request, decision)
	}
	return verdict, true
}

// verdictOf returns the decision's own verdict, or the historical three-field
// reconstruction when the judge did not carry one.
func verdictOf(decision ScopeDecision) scoperules.Verdict {
	if decision.Verdict != nil {
		return *decision.Verdict
	}
	return scoperules.Verdict{Action: decision.Action, RuleID: decision.RuleID, Reason: decision.Reason}
}

// passiveDest reports whether one Sec-Fetch-Dest value names a passive
// subresource a page pulls by itself (scripts, stylesheets, images, fonts).
// Navigations (document) and API calls (empty) are deliberate requests and
// stay judgeable; anything unrecognized is not passive.
func passiveDest(dest string) bool {
	switch strings.ToLower(strings.TrimSpace(dest)) {
	case "script", "style", "image", "font":
		return true
	}
	return false
}

// scopeRequestArguments builds the synthetic call's arguments: the request
// identity the control plane renders, the flow id the verdict sidecar keys on,
// and the passive hint (Sec-Fetch-Dest) the judge uses to let a page's own
// static subresources pass the allowlist fallback.
func scopeRequestArguments(f *mitmproxy.Flow) []byte {
	dest := ""
	if f.Request.Header != nil {
		dest = f.Request.Header.Get("Sec-Fetch-Dest")
	}
	payload, _ := json.Marshal(map[string]any{
		"method":  f.Request.Method,
		"url":     f.Request.URL.String(),
		"flow_id": f.Id.String(),
		"dest":    dest,
		"passive": passiveDest(dest),
	})
	return payload
}

// scopeRefusal is the synthetic reply a block (or refused review) produces.
// 403 with a small JSON body: the tool that issued the request sees an HTTP
// failure, not a transport error. The body states WHY, so a model reading its
// tool output can stop retrying on its own: pending marks the allowlist
// fallback (the host is out of range and queued for the operator's approval —
// repeating the request cannot admit it), and reason carries the judge's
// verdict prose.
func scopeRefusal(req *mitmproxy.Request, decision ScopeDecision) *mitmproxy.Response {
	pending := false
	if decision.Verdict != nil && decision.Verdict.DefaultMissed && decision.Action == scoperules.ActionReview {
		pending = true
	}
	body, _ := json.Marshal(map[string]any{
		"error":   "scope_rules_refused",
		"host":    req.URL.Host,
		"reason":  decision.Reason,
		"pending": pending,
	})
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	return &mitmproxy.Response{StatusCode: http.StatusForbidden, Header: header, Body: body}
}

// SetControlPlaneHost installs the control-plane host the proxy exempts from
// judging and capture. Safe before Start; read per request.
func (h *Hub) SetControlPlaneHost(host string) {
	if h == nil {
		return
	}
	h.controlPlaneMu.Lock()
	defer h.controlPlaneMu.Unlock()
	h.controlPlane = strings.ToLower(strings.TrimSpace(host))
}

// controlPlaneExempt reports whether the request host names the control
// plane. The fence is a statement about the target range; the executor's
// calls to its own control plane must always work, and capturing them would
// leak their Authorization headers into the traffic view. When the configured
// control plane itself lives on loopback, the whole loopback family counts as
// the platform — 127.0.0.1, localhost and ::1 are one machine's management
// plane spelled three ways.
func (h *Hub) controlPlaneExempt(host string) bool {
	if h == nil || host == "" {
		return false
	}
	h.controlPlaneMu.Lock()
	defer h.controlPlaneMu.Unlock()
	cp := h.controlPlane
	if cp == "" {
		return false
	}
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if strings.EqualFold(host, cp) {
		return true
	}
	if loopbackHost(cp) && loopbackHost(host) {
		return true
	}
	return false
}

// loopbackHost reports whether one host names the node's own loopback: the
// literal localhost, an address in 127.0.0.0/8, or ::1.
func loopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// SetScopeJudge installs the test-range judge. Safe before Start; judging
// reads it per request.
func (h *Hub) SetScopeJudge(judge ScopeJudge) {
	if h == nil {
		return
	}
	h.scopeJudge = judge
}
