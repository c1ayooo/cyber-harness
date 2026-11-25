package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/operation"
	"github.com/chainreactors/proxyclient"
)

// recordingDial returns a Dial that dials the target directly and counts its
// invocations: the hub's session-route path is proven by the counter, without
// needing a real upstream proxy process.
func recordingDial(hits *atomic.Int32) egress.Dial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

// A session the control plane bound to a project proxy dials through that
// endpoint (here: a recording dialer), while a session without a binding keeps
// the node default. Same hub, same target, independent sessions.
func TestSessionRouteOverridesDefaultChain(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	var routed atomic.Int32
	egress.SetSessionRoute("sess-routed", recordingDial(&routed))
	t.Cleanup(func() { egress.ClearSessionRoute("sess-routed") })

	getThrough(t, attributedClient(t, hub, "sess-routed", "tool-1"), target.URL)
	if routed.Load() != 1 {
		t.Fatalf("session route used %d times, want 1", routed.Load())
	}

	// The unbound session never touches the route: it goes through State's
	// default chain (direct here), and the route counter stays at 1.
	getThrough(t, attributedClient(t, hub, "sess-other", "tool-2"), target.URL)
	if routed.Load() != 1 {
		t.Fatalf("unbound session used the route: %d hits", routed.Load())
	}
}

// Clearing the binding switches the session back to the default chain at its
// next turn: exactly how a disabled draft must behave for a session that
// outlives the save.
func TestSessionRouteClearReturnsToDefault(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	var routed atomic.Int32
	egress.SetSessionRoute("sess-clear", recordingDial(&routed))
	getThrough(t, attributedClient(t, hub, "sess-clear", "tool-1"), target.URL)
	if routed.Load() != 1 {
		t.Fatalf("bound request skipped the route: %d hits", routed.Load())
	}

	egress.ClearSessionRoute("sess-clear")
	getThrough(t, attributedClient(t, hub, "sess-clear", "tool-2"), target.URL)
	if routed.Load() != 1 {
		t.Fatalf("cleared session still routed: %d hits", routed.Load())
	}
}

// The per-call passthrough (`proxy <url> <cmd>`) still wins over the session
// route: an explicit dial the caller asked for is not silently replaced by a
// project-level binding.
func TestPassthroughDialWinsOverSessionRoute(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	hub := startHub(t, true)
	var sessionHits, passthroughHits atomic.Int32
	egress.SetSessionRoute("sess-pt", recordingDial(&sessionHits))
	t.Cleanup(func() { egress.ClearSessionRoute("sess-pt") })

	// Same session, but the call carries its own dial: the passthrough
	// dialer must serve the real request, the session route must not.
	ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{SessionID: "sess-pt", CallID: "tool-3"})
	proxyURL, _, release := hub.egress(ctx, passthroughDialFor(&passthroughHits))
	t.Cleanup(release)
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true}, Timeout: 5 * time.Second}
	getThrough(t, client, target.URL)
	if sessionHits.Load() != 0 {
		t.Fatalf("passthrough call fell back to the session route: %d hits", sessionHits.Load())
	}
	if passthroughHits.Load() != 1 {
		t.Fatalf("passthrough dial used %d times, want 1", passthroughHits.Load())
	}
}

// passthroughDialFor builds the explicit dial a passthrough call carries; it
// dials directly and counts, mirroring recordingDial for the session route.
func passthroughDialFor(hits *atomic.Int32) proxyclient.Dial {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}
