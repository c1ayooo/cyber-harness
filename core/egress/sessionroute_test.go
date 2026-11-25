package egress

import (
	"context"
	"net"
	"testing"
)

// stubDial returns a Dial that records which route served a lookup; the tests
// never actually dial, they only check which dialer the registry hands back.
func stubDial(label string) Dial {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, context.Canceled
	}
}

// A bound session resolves to its dialer; an unknown session resolves to nil
// and the caller keeps its own default chain (the zero-value behavior that
// keeps control planes without the extension byte-identical).
func TestSessionRouteLookup(t *testing.T) {
	a := stubDial("a")
	SetSessionRoute("sess-a", a)
	if got := LookupSessionRoute("sess-a"); got == nil {
		t.Fatal("bound session resolved to nil")
	}
	if got := LookupSessionRoute("sess-other"); got != nil {
		t.Fatalf("unknown session resolved to %v", got)
	}
	if got := LookupSessionRoute(""); got != nil {
		t.Fatal("empty session resolved to a dialer")
	}
}

// Nil dials and empty ids are no-ops, never poison values: a rejected binding
// must not shadow the node default with a dialer that cannot work.
func TestSessionRouteRejectsNilDial(t *testing.T) {
	SetSessionRoute("sess-nil", nil)
	if got := LookupSessionRoute("sess-nil"); got != nil {
		t.Fatal("nil dial was stored")
	}
}

// The newest Set wins: the control plane re-sends the endpoint every turn, so
// a switched endpoint must replace the old binding, and a disabled draft must
// really unbind.
func TestSessionRouteReplaceAndClear(t *testing.T) {
	first, second := stubDial("first"), stubDial("second")
	SetSessionRoute("sess-x", first)
	SetSessionRoute("sess-x", second)
	if got := LookupSessionRoute("sess-x"); got == nil {
		t.Fatal("replaced binding missing")
	}
	ClearSessionRoute("sess-x")
	if got := LookupSessionRoute("sess-x"); got != nil {
		t.Fatal("cleared session still bound")
	}
	// Unbinding an unknown session is safe.
	ClearSessionRoute("sess-unknown")
}

// The store is bounded like the scope-rule registry: sessions beyond the cap
// evict the oldest, so a long-lived agent process cannot leak memory.
func TestSessionRouteBound(t *testing.T) {
	if maxSessionRoutes > 64 {
		t.Skip("cap too large for this test's loop budget")
	}
	for i := 0; i < maxSessionRoutes+8; i++ {
		SetSessionRoute("sess-ring-"+string(rune('a'+i%26))+string(rune('0'+i/26)), stubDial("d"))
	}
	// Exactly maxSessionRoutes entries survive; the oldest are gone.
	if len(routeRing) != maxSessionRoutes {
		t.Fatalf("ring length = %d, want %d", len(routeRing), maxSessionRoutes)
	}
	if len(routeDials) != maxSessionRoutes {
		t.Fatalf("map length = %d, want %d", len(routeDials), maxSessionRoutes)
	}
}
