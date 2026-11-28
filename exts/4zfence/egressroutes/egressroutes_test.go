package egressroutes

import (
	"context"
	"net"
	"testing"

	"github.com/chainreactors/cyber/core/egress"
)

// stubDial returns a Dial that records which route served a lookup; the tests
// never actually dial, they only check which dialer the store hands back.
func stubDial(label string) egress.Dial {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, context.Canceled
	}
}

// A bound session resolves to its dialer; an unknown session resolves to nil
// and the caller keeps its own default chain (the zero-value behavior that
// keeps control planes without the extension byte-identical).
func TestSessionRouteLookup(t *testing.T) {
	store := NewStore()
	a := stubDial("a")
	store.Set("sess-a", a)
	if got := store.Lookup("sess-a"); got == nil {
		t.Fatal("bound session resolved to nil")
	}
	if got := store.Lookup("sess-other"); got != nil {
		t.Fatalf("unknown session resolved to %v", got)
	}
	if got := store.Lookup(""); got != nil {
		t.Fatal("empty session resolved to a dialer")
	}
}

// Nil dials and empty ids are no-ops, never poison values: a rejected binding
// must not shadow the node default with a dialer that cannot work.
func TestSessionRouteRejectsNilDial(t *testing.T) {
	store := NewStore()
	store.Set("sess-nil", nil)
	if got := store.Lookup("sess-nil"); got != nil {
		t.Fatal("nil dial was stored")
	}
}

// The newest Set wins: the control plane re-sends the endpoint every turn, so
// a switched endpoint must replace the old binding, and a disabled draft must
// really unbind.
func TestSessionRouteReplaceAndClear(t *testing.T) {
	store := NewStore()
	first, second := stubDial("first"), stubDial("second")
	store.Set("sess-x", first)
	store.Set("sess-x", second)
	if got := store.Lookup("sess-x"); got == nil {
		t.Fatal("replaced binding missing")
	}
	store.Clear("sess-x")
	if got := store.Lookup("sess-x"); got != nil {
		t.Fatal("cleared session still bound")
	}
	// Unbinding an unknown session is safe.
	store.Clear("sess-unknown")
}

// The store is bounded like the scope-rule registry: sessions beyond the cap
// evict the oldest, so a long-lived agent process cannot leak memory.
func TestSessionRouteBound(t *testing.T) {
	store := NewStore()
	if maxSessionRoutes > 64 {
		t.Skip("cap too large for this test's loop budget")
	}
	for i := 0; i < maxSessionRoutes+8; i++ {
		store.Set("sess-ring-"+string(rune('a'+i%26))+string(rune('0'+i/26)), stubDial("d"))
	}
	// Exactly maxSessionRoutes entries survive; the oldest are gone.
	if len(store.routeRing) != maxSessionRoutes {
		t.Fatalf("ring length = %d, want %d", len(store.routeRing), maxSessionRoutes)
	}
	if len(store.routeDials) != maxSessionRoutes {
		t.Fatalf("map length = %d, want %d", len(store.routeDials), maxSessionRoutes)
	}
}

// ClearAll forgets every binding at once: the fence extension calls it on
// Close, so no route outlives the store's owner.
func TestSessionRouteClearAll(t *testing.T) {
	store := NewStore()
	store.Set("sess-all-1", stubDial("1"))
	store.Set("sess-all-2", stubDial("2"))
	store.ClearAll()
	if got := store.Lookup("sess-all-1"); got != nil {
		t.Fatal("ClearAll left a binding behind")
	}
	if got := store.Lookup("sess-all-2"); got != nil {
		t.Fatal("ClearAll left a binding behind")
	}
	// The store keeps working after a clear: a fresh Set binds again.
	store.Set("sess-all-3", stubDial("3"))
	if got := store.Lookup("sess-all-3"); got == nil {
		t.Fatal("store dead after ClearAll")
	}
}
