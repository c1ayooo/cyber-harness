package egress

import (
	"context"
	"net"
	"sync"
)

// Dial is one outbound dialer. It mirrors proxyclient.Dial structurally so
// neither side of the registry must import the other: agent/session converts
// a proxyclient.Dial into this type when registering, and the proxy hub
// converts it back when dialing. A capability without proxyclient linked
// (core is dependency-light by design) can still hold and hand off the value.
type Dial func(ctx context.Context, network, address string) (net.Conn, error)

// The session-route registry: one dialer per agent session, written by the
// session layer (the control plane's per-turn 4zrcin.EgressProxy extension)
// and read by the proxy hub when a tool call's egress lease resolves. It
// exists for the same reason core/scoperules does — two layers need to agree
// per session without importing each other, and the control plane re-sends
// the value every turn, so a bounded store of live sessions is enough.

const maxSessionRoutes = 256

var (
	routeMu    sync.Mutex
	routeDials = map[string]Dial{}
	routeRing  []string
)

// SetSessionRoute binds one session's outbound traffic to dial. An invalid or
// refused dial must never be stored: callers clear the route instead, and a
// nil dial here is a no-op rather than a poison value.
func SetSessionRoute(sessionID string, dial Dial) {
	if sessionID == "" || dial == nil {
		return
	}
	routeMu.Lock()
	defer routeMu.Unlock()
	if _, exists := routeDials[sessionID]; !exists {
		routeRing = append(routeRing, sessionID)
		if len(routeRing) > maxSessionRoutes {
			delete(routeDials, routeRing[0])
			routeRing = routeRing[1:]
		}
	}
	routeDials[sessionID] = dial
}

// ClearSessionRoute removes a session's binding: the endpoint was disabled or
// the session closed. Unbinding is safe on an unknown session.
func ClearSessionRoute(sessionID string) {
	if sessionID == "" {
		return
	}
	routeMu.Lock()
	defer routeMu.Unlock()
	if _, exists := routeDials[sessionID]; !exists {
		return
	}
	delete(routeDials, sessionID)
	for i, id := range routeRing {
		if id == sessionID {
			routeRing = append(routeRing[:i], routeRing[i+1:]...)
			break
		}
	}
}

// LookupSessionRoute returns the session's dialer, or nil when unbound. The
// caller falls back to its own default chain on nil — a control plane that
// never sends the extension leaves every session exactly as before.
func LookupSessionRoute(sessionID string) Dial {
	if sessionID == "" {
		return nil
	}
	routeMu.Lock()
	defer routeMu.Unlock()
	return routeDials[sessionID]
}
