// Package egressroutes is the fence extension's per-session egress table
// (4zrcin.EgressProxy, docs/19 E3-4): one dialer per agent session, written
// by the control plane's per-turn payload and read by the proxy hub when a
// tool call's egress lease resolves. It exists for the same reason
// exts/4zfence/scoperules does — two layers need to agree per session without
// importing each other, and the control plane re-sends the value every turn,
// so a bounded store of live sessions is enough. The fence extension owns the
// store (created at Load, cleared at Close): there is no package-level
// session state.
package egressroutes

import (
	"sync"

	"github.com/chainreactors/cyber/core/egress"
)

const maxSessionRoutes = 256

// Store owns the per-session route table.
type Store struct {
	routeMu    sync.Mutex
	routeDials map[string]egress.Dial
	routeRing  []string
}

// NewStore builds an empty store.
func NewStore() *Store {
	return &Store{routeDials: map[string]egress.Dial{}}
}

// Set binds one session's outbound traffic to dial. An invalid or refused
// dial must never be stored: callers clear the route instead, and a nil dial
// here is a no-op rather than a poison value.
func (s *Store) Set(sessionID string, dial egress.Dial) {
	if sessionID == "" || dial == nil {
		return
	}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	if _, exists := s.routeDials[sessionID]; !exists {
		s.routeRing = append(s.routeRing, sessionID)
		if len(s.routeRing) > maxSessionRoutes {
			delete(s.routeDials, s.routeRing[0])
			s.routeRing = s.routeRing[1:]
		}
	}
	s.routeDials[sessionID] = dial
}

// Clear removes a session's binding: the endpoint was disabled or the session
// closed. Unbinding is safe on an unknown session.
func (s *Store) Clear(sessionID string) {
	if sessionID == "" {
		return
	}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	if _, exists := s.routeDials[sessionID]; !exists {
		return
	}
	delete(s.routeDials, sessionID)
	for i, id := range s.routeRing {
		if id == sessionID {
			s.routeRing = append(s.routeRing[:i], s.routeRing[i+1:]...)
			break
		}
	}
}

// Lookup returns the session's dialer, or nil when unbound. The caller falls
// back to its own default chain on nil — a control plane that never sends the
// extension leaves every session exactly as before.
func (s *Store) Lookup(sessionID string) egress.Dial {
	if sessionID == "" {
		return nil
	}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	return s.routeDials[sessionID]
}

// ClearAll forgets every binding: Close clears, so no route outlives the
// extension that owned the store.
func (s *Store) ClearAll() {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.routeDials = map[string]egress.Dial{}
	s.routeRing = nil
}
