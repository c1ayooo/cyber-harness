// Package fence is the 4zfence building block (4zrcin docs/19 P1-4): the
// instance fence, the project scope rules, and the egress binding — the
// control plane's per-turn policy payloads, their registration tables (the
// scoperules and globalfence subpackages), and the session-lifecycle hooks
// that keep the tables to live sessions. The proxy judges against what this
// registers; the agent runtime itself carries none of it.
//
// The extension subscribes the runtime's SessionStart/SessionEnd hooks: a
// child session inherits its parent's registrations on open (FailClosed — an
// inheritance failure fails the open), and every close drops them, freeing
// capacity for the next session (fork fix P1-0). The proxy's judge seam (G2)
// reads the tables; the composition wires the turn decorators through
// TurnDecorators, so a composition that omits 4zfence simply never fences.
package fence

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sync"

	"github.com/chainreactors/proxyclient"

	agenthooks "github.com/chainreactors/cyber/agent/hooks"
	agentsession "github.com/chainreactors/cyber/agent/session"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"github.com/chainreactors/cyber/core/egress"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
)

// Extension keeps the fence tables to live sessions via the session hooks,
// and owns the fence's tool admission (the guaranteed audit and the instance
// red lines, admission.go).
type Extension struct {
	mu        sync.Mutex
	subs      []*hooks.Subscription
	stream    *events.Stream
	guardrail *guardrailext.Runtime
}

var _ extension.Extension = (*Extension)(nil)

// New builds the fence extension.
func New() *Extension { return &Extension{} }

// Load subscribes the session-lifecycle hooks.
func (e *Extension) Load(scope *extension.Scope) error {
	if err := scope.Init().Err(); err != nil {
		return err
	}
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	// The fence admission must subscribe before the guardrail extension, so
	// a red line denies before any policy concern; the composition orders the
	// entries and binds the guardrail runtime afterwards (Bind).
	const source = "4zfence"
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stream = stream
	if err := extension.Provide[*Extension](scope, e); err != nil {
		return err
	}
	e.subs = append(e.subs,
		toolhooks.Before.On(registry, source, e.admit),
		agenthooks.SessionStart.On(registry, source, inheritOnOpen),
		agenthooks.SessionEnd.On(registry, source, dropOnClose),
	)
	return nil
}

// Close releases the hook subscriptions.
func (e *Extension) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, sub := range e.subs {
		sub.Close(context.Background())
	}
	e.subs = nil
	return nil
}

// TurnDecorators returns the fence's turn decorators in application order:
// the scope rules and the instance fence register first (the proxy judges
// this turn's requests against them), then the egress binding.
func TurnDecorators() []agentsession.RunTurnDecorator {
	return []agentsession.RunTurnDecorator{fenceRulesDecorator, egressProxyDecorator}
}

// inheritOnOpen copies the parent's fence registrations to the child session
// at open time. The SessionStart hook is FailClosed, so an inheritance failure
// (a full table) fails the open instead of starting the child unfenced; a
// root session (no parent) inherits nothing.
func inheritOnOpen(_ context.Context, ev agenthooks.SessionEvent) (struct{}, error) {
	if ev.ParentID == "" {
		return struct{}{}, nil
	}
	if err := scoperules.InheritSessionRules(ev.ParentID, ev.SessionID); err != nil {
		return struct{}{}, err
	}
	if err := globalfence.InheritSessionRules(ev.ParentID, ev.SessionID); err != nil {
		return struct{}{}, err
	}
	return struct{}{}, nil
}

// dropOnClose drops the session's fence registrations and its project proxy
// binding when the session closes, so the tables hold only live sessions and
// capacity is never exhausted by stale ids (fork fix P1-0). Unknown ids are a
// no-op.
func dropOnClose(_ context.Context, ev agenthooks.SessionEvent) (struct{}, error) {
	egress.ClearSessionRoute(ev.SessionID)
	scoperules.DropSession(ev.SessionID)
	globalfence.DropSession(ev.SessionID)
	return struct{}{}, nil
}

// fenceRulesDecorator registers the project scope rules and the instance
// fence for the turn's session. A full table rejects the turn: an unfenced
// run is never acceptable.
func fenceRulesDecorator(req *aop.RunTurnRequest, _ *agentsession.RunInput) error {
	if err := turnScopeRules(req); err != nil {
		return err
	}
	return turnGlobalFence(req)
}

// egressProxyDecorator binds the session's outbound calls to the project
// proxy the manifest held at dispatch time.
func egressProxyDecorator(req *aop.RunTurnRequest, _ *agentsession.RunInput) error {
	turnEgressProxy(req)
	return nil
}

// turnScopeRules registers the test-range rule set a control plane attached to
// this turn. The set rides every turn (disabled drafts included) so the proxy
// judges each request against what the project manifest held when the run
// dispatched — never a stale push-once copy. An invalid payload is logged and
// ignored (the previous set stays in force); a full table is returned as
// ErrCapacity — the caller must reject the turn, because a skipped
// registration would run it unfenced.
func turnScopeRules(req *aop.RunTurnRequest) error {
	if req == nil {
		return nil
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.ScopeRulesURLs)
	if extension == nil {
		return nil
	}
	if err := scoperules.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
		if errors.Is(err, scoperules.ErrCapacity) {
			return fmt.Errorf("scope rules: %w", err)
		}
		log.Printf("aop: ignore invalid scope rules for session %s: %v", req.GetSessionId(), err)
	}
	return nil
}

// turnGlobalFence registers the instance fence for this turn's session. An
// invalid payload is logged and ignored; the previous set stays in force
// rather than opening a hole on one malformed send. A full table is returned
// as ErrCapacity — the caller must reject the turn, because a skipped
// registration would run it unfenced.
func turnGlobalFence(req *aop.RunTurnRequest) error {
	if req == nil {
		return nil
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.GlobalFenceURLs)
	if extension == nil {
		return nil
	}
	if err := globalfence.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
		if errors.Is(err, globalfence.ErrCapacity) {
			return fmt.Errorf("global fence: %w", err)
		}
		log.Printf("aop: ignore invalid global fence for session %s: %v", req.GetSessionId(), err)
	}
	return nil
}

// turnEgressProxy binds this turn's session to the project proxy a control
// plane attached. The binding rides every turn — a disabled draft included —
// so a session that outlives the save learns the endpoint was switched off
// and falls back to the node default. Registration lives in core/egress (same
// pattern as scoperules): the session layer writes, the proxy hub reads, and
// neither imports the other.
//
// NewClient needs the extra protocol factories (trojan/vmess/hysteria2/anytls/
// clash) registered; those blank imports live in tools/proxy, which every
// agent binary links, so the factories are in the registry by the time a turn
// with such an endpoint arrives.
func turnEgressProxy(req *aop.RunTurnRequest) {
	if req == nil {
		return
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.EgressProxyURLs)
	if extension == nil {
		return
	}
	sessionID := req.GetSessionId()
	payload, ok := payloads.ParseEgressProxy(extension)
	if !ok {
		log.Printf("aop: ignore invalid egress proxy for session %s", sessionID)
		egress.ClearSessionRoute(sessionID)
		return
	}
	// Disabled is a stored state the operator kept, not a deletion: clearing
	// the route is exactly how "off" reaches a session that is already live.
	if !payload.Enabled {
		egress.ClearSessionRoute(sessionID)
		return
	}
	raw := payload.URL
	if raw == "" {
		// Legacy control planes without the url field: derive from the fields.
		host := payload.Host
		if payload.Port > 0 {
			host = fmt.Sprintf("%s:%d", host, payload.Port)
		}
		u := &url.URL{Scheme: payload.Scheme, Host: host}
		if payload.Username != "" {
			if payload.Password != "" {
				u.User = url.UserPassword(payload.Username, payload.Password)
			} else {
				u.User = url.User(payload.Username)
			}
		}
		raw = u.String()
	}
	endpoint, err := url.Parse(raw)
	if err != nil {
		log.Printf("aop: ignore invalid egress proxy url for session %s: %v", sessionID, err)
		egress.ClearSessionRoute(sessionID)
		return
	}
	dial, err := proxyclient.NewClient(endpoint)
	if err != nil {
		log.Printf("aop: ignore undialable egress proxy for session %s: %v", sessionID, err)
		egress.ClearSessionRoute(sessionID)
		return
	}
	egress.SetSessionRoute(sessionID, egress.Dial(dial))
}
