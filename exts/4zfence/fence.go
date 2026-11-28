// Package fence is the 4zfence building block (4zrcin docs/19 P1-4): the
// instance fence, the project scope rules, and the egress binding — the
// control plane's per-turn policy payloads, their registration tables (the
// scoperules, globalfence and egressroutes subpackages), and the
// session-lifecycle hooks that keep the tables to live sessions. The proxy
// judges against what this registers; the agent runtime itself carries none
// of it.
//
// The extension subscribes the runtime's SessionStart/SessionEnd hooks: a
// child session inherits its parent's registrations on open (FailClosed — an
// inheritance failure fails the open), and every close drops them, freeing
// capacity for the next session (fork fix P1-0). The proxy's judge seam (G2)
// reads the tables; the composition wires the turn decorators through
// TurnDecorators, so a composition that omits 4zfence simply never fences.
package fence

import fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"

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
	"github.com/chainreactors/cyber/core/resource"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"

	"github.com/chainreactors/cyber/exts/4zfence/egressroutes"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"github.com/chainreactors/cyber/exts/4zfence/policy"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

// Extension keeps the fence tables to live sessions via the session hooks,
// and owns the fence's tool admission (the guaranteed audit and the instance
// red lines, admission.go).
type Extension struct {
	mu        sync.Mutex
	subs      []*hooks.Subscription
	stream    *events.Stream
	guardrail *guardrailext.Runtime
	// The judge (docs/19 E3-3): the fence section's knobs and the policy they
	// select; policy is nil for provider none.
	fence    fenceconfig.Config
	jevRules guardrailext.Rules
	policy   policy.Policy
	options  judgeOptions
	// The tables (docs/19 E3-4): extension-owned stores, created at Load,
	// provided for consumers that can borrow, and reached by the fence's own
	// entry points — the turn decorators, the session hooks and the scope
	// judge — through stores(). Close clears them.
	scopes  *scoperules.Store
	globals *globalfence.Store
	routes  *egressroutes.Store

	// The auto-mode repeated-rejection backoff state (upstream keeps the same
	// map on its runtime): bounded diagnostic counters, never decisions.
	rejectionsMu sync.Mutex
	rejections   map[[32]byte]int
}

var _ extension.Extension = (*Extension)(nil)

// New builds the fence extension. cfg is the fence section (the judge's
// knobs); jevRules is the guardrail section's own `jev` block, which the
// JEV stage of a jev or hybrid judge screens with — the approval queue and
// the fence read the same operator config.
func New(cfg fenceconfig.Config, jevRules guardrailext.Rules) *Extension {
	return &Extension{fence: cfg.Defaults(), jevRules: jevRules}
}

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
	// The judge is built at load time: the provider comes from the fence
	// section, and a jev or hybrid stage borrows the shared JEV client (only
	// then is the client required — provider none and llm never need it).
	policy, err := e.buildPolicy(scope, stream)
	if err != nil {
		return err
	}
	e.policy = policy
	e.options = newJudgeOptions(e.fence)
	// The session tables live in this extension's stores (docs/19 E3-4): they
	// are created here, cleared at Close, and never outlive the extension
	// that owns them. The Provide is the contribution point for consumers
	// that can borrow them.
	e.scopes = scoperules.NewStore()
	e.globals = globalfence.NewStore()
	e.routes = egressroutes.NewStore()
	if err := extension.Provide[*scoperules.Store](scope, e.scopes); err != nil {
		return err
	}
	if err := extension.Provide[*globalfence.Store](scope, e.globals); err != nil {
		return err
	}
	if err := extension.Provide[*egressroutes.Store](scope, e.routes); err != nil {
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
		agenthooks.SessionStart.On(registry, source, e.inheritOnOpen),
		agenthooks.SessionEnd.On(registry, source, e.dropOnClose),
	)
	return nil
}

// Close releases the hook subscriptions and clears the stores: no session's
// rules or parked sets survive the extension that owned them (docs/19 E3-4).
func (e *Extension) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, sub := range e.subs {
		sub.Close(context.Background())
	}
	e.subs = nil
	if e.scopes != nil {
		e.scopes.Clear()
	}
	if e.globals != nil {
		e.globals.Clear()
	}
	if e.routes != nil {
		e.routes.ClearAll()
	}
	e.scopes, e.globals, e.routes = nil, nil, nil
	return nil
}

// stores returns the session tables. All are nil before Load and after
// Close: the fence then judges nothing, and an entry point that has to
// register reports ErrNotLoaded instead of letting the registration go
// nowhere.
func (e *Extension) stores() (*scoperules.Store, *globalfence.Store, *egressroutes.Store) {
	if e == nil {
		return nil, nil, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scopes, e.globals, e.routes
}

// SessionRoutes returns the per-session egress lookup the proxy hub reads:
// the fence's own route table, resolved at call time (the composition wires
// this before Load, like the scope judge). Every lookup yields nil while the
// extension holds no table — before Load and after Close — so the hub walks
// the node default chain, exactly its answer to "no route for this session".
func (e *Extension) SessionRoutes() func(sessionID string) egress.Dial {
	if e == nil {
		return nil
	}
	return func(sessionID string) egress.Dial {
		_, _, routes := e.stores()
		if routes == nil {
			return nil
		}
		return routes.Lookup(sessionID)
	}
}

// ErrNotLoaded is returned by the entry points that must register or copy
// rules when the extension holds no store: a registration that silently went
// nowhere would run the session unfenced.
var ErrNotLoaded = errors.New("fence extension is not loaded: no session tables to register with")

// Declare registers the fence's configuration section (the judge knobs;
// docs/19 已决 15). The section's struct and validation are fenceconfig's —
// the shell's settings writer shares them through the engine module.
func Declare(resources *resource.Registry) error {
	_, err := resource.Add[cfg.Section](resources, cfg.Section{
		Key:      fenceconfig.ConfigKey,
		New:      func() any { return &fenceconfig.Config{} },
		Secrets:  []string{"llm.api_key"},
		Validate: func(v any) error { return v.(*fenceconfig.Config).Validate() },
	})
	return err
}

// TurnDecorators returns the fence's turn decorators in application order:
// the scope rules and the instance fence register first (the proxy judges
// this turn's requests against them), then the egress binding. They are bound
// to this extension, so they register with its own tables (docs/19 E3-4).
func (e *Extension) TurnDecorators() []agentsession.RunTurnDecorator {
	return []agentsession.RunTurnDecorator{e.fenceRulesDecorator, e.egressProxyDecorator}
}

// inheritOnOpen copies the parent's fence registrations to the child session
// at open time. The SessionStart hook is FailClosed, so an inheritance failure
// (a full table, or no tables because the extension is not loaded) fails the
// open instead of starting the child unfenced; a root session (no parent)
// inherits nothing.
func (e *Extension) inheritOnOpen(_ context.Context, ev agenthooks.SessionEvent) (struct{}, error) {
	if ev.ParentID == "" {
		return struct{}{}, nil
	}
	scopes, globals, _ := e.stores()
	if scopes == nil || globals == nil {
		return struct{}{}, ErrNotLoaded
	}
	if err := scopes.InheritSessionRules(ev.ParentID, ev.SessionID); err != nil {
		return struct{}{}, err
	}
	if err := globals.InheritSessionRules(ev.ParentID, ev.SessionID); err != nil {
		return struct{}{}, err
	}
	return struct{}{}, nil
}

// rotatingReasons are the close reasons that are immediately followed by a
// continuation open on the same logical session (Session.rotate: /clear,
// /compact, resume). Their SessionEnd fires before the child's SessionStart,
// so the registrations park for one hop instead of dropping — otherwise the
// child's inheritance silently misses and it runs a turn unfenced
// (docs/19 appendix E2-2).
var rotatingReasons = map[string]bool{
	string(agentsession.SessionCloseCleared):   true,
	string(agentsession.SessionCloseCompacted): true,
	string(agentsession.SessionCloseResumed):   true,
}

// dropOnClose drops the session's fence registrations and its project proxy
// binding when the session closes, so the tables hold only live sessions and
// capacity is never exhausted by stale ids (fork fix P1-0). A rotation close
// parks the rule registrations for the continuation's inheritance instead —
// the egress binding is not parked: it rides every turn, so the continuation
// re-binds from its own payload, and a cleared route falls back to the node
// default. Unknown ids are a no-op; so is a close after the extension's own.
func (e *Extension) dropOnClose(_ context.Context, ev agenthooks.SessionEvent) (struct{}, error) {
	scopes, globals, routes := e.stores()
	if routes != nil {
		routes.Clear(ev.SessionID)
	}
	if scopes == nil || globals == nil {
		return struct{}{}, nil
	}
	if rotatingReasons[ev.Reason] {
		scopes.ParkSession(ev.SessionID)
		globals.ParkSession(ev.SessionID)
		return struct{}{}, nil
	}
	scopes.DropSession(ev.SessionID)
	globals.DropSession(ev.SessionID)
	return struct{}{}, nil
}

// fenceRulesDecorator registers the project scope rules and the instance
// fence for the turn's session. A full table rejects the turn: an unfenced
// run is never acceptable.
func (e *Extension) fenceRulesDecorator(req *aop.RunTurnRequest, _ *agentsession.RunInput) error {
	if err := e.turnScopeRules(req); err != nil {
		return err
	}
	return e.turnGlobalFence(req)
}

// egressProxyDecorator binds the session's outbound calls to the project
// proxy the manifest held at dispatch time. A store-less extension refuses
// the turn: a binding that went nowhere would run the session on the node
// default chain as if no proxy existed.
func (e *Extension) egressProxyDecorator(req *aop.RunTurnRequest, _ *agentsession.RunInput) error {
	return e.turnEgressProxy(req)
}

// turnScopeRules registers the test-range rule set a control plane attached to
// this turn. The set rides every turn (disabled drafts included) so the proxy
// judges each request against what the project manifest held when the run
// dispatched — never a stale push-once copy. An invalid payload is logged and
// ignored (the previous set stays in force); a full table is returned as
// ErrCapacity — the caller must reject the turn, because a skipped
// registration would run it unfenced.
func (e *Extension) turnScopeRules(req *aop.RunTurnRequest) error {
	if req == nil {
		return nil
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.ScopeRulesURLs)
	if extension == nil {
		return nil
	}
	scopes, _, _ := e.stores()
	if scopes == nil {
		return ErrNotLoaded
	}
	if err := scopes.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
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
func (e *Extension) turnGlobalFence(req *aop.RunTurnRequest) error {
	if req == nil {
		return nil
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.GlobalFenceURLs)
	if extension == nil {
		return nil
	}
	_, globals, _ := e.stores()
	if globals == nil {
		return ErrNotLoaded
	}
	if err := globals.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
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
// and falls back to the node default. Registration lives in this extension's
// own route store (same pattern as the rule tables): the session layer
// writes, the proxy hub reads through the seam, and neither imports the
// other. A store-less extension refuses the turn with ErrNotLoaded — a
// binding that went nowhere would run the session unfenced from its own
// egress policy.
//
// NewClient needs the extra protocol factories (trojan/vmess/hysteria2/anytls/
// clash) registered; those blank imports live in tools/proxy, which every
// agent binary links, so the factories are in the registry by the time a turn
// with such an endpoint arrives.
func (e *Extension) turnEgressProxy(req *aop.RunTurnRequest) error {
	if req == nil {
		return nil
	}
	extension := payloads.ExtensionWithURL(req.GetExtensions(), payloads.EgressProxyURLs)
	if extension == nil {
		return nil
	}
	_, _, routes := e.stores()
	if routes == nil {
		return ErrNotLoaded
	}
	sessionID := req.GetSessionId()
	payload, ok := payloads.ParseEgressProxy(extension)
	if !ok {
		log.Printf("aop: ignore invalid egress proxy for session %s", sessionID)
		routes.Clear(sessionID)
		return nil
	}
	// Disabled is a stored state the operator kept, not a deletion: clearing
	// the route is exactly how "off" reaches a session that is already live.
	if !payload.Enabled {
		routes.Clear(sessionID)
		return nil
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
		routes.Clear(sessionID)
		return nil
	}
	dial, err := proxyclient.NewClient(endpoint)
	if err != nil {
		log.Printf("aop: ignore undialable egress proxy for session %s: %v", sessionID, err)
		routes.Clear(sessionID)
		return nil
	}
	routes.Set(sessionID, egress.Dial(dial))
	return nil
}
