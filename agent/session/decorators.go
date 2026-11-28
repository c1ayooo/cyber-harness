package session

// Request decorators are the upstream seam G1 (4zdesign/19 appendix A).
// A control plane attaches fork payloads (WorkDir, RunGoal, CaseSeed, scope
// rules, …) to the AOP requests' own `extensions []*anypb.Any`. This package
// only runs the decorators a composition registered: the payload contract and
// its effects belong to the building blocks that register them (the 4zsession
// and 4zfence extensions), so a composition that registers none keeps
// upstream behavior.
//
// OpenAOPSession and RunAOPTurn each hand their request to one wrapper below
// instead of to EnsureSession / RunSession directly — a one-line hook per
// entry point. A decorator's error rejects the request with the entry point's
// ordinary FAILED_PRECONDITION, so a payload that claims to have landed
// cannot silently not have.
//
// The types live in agent/session (not the extension package) because the
// architecture test only allows agent/ to import core/ — the decorators take
// SessionOptions and RunInput, which are agent/session types. Registration
// flows through Config, set by the composition root: no global registry, no
// init side effects.

import (
	"context"

	aop "github.com/chainreactors/cyber/aop"
)

// OpenSessionDecorator mutates one open-session request into the session
// options the runtime will honor. Returning an error rejects the open.
type OpenSessionDecorator func(req *aop.OpenSessionRequest, options *SessionOptions) error

// RunTurnDecorator mutates one run-turn request into the turn input.
// Returning an error rejects the turn.
type RunTurnDecorator func(req *aop.RunTurnRequest, input *RunInput) error

// openDecoratedSession runs the registered open decorators, in order, and
// ensures the session with the options they produced.
func (rt *Runtime) openDecoratedSession(req *aop.OpenSessionRequest, options SessionOptions) (*Session, error) {
	for _, decorator := range rt.config.OpenSessionDecorators {
		if decorator == nil {
			continue
		}
		if err := decorator(req, &options); err != nil {
			return nil, err
		}
	}
	return rt.EnsureSession(options)
}

// runDecoratedTurn runs the registered turn decorators, in order, and starts
// the turn with the input they produced.
func (rt *Runtime) runDecoratedTurn(ctx context.Context, req *aop.RunTurnRequest, input RunInput) (*Run, error) {
	for _, decorator := range rt.config.TurnDecorators {
		if decorator == nil {
			continue
		}
		if err := decorator(req, &input); err != nil {
			return nil, err
		}
	}
	return rt.RunSession(ctx, req.SessionId, input)
}
