package session

// Request decorators are the upstream seam G1 (4zrcin docs/19 appendix A):
// a control plane attaches fork payloads (WorkDir, RunGoal, CaseSeed, …) to
// the AOP requests' own `extensions []*anypb.Any`, and this package turns
// each into its session-side effect at open/turn time. Upstream
// OpenAOPSession/RunAOPTurn keep a single loop over the registered
// decorators — a decorator's error rejects the request (FAILED_PRECONDITION
// for turns), so a payload that claims to have landed cannot silently not
// have.
//
// The types live in agent/session (not the extension package) because the
// architecture test only allows agent/ to import core/ — the decorators take
// SessionOptions and RunInput, which are agent/session types. Registration
// flows through Runtime Config fields, set by the composition root: no
// global registry, no init side effects.

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

// applyOpenSessionDecorators runs the configured open decorators in order.
// A decorator's error names the decorator source when one is set.
func applyOpenSessionDecorators(ctx context.Context, decorators []OpenSessionDecorator, req *aop.OpenSessionRequest, options *SessionOptions) error {
	for _, decorator := range decorators {
		if decorator == nil {
			continue
		}
		if err := decorator(req, options); err != nil {
			return err
		}
	}
	return nil
}

// applyTurnDecorators runs the configured turn decorators in order.
func applyTurnDecorators(ctx context.Context, decorators []RunTurnDecorator, req *aop.RunTurnRequest, input *RunInput) error {
	for _, decorator := range decorators {
		if decorator == nil {
			continue
		}
		if err := decorator(req, input); err != nil {
			return err
		}
	}
	return nil
}
