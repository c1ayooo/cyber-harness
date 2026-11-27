package guardrail

import (
	"context"
	"errors"

	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
)

// Policy is the pluggable admission judge behind the guardrail boundary.
// Check is the first judgment for every intercepted invocation. Confirm is the
// optional consequence stage; only auto mode runs it, and only for a call that
// Check flagged as risky. Implementations own provider transport and failure
// handling: a provider that is unreachable, times out or answers garbage must
// still return a Decision according to the configured on_error policy, so only
// cancellation justifies an error. Runtime.Admit depends on this interface and
// never on a concrete provider.
type Policy interface {
	Check(context.Context, toolhooks.CallEvent) (*Decision, error)
	Confirm(context.Context, toolhooks.CallEvent) (*Decision, error)
}

var (
	// errNoPolicy means the configured provider installs no judgment at all
	// (provider none). The invocation proceeds without a policy event.
	errNoPolicy = errors.New("guardrail policy is not configured")
	// errNoConsequence means the Policy has no second stage. Auto mode then
	// keeps the first judgment instead of treating the gap as a failure.
	errNoConsequence = errors.New("guardrail policy has no consequence stage")
)

// funcPolicy adapts two decision functions to the Policy interface. It backs
// the disabled provider and the package's function-level test seams; concrete
// providers implement Policy directly and are never wrapped here.
type funcPolicy struct {
	check, confirm checkFunc
}

func (p funcPolicy) Check(ctx context.Context, ev toolhooks.CallEvent) (*Decision, error) {
	if p.check == nil {
		return nil, errNoPolicy
	}
	return p.check(ctx, ev)
}

func (p funcPolicy) Confirm(ctx context.Context, ev toolhooks.CallEvent) (*Decision, error) {
	if p.confirm == nil {
		return nil, errNoConsequence
	}
	return p.confirm(ctx, ev)
}
