// Package policy is the fence's admission judge machinery (docs/19 E3-3):
// the pluggable judges — an OpenAI-compatible LLM, the JEV screen, and the
// hybrid of both — moved out of the guardrail extension, which keeps only
// the approval queue. Every implementation owns its provider transport and
// failure handling: a provider that is unreachable, times out or answers
// garbage must still return a Decision according to the configured on_error
// policy, so only cancellation justifies an error.
package policy

import (
	"context"
	"errors"

	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	guardrail "github.com/chainreactors/cyber/exts/guardrail"
)

// Policy is the pluggable admission judge behind the fence boundary.
// Check is the first judgment for every intercepted invocation. Confirm is
// the optional consequence stage; only auto mode runs it, and only for a
// call that Check flagged as risky.
type Policy interface {
	Check(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error)
	Confirm(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error)
}

var (
	// ErrNoPolicy means the configured provider installs no judgment at all
	// (provider none). The invocation proceeds without a policy event.
	ErrNoPolicy = errors.New("fence policy is not configured")
	// ErrNoConsequence means the Policy has no second stage. Auto mode then
	// keeps the first judgment instead of treating the gap as a failure.
	ErrNoConsequence = errors.New("fence policy has no consequence stage")
)
