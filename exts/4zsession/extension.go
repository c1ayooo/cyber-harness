package zsession

import (
	agentsession "github.com/chainreactors/cyber/agent/session"
	"github.com/chainreactors/cyber/core/extension"
)

// InputDecorators is the extension-level contribution: the input-enrichment
// decorators a composition appends to the session runtime. A step toward the
// G1 contribution point (4zdesign/19 appendix E3); the RuntimeConfig wiring keeps
// consuming TurnDecorators() for now.
type InputDecorators []agentsession.RunTurnDecorator

// Extension declares the subtree so the composition and the exts guard see
// 4zsession mounted as a whole; Load publishes its decorators.
type Extension struct{}

var _ extension.Extension = (*Extension)(nil)

// New builds the session-payload extension.
func New() *Extension { return &Extension{} }

// Load publishes the input-enrichment decorators.
func (e *Extension) Load(scope *extension.Scope) error {
	if err := scope.Init().Err(); err != nil {
		return err
	}
	return extension.Provide[InputDecorators](scope, InputDecorators(TurnDecorators()))
}
