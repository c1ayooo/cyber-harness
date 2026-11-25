// Package native contributes the built-in Agent tools and commands.
package native

import (
	"github.com/c1ayooo/cyber/agent"
	"github.com/c1ayooo/cyber/core/extension"
	coretool "github.com/c1ayooo/cyber/core/tool"
	looptool "github.com/c1ayooo/cyber/tools/loop"
)

type Extension struct{}

func New() *Extension { return &Extension{} }
func (e *Extension) Load(scope *extension.Scope) error {
	if err := extension.Add[coretool.Tool](scope, &agent.InboxWaitTool{}); err != nil {
		return err
	}
	return extension.Add(scope, looptool.NewCommand())
}

var _ extension.Extension = (*Extension)(nil)
