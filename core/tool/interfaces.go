package tool

import (
	"context"

	"github.com/c1ayooo/cyber/core/types"
)

type CommandExecutor interface {
	Get(string) (*types.CommandSpec, bool)
	Has(string) bool
	All() []*types.CommandSpec
	Names() []string
	DescriptionPath(string) string
	UsageDocs() string
	Execute(context.Context, string, *Execution) (any, error)
	Run(context.Context, []string, *Execution) (any, error)
}
