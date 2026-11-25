package passive

import (
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
)

func NewCommand(backend QueryEngine, logger telemetry.Logger) coretool.Command {
	impl := New(backend).WithLogger(logger)
	return coretool.Command{
		Name: impl.Name(), Usage: impl.Usage(),
		DescriptionPath: "cyber://skills/passive/passive.md",
		Run:             impl.Run,
	}
}
