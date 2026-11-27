package passive

import (
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
)

func NewCommand(backend Engine, logger telemetry.Logger) coretool.Command {
	impl := New(backend).WithLogger(logger)
	return coretool.Command{
		Name: impl.Name(), Usage: impl.Usage(), QuickReference: impl.QuickReference(),
		DescriptionPath: ReferenceURI,
		Run:             impl.Run,
	}
}
