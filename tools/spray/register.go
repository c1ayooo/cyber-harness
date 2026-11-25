package spray

import (
	"fmt"

	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
	"github.com/c1ayooo/cyber/tools/scan/engine"
)

func NewCommand(engines *engine.Set, logger telemetry.Logger, proxy string, events aop.EventPublisher) (coretool.Command, error) {
	if engines == nil || engines.Spray == nil {
		return coretool.Command{}, fmt.Errorf("spray engine is unavailable")
	}
	impl := New(engines.Spray).WithLogger(logger).WithProxy(proxy).WithEvents(events)
	return coretool.Command{
		Name: impl.Name(), Usage: impl.Usage(), QuickReference: impl.QuickReference(),
		DescriptionPath: "cyber://skills/cyber/okf/easm/spray.md",
		Run:             impl.Run,
	}, nil
}
