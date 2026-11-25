package proton

import (
	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
)

func NewCommand(workDir string, provider func(string) []byte, logger telemetry.Logger, proxy string, events aop.EventPublisher, excludes ...string) coretool.Command {
	cmd := New().WithLogger(logger).WithProxy(proxy).WithEvents(events)
	if provider != nil {
		cmd.WithResourceProvider(provider)
	}
	cmd.SetWorkDir(workDir)
	cmd.excludePaths = append([]string(nil), excludes...)
	return coretool.Command{
		Name: cmd.Name(), Usage: cmd.Usage(),
		DescriptionPath: "cyber://proton/proton.md",
		Run:             cmd.Run,
	}
}
