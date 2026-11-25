package arsenal

import (
	coretool "github.com/c1ayooo/cyber/core/tool"
	crtm "github.com/chainreactors/crtm/pkg"
)

func NewCommand(mgr *crtm.Manager) coretool.Command {
	cmd := &command{mgr: mgr}
	return coretool.Command{
		Name: cmd.Name(), Usage: cmd.Usage(),
		DescriptionPath: "cyber://skills/runtime/arsenal.md",
		Run:             cmd.Run,
	}
}
