package server

import (
	"github.com/c1ayooo/cyber/core/resource"
	hostcli "github.com/c1ayooo/cyber/pkg/cli"
	cfg "github.com/c1ayooo/cyber/pkg/config"
)

// Declare contributes the server resources needed before argument parsing.
func Declare(resources *resource.Registry, command hostcli.Contribution) error {
	section := Section()
	if _, err := resource.Add[hostcli.Contribution](resources, command); err != nil {
		return err
	}
	_, err := resource.Add[cfg.Section](resources, section)
	return err
}
