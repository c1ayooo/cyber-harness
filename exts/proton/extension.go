// Package proton installs content leak detection independently of scanner engines.
package proton

import (
	"context"
	"embed"

	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/telemetry"
	"github.com/c1ayooo/cyber/tools/files"
	protontool "github.com/c1ayooo/cyber/tools/proton"
	"github.com/c1ayooo/cyber/tools/proton/resources"
)

//go:embed proton.md
var docs embed.FS

type Config struct {
	Directory    string
	Rules        func(string) []byte
	ExcludePaths []string
}
type Extension struct {
	config Config
	files  *files.Files
}

func New(config Config) *Extension { return &Extension{config: config} }
func Usage() string                { return protontool.New().Usage() }
func (e *Extension) Load(scope *extension.Scope) error {
	logger, err := extension.Use[telemetry.Logger](scope)
	if err != nil {
		return err
	}
	endpoint, err := extension.Use[egress.Endpoint](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	files, err := extension.Use[*files.Files](scope)
	if err != nil {
		return err
	}
	if err := files.Mount("cyber://proton/", docs); err != nil {
		return err
	}
	e.files = files
	rules := e.config.Rules
	if rules == nil {
		rules = resources.Config
	}
	command := protontool.NewCommand(e.config.Directory, rules, logger, endpoint.ProxyURL(), stream, e.config.ExcludePaths...)
	return extension.Add(scope, command)
}
func (e *Extension) Close(ctx context.Context) error {
	if e.files == nil {
		return nil
	}
	err := e.files.Unmount(ctx, "cyber://proton/")
	if err == nil {
		e.files = nil
	}
	return err
}

var _ extension.Extension = (*Extension)(nil)
