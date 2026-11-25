// Package apptest installs the base capabilities used by extension tests.
package apptest

import (
	"context"
	"testing"

	"github.com/c1ayooo/cyber/agent/provider"
	"github.com/c1ayooo/cyber/agent/skills"
	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/hooks"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
	providerext "github.com/c1ayooo/cyber/exts/provider"
	skillsext "github.com/c1ayooo/cyber/exts/skills"
	terminalext "github.com/c1ayooo/cyber/exts/terminal"
	tmuxext "github.com/c1ayooo/cyber/exts/tmux"
	"github.com/c1ayooo/cyber/pkg/internal/testutil/hosttest"
	terminaltool "github.com/c1ayooo/cyber/tools/terminal"
)

type Fixture struct {
	Providers *provider.State
	Stream    *events.Stream
	Logger    telemetry.Logger
	Hooks     *hooks.Registry
	Tools     coretool.Executor
	Commands  coretool.CommandExecutor
	Skills    *skills.Store
	Shell     *terminaltool.BashTool
}

func NewFixture(t testing.TB, logger telemetry.Logger, stream *events.Stream) *Fixture {
	t.Helper()
	if logger == nil {
		logger = telemetry.NopLogger()
	}
	if stream == nil {
		stream = events.New()
	}
	return &Fixture{Providers: &provider.State{}, Stream: stream, Logger: logger}
}

func Entries(t testing.TB, f *Fixture) []extension.Extension {
	t.Helper()
	library, err := skillsext.NewLibrary(skillsext.LibraryConfig{Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return []extension.Extension{
		extension.Provided[*hooks.Registry](hooks.New()),
		extension.Provided[*events.Stream](f.Stream),
		extension.Provided[telemetry.Logger](f.Logger),
		extension.Provided[egress.Endpoint](egress.Disabled()),
		coretool.NewCommandRegistry(), coretool.NewToolRegistry(), library,
		providerext.New(provider.StartupConfig{Mode: provider.StartupDisabled}),
		terminalext.New(terminalext.Config{Directory: t.TempDir(), Timeout: 1}), tmuxext.New(),
		extension.Func{LoadFunc: func(scope *extension.Scope) error {
			initial, config := f.Providers.Current()
			var err error
			if f.Providers, err = extension.Use[*provider.State](scope); err != nil {
				return err
			}
			f.Providers.Set(initial, config)
			if f.Hooks, err = extension.Use[*hooks.Registry](scope); err != nil {
				return err
			}
			if f.Tools, err = extension.Use[coretool.Executor](scope); err != nil {
				return err
			}
			if f.Commands, err = extension.Use[coretool.CommandExecutor](scope); err != nil {
				return err
			}
			if f.Skills, err = extension.Use[*skills.Store](scope); err != nil {
				return err
			}
			f.Shell, err = extension.Use[*terminaltool.BashTool](scope)
			return err
		}},
	}
}

func Load(t testing.TB, ctx context.Context, f *Fixture) *extension.Set {
	t.Helper()
	return hosttest.Load(t, ctx, Entries(t, f)...)
}
