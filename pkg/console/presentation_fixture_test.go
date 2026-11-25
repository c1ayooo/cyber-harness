package console

import (
	"context"
	agentsession "github.com/c1ayooo/cyber/agent/session"
	"github.com/c1ayooo/cyber/core/extension"
	sessionext "github.com/c1ayooo/cyber/exts/session"
	tuiext "github.com/c1ayooo/cyber/exts/tui"
	"github.com/c1ayooo/cyber/pkg/console/api"
	"testing"
)

// Tests install the same provider/contributor path as a Profile.
func testSessionBindings(t *testing.T, runtime *agentsession.Runtime) *api.Bindings {
	t.Helper()
	tui := tuiext.New()
	contribution := sessionext.NewConsole()
	var registry *api.Registry
	borrow := extension.Func{LoadFunc: func(scope *extension.Scope) error {
		var err error
		registry, err = extension.Use[*api.Registry](scope)
		return err
	}}
	set, err := extension.New(extension.Provided[*agentsession.Runtime](runtime), tui, contribution, borrow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := set.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	return registry.Bindings()
}
