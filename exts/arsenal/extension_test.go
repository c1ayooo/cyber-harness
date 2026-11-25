package arsenal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/c1ayooo/cyber/core/extension"
	coretool "github.com/c1ayooo/cyber/core/tool"
	arsenalext "github.com/c1ayooo/cyber/exts/arsenal"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
	crtm "github.com/chainreactors/crtm/pkg"
)

func TestArsenalOwnsManagerAndCommandInstallation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "arsenal")
	arsenal, err := arsenalext.New(directory, crtm.ManagerOption{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := arsenal.BinPath(), filepath.Join(directory, "bin"); got != want {
		t.Fatalf("child process path: %q, want %q", got, want)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("constructor changed the filesystem: %v", err)
	}
	commands := coretool.NewCommandRegistry()
	var manager *crtm.Manager
	set := hosttest.Load(t, t.Context(), hosttest.Capabilities(), commands, arsenal,
		extension.Func{LoadFunc: func(scope *extension.Scope) error {
			var err error
			manager, err = extension.Use[*crtm.Manager](scope)
			return err
		}})
	if manager == nil || manager.BinPath() != arsenal.BinPath() || !commands.Has("arsenal") {
		t.Fatal("manager and command were not installed together")
	}
	if err := set.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if commands.Has("arsenal") {
		t.Fatal("arsenal command survived installation close")
	}
}

func TestArsenalRejectsRelativeDirectory(t *testing.T) {
	if instance, err := arsenalext.New("relative", crtm.ManagerOption{}); err == nil || instance != nil {
		t.Fatalf("invalid directory accepted: %v, %v", instance, err)
	}
}
