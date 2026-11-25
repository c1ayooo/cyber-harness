package passive

import (
	"context"
	"testing"

	"github.com/c1ayooo/cyber/agent/provider"
	"github.com/c1ayooo/cyber/core/extension"
	coretool "github.com/c1ayooo/cyber/core/tool"
	"github.com/c1ayooo/cyber/pkg/harness"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
	"github.com/c1ayooo/cyber/tools/files"
	"github.com/c1ayooo/cyber/tools/passive"
)

func TestIndependentCommandAndDocsLifecycle(t *testing.T) {
	entries, err := harness.BaseExtensions(harness.BaseConfig{Directory: t.TempDir(), Provider: provider.StartupConfig{Mode: provider.StartupDisabled}})
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, New(passive.ReconOptions{}))
	var commands coretool.CommandExecutor
	var fs *files.Files
	entries = append(entries, extension.Func{LoadFunc: func(scope *extension.Scope) error {
		var err error
		commands, err = extension.Use[coretool.CommandExecutor](scope)
		if err != nil {
			return err
		}
		fs, err = extension.Use[*files.Files](scope)
		return err
	}})
	set := hosttest.Load(t, t.Context(), entries...)
	if !commands.Has("passive") || commands.Has("scan") {
		t.Fatalf("commands=%v", commands.Names())
	}
	body, err := fs.Read(t.Context(), commands.DescriptionPath("passive"))
	if err != nil || len(body) == 0 {
		t.Fatalf("docs: %v", err)
	}
	if err = set.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if commands.Has("passive") {
		t.Fatal("command survived extension close")
	}
}
