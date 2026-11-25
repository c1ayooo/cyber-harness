package proton_test

import (
	"testing"

	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
	protoncmd "github.com/c1ayooo/cyber/tools/proton"
)

func TestFactoryBuildsProtonCommand(t *testing.T) {
	registry := hosttest.Commands(t, protoncmd.NewCommand(t.TempDir(), nil, nil, "", nil))

	if !registry.Has("proton") {
		t.Fatal("proton command was not registered")
	}
}
