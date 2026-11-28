package assembly

import (
	"os/exec"
	"strings"
	"testing"
)

// The recap worker spends one model call after every turn without reporting its
// usage, so the reference profile must not link it again; see FORK.md patch 16.
// exts/recap stays available for embedders that compose it explicitly.
func TestProfileDoesNotLinkRecapWorker(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./cmd/cyber-scan")
	cmd.Dir = repositoryRoot(t)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if dependency == "github.com/chainreactors/cyber/exts/recap" {
			t.Fatal("cyber-scan links the recap worker again; it adds unreported model calls per turn")
		}
	}
}
