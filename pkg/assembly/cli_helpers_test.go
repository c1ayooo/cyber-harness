package assembly

// CLI test helpers shared by the package's test files.

import (
	"strings"
	"testing"

	ioaclient "github.com/chainreactors/cyber/exts/ioa/client"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func readClientOptions(t *testing.T, option *cfg.Option) ioaclient.Options {
	t.Helper()
	value, err := ioaclient.ReadOptions(option)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
