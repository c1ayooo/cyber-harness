package main

// CLI test helpers shared by every recipe's test files: the capture build's
// tests use them too, so they live outside the !captureonly test files.

import (
	"strings"
	"testing"

	ioaclient "github.com/c1ayooo/cyber/exts/ioa/client"
	cfg "github.com/c1ayooo/cyber/pkg/config"
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
