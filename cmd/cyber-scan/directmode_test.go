//go:build !captureonly

package main

// The direct scanner mode only exists in the full recipe: the capture binary
// has no scan subcommand to parse (docs/04 §3.3), so this test does not apply
// there.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/chainreactors/cyber/core/telemetry"
	taskcli "github.com/chainreactors/cyber/pkg/cli/task"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

func TestDirectScannerModeSuppressesInitInfoByDefault(t *testing.T) {
	var logBuf bytes.Buffer
	logger := telemetry.NewLogger(telemetry.LogConfig{Output: &logBuf})
	err := runDirectScannerMode(context.Background(), newCyberScanProfile, &cfg.Option{
		MiscOptions: cfg.MiscOptions{NoColor: true},
	}, []string{"scan", "-i", "http://127.0.0.1:1", "--timeout", "1", "--no-color"}, logger, taskcli.NewOutput(&cfg.Option{}, nil, nil))
	if err != nil {
		t.Fatalf("RunDirectScannerMode() error = %v", err)
	}
	logText := logBuf.String()
	for _, unwanted := range []string{"provider init", "engine=fingers", "resources type="} {
		if strings.Contains(logText, unwanted) {
			t.Fatalf("normal mode leaked init log %q:\n%s", unwanted, logText)
		}
	}
}
