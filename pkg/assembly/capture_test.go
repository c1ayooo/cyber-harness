package assembly

// The capture mode is a runtime switch on the one scan binary (4zdesign/19
// P6 step 3): --capture-only assembles no engine block and announces
// scan-capture in the registration hello, and the scanner commands refuse to
// run. Without the switch every surface is today's full node.

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/chainreactors/cyber/agent/provider"
	"github.com/chainreactors/cyber/core/telemetry"
	taskcli "github.com/chainreactors/cyber/pkg/cli/task"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

func captureOption(captureOnly bool) *cfg.Option {
	return &cfg.Option{MiscOptions: cfg.MiscOptions{CaptureOnly: captureOnly}}
}

func TestCaptureOnlyAssemblesNoEngines(t *testing.T) {
	config, err := configFromOption(captureOption(true), provider.StartupDisabled, nil, telemetry.NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Base.SkipEngines {
		t.Fatal("--capture-only must leave the engine block unassembled")
	}
	engines, bindings := Engines(EnginesInput{SkipEngines: config.Base.SkipEngines}, "")
	if len(engines) != 0 || len(bindings) != 0 {
		t.Fatalf("capture mode assembled engines %v / bindings %v", engines, bindings)
	}
}

func TestFullModeKeepsTheEngineBlock(t *testing.T) {
	config, err := configFromOption(captureOption(false), provider.StartupDisabled, nil, telemetry.NopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if config.Base.SkipEngines {
		t.Fatal("the full node must assemble the engine block")
	}
	if engines, _ := Engines(EnginesInput{}, ""); len(engines) == 0 {
		t.Fatal("the full engine block assembled nothing")
	}
}

func TestCaptureOnlyHelloAnnouncesScanCapture(t *testing.T) {
	if got := recipeCapabilities(captureOption(true)); !slices.Equal(got, []string{"scan-capture"}) {
		t.Fatalf("capture hello capabilities = %v, want [scan-capture]", got)
	}
	if got := recipeCapabilities(captureOption(false)); got != nil {
		t.Fatalf("full hello capabilities = %v, want none", got)
	}
}

func TestCaptureOnlyRefusesScannerRuns(t *testing.T) {
	for _, command := range []string{"scan", "passive", "gogo"} {
		args := []string{command, "-i", "http://127.0.0.1:1"}
		err := runDirectScannerMode(context.Background(), nil, captureOption(true), args, telemetry.NopLogger(), taskcli.NewOutput(&cfg.Option{}, nil, nil))
		if err == nil {
			t.Fatalf("%s ran on a capture node", command)
		}
		if !strings.Contains(err.Error(), "--capture-only") {
			t.Fatalf("%s refusal names the switch, got %q", command, err)
		}
	}
}

func TestCaptureOnlyStillServesScannerHelp(t *testing.T) {
	// The catalog stays full: help is not execution, so a capture node still
	// explains a scanner command it refuses to run.
	err := runDirectScannerMode(context.Background(), nil, captureOption(true), []string{"gogo", "-h"}, telemetry.NopLogger(), taskcli.NewOutput(&cfg.Option{}, io.Discard, io.Discard))
	if err != nil {
		t.Fatalf("scanner help refused on a capture node: %v", err)
	}
}

func TestFullModeRunsScanners(t *testing.T) {
	// Same args as the refusal test, switch off: the refusal must not fire —
	// the run proceeds past the capture gate (it fails later on its own terms,
	// or succeeds; either is today's behavior).
	err := runDirectScannerMode(context.Background(), nil, captureOption(false), []string{"passive", "-i", "x"}, telemetry.NopLogger(), taskcli.NewOutput(&cfg.Option{}, io.Discard, io.Discard))
	if err != nil && strings.Contains(err.Error(), "--capture-only") {
		t.Fatalf("full node hit the capture refusal: %v", err)
	}
}
