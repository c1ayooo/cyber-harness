// Package assembly is the scan product's recipe boundary (4zrcin docs/19
// P1-5, fork patch 24's importable form): the engine block — scanner, proton
// and the discovery pair — lives in this package instead of the upstream
// `package main`, so an embedding composition root links exactly one call.
// The capture twin (engines_capture.go, -tags captureonly) compiles an empty
// form: none of the engine packages behind these extensions enter that
// binary, and the passive gateway bindings cross back as data (nil there).
//
// The input types reference only config structs that compile in both
// recipes; the heavy tool chains stay behind the tagged files.
package assembly

import (
	passiveconfig "github.com/chainreactors/cyber/exts/passive/config"
	scannerext "github.com/chainreactors/cyber/exts/scanner"
)

// EnginesInput carries the fields the engine block reads off the scan
// configuration. It is an explicit, closed input: the assembly package owns
// no configuration parsing of its own.
type EnginesInput struct {
	SkipEngines      bool
	Scanner          scannerext.Config
	Recon            passiveconfig.Recon
	ReconCredentials map[string]string
}
