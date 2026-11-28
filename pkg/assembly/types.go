// Package assembly is the scan product's composition (4zrcin docs/19 P1-5,
// P6): the whole cyber-scan command — CLI, modes, profile and the extension
// graph it loads — together with the engine recipe and the judge block, in
// one importable package. The `scan` binary's entry and an embedding control
// plane's node verb both call Exec, so the node is assembled once.
//
// The capture twin (engines_capture.go, -tags captureonly) compiles an empty
// form: none of the engine packages behind these extensions enter that
// binary, and the passive gateway bindings cross back as data (nil there).
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
