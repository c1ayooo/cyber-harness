// Package assembly is the scan product's composition (4zrcin docs/19 P1-5,
// P6): the whole cyber-scan command — CLI, modes, profile and the extension
// graph it loads — together with the engine recipe and the judge block, in
// one importable package. The `scan` binary's entry and an embedding control
// plane's node verb both call Exec, so the node is assembled once. The
// capture recipe is a runtime mode of that one binary: --capture-only leaves
// Engines unassembled and the passive gateway bindings cross back as data
// (nil there); the scanner catalog stays full so parsing and help are the
// same in both modes.
package assembly

import (
	rulesconfig "github.com/chainreactors/cyber/exts/4zrules/config"
	passiveconfig "github.com/chainreactors/cyber/exts/passive/config"
	scannerext "github.com/chainreactors/cyber/exts/scanner"
)

// EnginesInput carries the fields the engine block reads off the scan
// configuration. It is an explicit, closed input: the assembly package owns
// no configuration parsing of its own.
type EnginesInput struct {
	SkipEngines      bool
	Scanner          scannerext.Config
	Rules            rulesconfig.Config
	Recon            passiveconfig.Recon
	ReconCredentials map[string]string
}
