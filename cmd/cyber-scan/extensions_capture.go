//go:build captureonly

package main

// The capture recipe's engine block (docs/04 §3.3): empty by construction.
// The scan-capture binary is a fenced traffic node — the proxy and the
// guardrail (with the guaranteed builtin audit) are its payload, and the
// scanner/proton/discovery extension packages plus the gogo/spray/zombie/
// neutron/katana tool chains behind them are compiled out entirely, together
// with the embedded template bundle (-tags emptyresources). The runtime
// SkipEngines switch loses its meaning here: there are no engines to skip.

import (
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/exts/gateway"
)

func engineExtensions(appConfig, string) ([]extension.Extension, []gateway.Kind) {
	return nil, nil
}
