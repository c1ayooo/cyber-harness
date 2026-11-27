//go:build !captureonly

package main

// The full recipe's engine block (docs/04 §3.3): scanner, proton and the
// discovery pair. This is the default build; the capture recipe compiles
// extensions_capture.go instead and none of these packages are linked. The
// second return carries the passive extension's gateway bindings: the gateway
// extension composes outside the recipe boundary, so its passive service has
// to cross it as data, not as a linked reference.

import (
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/exts/gateway"
	protonext "github.com/chainreactors/cyber/exts/proton"
	scannerext "github.com/chainreactors/cyber/exts/scanner"
	"github.com/chainreactors/cyber/tools/katana"
)

func engineExtensions(config appConfig, workDir string) ([]extension.Extension, []gateway.Kind) {
	if config.SkipEngines {
		return nil, nil
	}
	config.Scanner.Crawler = katana.Crawl
	discovery, feature := discoveryExtensions(config)
	extensions := []extension.Extension{
		scannerext.New(config.Scanner, workDir),
		protonext.New(protonext.Config{Directory: workDir}),
	}
	extensions = append(extensions, discovery...)
	return extensions, feature.Gateway(config.Recon.Service)
}
