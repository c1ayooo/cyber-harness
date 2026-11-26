//go:build !captureonly

package main

// The full recipe's engine block (docs/04 §3.3): scanner, proton and the
// discovery pair. This is the default build; the capture recipe compiles
// extensions_capture.go instead and none of these packages are linked.

import (
	"github.com/c1ayooo/cyber/core/extension"
	protonext "github.com/c1ayooo/cyber/exts/proton"
	scannerext "github.com/c1ayooo/cyber/exts/scanner"
	"github.com/c1ayooo/cyber/tools/katana"
)

func engineExtensions(config appConfig, workDir string) []extension.Extension {
	if config.SkipEngines {
		return nil
	}
	config.Scanner.Crawler = katana.Crawl
	extensions := []extension.Extension{
		scannerext.New(config.Scanner, workDir),
		protonext.New(protonext.Config{Directory: workDir}),
	}
	return append(extensions, discoveryExtensions(config)...)
}
