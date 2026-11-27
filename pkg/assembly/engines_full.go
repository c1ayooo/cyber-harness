//go:build !captureonly

package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/exts/gateway"
	protonext "github.com/chainreactors/cyber/exts/proton"
	scannerext "github.com/chainreactors/cyber/exts/scanner"
	"github.com/chainreactors/cyber/tools/katana"
)

func Engines(input EnginesInput, workDir string) ([]extension.Extension, []gateway.Kind) {
	if input.SkipEngines {
		return nil, nil
	}
	input.Scanner.Crawler = katana.Crawl
	discovery, feature := Discovery(input)
	extensions := []extension.Extension{
		scannerext.New(input.Scanner, workDir),
		protonext.New(protonext.Config{Directory: workDir}),
	}
	extensions = append(extensions, discovery...)
	var bindings []gateway.Kind
	if feature != nil {
		bindings = feature.Gateway(input.Recon.Service)
	}
	return extensions, bindings
}
