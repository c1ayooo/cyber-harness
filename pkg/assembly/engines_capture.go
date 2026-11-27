//go:build captureonly

package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/exts/gateway"
)

func Engines(EnginesInput, string) ([]extension.Extension, []gateway.Kind) {
	return nil, nil
}
