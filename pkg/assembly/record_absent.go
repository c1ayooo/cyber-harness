//go:build !(record && cgo && (windows || linux))

package assembly

import "github.com/chainreactors/cyber/core/extension"

func recordExtension(appConfig, string) (extension.Extension, error) {
	return nil, nil
}

const recordExtensionLinked = false
