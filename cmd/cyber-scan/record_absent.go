//go:build !(record && cgo && (windows || linux))

package main

import "github.com/c1ayooo/cyber/core/extension"

func recordExtension(appConfig, string) (extension.Extension, error) {
	return nil, nil
}

const recordExtensionLinked = false
