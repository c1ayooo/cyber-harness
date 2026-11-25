package main

import (
	"github.com/c1ayooo/cyber/core/extension"
	browserext "github.com/c1ayooo/cyber/exts/browser"
)

func browserExtension(config appConfig, workDir string) (extension.Extension, error) {
	if !optionalToolEnabled(config.OptionalTools, "browser") {
		return nil, nil
	}
	return browserext.New(workDir, config.PlaywrightSession)
}
