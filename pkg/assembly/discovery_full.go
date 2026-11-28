package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	katanaext "github.com/chainreactors/cyber/exts/katana"
	passiveext "github.com/chainreactors/cyber/exts/passive"
	"github.com/chainreactors/cyber/tools/passive"
)

// Discovery composes the katana crawler and the passive recon extension.
func Discovery(input EnginesInput) ([]extension.Extension, *passiveext.Extension) {
	feature := passiveext.New(passive.Config{
		HunterAPIKey: input.Recon.HunterAPIKey,
		Proxy:        input.Recon.Proxy,
		Limit:        intValue(input.Recon.Limit),
		Credentials:  input.ReconCredentials,
	})
	return []extension.Extension{katanaext.New(), feature}, feature
}
