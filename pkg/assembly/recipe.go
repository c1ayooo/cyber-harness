package assembly

import cfg "github.com/chainreactors/cyber/pkg/config"

// recipeCapability marks a capture node in the registration hello: the
// control plane uses the scan-capture marker to keep implicit dispatch off a
// node whose engine block is not assembled, while an explicit operator
// placement (traffic recording, fenced sessions) still honours the choice.
const recipeCapability = "scan-capture"

// recipeCapabilities reads the recipe off the runtime option. A full node
// reports no recipe marker: an absent capability tag means "full" on the
// control plane (docs/04 §3.1 - the conservative default keeps today's
// routing for every node launched without --capture-only).
func recipeCapabilities(option *cfg.Option) []string {
	if option.CaptureOnly {
		return []string{recipeCapability}
	}
	return nil
}
