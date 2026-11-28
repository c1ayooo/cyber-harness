//go:build captureonly

package assembly

// The capture recipe announces itself in the registration hello: the control
// plane uses the scan-capture marker to keep implicit dispatch off a node
// whose engine block was compiled out, while an explicit operator placement
// (traffic recording, fenced sessions) still honours the choice.
const recipeCapability = "scan-capture"

func recipeCapabilities() []string { return []string{recipeCapability} }
