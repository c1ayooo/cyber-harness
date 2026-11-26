//go:build !captureonly

package main

// The full recipe reports no recipe marker: an absent capability tag means
// "full" on the control plane (docs/04 §3.1 - the conservative default keeps
// today's routing for every binary built before the marker existed).

func recipeCapabilities() []string { return nil }
