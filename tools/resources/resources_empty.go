//go:build emptyresources

package resources

// The empty twin of template.go (docs/04 §3.2, the scan-capture recipe): the
// embedded engine templates are a capability the capture recipe does not carry,
// so -tags emptyresources swaps the 472K bundle for this no-op. The interface
// is deliberately one private function — every call site lives inside this
// package, the public surface (Init/Set/Config) is unchanged, and the chain
// above loadEmbeddedConfig already degrades gracefully when a config is absent.
//
// What stays behind: guardrail_builtin_gen.go (the guaranteed audit corpus,
// fork patch 23b) carries no build tag — the audit duty is not a capability
// and ships in every binary form.

// loadEmbeddedConfig returns no embedded engine templates; engine
// configurations resolve from disk or the cyberhub relay only, and a missing
// one stays missing.
func loadEmbeddedConfig(typ string) []byte {
	return nil
}
