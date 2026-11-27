//go:build emptyresources

package resources

// The empty twin of template.go (docs/19 §5.2, the scan-capture recipe):
// embedded proton rules are a capability the capture recipe does not carry,
// so -tags emptyresources swaps the rule bundle for this no-op — a missing
// rule stays missing.

func loadEmbeddedConfig(typ string) []byte {
	return nil
}
