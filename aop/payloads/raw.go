package payloads

import (
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// ScopeRulesExtension wraps the project's machine-matchable rule table (the
// manifest's scope_rules JSON) as a sidecar. The control plane holds the rows
// verbatim; the node's fence parses them with its own schema. An empty payload
// (no rules configured) returns nil: callers append the extension only when
// it is non-nil.
func ScopeRulesExtension(rules json.RawMessage) *anypb.Any {
	if len(strings.TrimSpace(string(rules))) == 0 {
		return nil
	}
	return encodeRaw(ScopeRulesExtensionURL, rules)
}

// GlobalFenceExtension wraps the instance's red-line tables (command and
// domain deny/allow JSON) as a sidecar. Empty returns nil.
func GlobalFenceExtension(fence json.RawMessage) *anypb.Any {
	if len(strings.TrimSpace(string(fence))) == 0 {
		return nil
	}
	return encodeRaw(GlobalFenceExtensionURL, fence)
}
