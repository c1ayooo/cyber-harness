// Package payloads is the single source for the 4zrcin request/verdict
// payload contracts: the JSON shapes carried in AOP request `extensions` and
// event sidecars between a control plane and the harness. Both sides import
// this package — the control plane encodes, the agent decodes — so the wire
// format cannot drift and neither side re-declares it.
//
// Everything here rides the upstream request's own `extensions []*anypb.Any`
// (JSON-in-Any per the fork convention): no upstream proto message is
// modified. Type URLs carry the current 4zrcin namespace; the legacy tianwu
// namespace is still recognized on decode for pre-rename control planes.
//
// Dependencies are deliberately stdlib + anypb only, matching the aop
// module's budget, so any consumer (control plane, agent, extension) can
// import it without pulling the engine.
package payloads

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
)

// Namespace prefixes every payload type URL. The control plane renamed
// tianwu.* to 4zrcin.* (fork patch 20); agents accept both, control planes
// send the current one.
const (
	NamespaceCurrent = "4zrcin"
	NamespaceLegacy  = "tianwu"
)

// Extension type URLs in the current namespace.
const (
	WorkDirExtensionURL        = "type.googleapis.com/" + NamespaceCurrent + ".WorkDir"
	RunGoalExtensionURL        = "type.googleapis.com/" + NamespaceCurrent + ".RunGoal"
	CaseSeedExtensionURL       = "type.googleapis.com/" + NamespaceCurrent + ".CaseSeed"
	ToolEnvExtensionURL        = "type.googleapis.com/" + NamespaceCurrent + ".ToolEnv"
	ScopeRulesExtensionURL     = "type.googleapis.com/" + NamespaceCurrent + ".ScopeRules"
	GlobalFenceExtensionURL    = "type.googleapis.com/" + NamespaceCurrent + ".GlobalFence"
	EgressProxyExtensionURL    = "type.googleapis.com/" + NamespaceCurrent + ".EgressProxy"
	TrafficVerdictExtensionURL = "type.googleapis.com/" + NamespaceCurrent + ".TrafficVerdict"
	ArtifactExtensionURL       = "type.googleapis.com/" + NamespaceCurrent + ".Artifact"
)

// ExtensionURLs lists both namespaces for one payload, oldest first — the
// tianwu → 4zrcin rename (fork patch 20) means agents match by list to keep
// pre-rename control planes working.
func ExtensionURLs(name string) []string {
	return []string{
		"type.googleapis.com/" + NamespaceLegacy + "." + name,
		"type.googleapis.com/" + NamespaceCurrent + "." + name,
	}
}

// WorkDirURLs, RunGoalURLs and friends are the per-payload URL lists agents
// match against.
var (
	WorkDirURLs     = ExtensionURLs("WorkDir")
	RunGoalURLs     = ExtensionURLs("RunGoal")
	CaseSeedURLs    = ExtensionURLs("CaseSeed")
	ToolEnvURLs     = ExtensionURLs("ToolEnv")
	ScopeRulesURLs  = ExtensionURLs("ScopeRules")
	GlobalFenceURLs = ExtensionURLs("GlobalFence")
	EgressProxyURLs = ExtensionURLs("EgressProxy")
)

// extension builds one JSON-in-Any sidecar with the current-namespace URL.
func extension(url string, v any) *anypb.Any {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("payloads: %s: %v", url, err)) // marshal of our own shapes cannot fail
	}
	return &anypb.Any{TypeUrl: url, Value: raw}
}

// encodeRaw wraps raw JSON (a rule table the control plane holds verbatim)
// as a sidecar.
func encodeRaw(url string, raw json.RawMessage) *anypb.Any {
	return &anypb.Any{TypeUrl: url, Value: []byte(raw)}
}

// ExtensionWithURL returns the first extension whose type URL matches one of
// the given URLs. Shared by every agent-side decoder.
func ExtensionWithURL(extensions []*anypb.Any, urls []string) *anypb.Any {
	for _, extension := range extensions {
		if extension == nil {
			continue
		}
		for _, url := range urls {
			if extension.GetTypeUrl() == url {
				return extension
			}
		}
	}
	return nil
}
