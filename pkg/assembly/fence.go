package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	fenceext "github.com/chainreactors/cyber/exts/4zfence"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	proxyext "github.com/chainreactors/cyber/exts/proxy"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

// Judge is the 4z judge block a product root adds around the guardrail the
// base composition installs (docs/19 E3-2).
//
// Ahead loads before that guardrail, so the fence's tool.before admission
// (audit + red lines) is consulted first. Behind loads after it and hands the
// fence the guardrail runtime for the approval lifecycle. Fence is the same
// extension, so the same composition wires the proxy's scope judge without a
// second lookup.
type Judge struct {
	Ahead, Behind []extension.Extension
	Fence         *fenceext.Extension
	needsJEV      bool
}

// Fence reads the judge off the resolved configuration: the fence section
// carries the judge knobs (docs/19 已决 15), and its provider overrides the
// guardrail section's when it names a judge — so a deployment that filled only
// the guardrail section keeps its provider. A configuration without a fence
// section judges with the fence defaults.
func Fence(resolved *cfg.Resolved, guardrail guardrailext.Config) Judge {
	fence, provider := fenceconfig.Config{}, string(guardrail.Provider)
	if value, err := cfg.Get[*fenceconfig.Config](resolved, fenceconfig.ConfigKey); err == nil && value != nil {
		fence = *value
		if fence.Provider == "" {
			fence.Provider = provider
		}
		provider = fence.Provider
	}
	judge := Policy(fence, guardrail.Rules)
	judge.needsJEV = provider == "jev" || provider == "hybrid"
	return judge
}

// NeedsJEV reports whether the judge screens with JEV: a jev or hybrid
// provider needs the shared client, because hybrid escalates its
// low-confidence and review judgments to JEV. The LLM-only judge has no JEV
// dependency.
func (j Judge) NeedsJEV() bool { return j.needsJEV }

// Proxy dresses the traffic proxy with the judge (seam G2): the proxy's scope
// judge is the fence's, the node's own control plane — whatever server URL it
// serves — is exempt from judging and capture (fork patch 36), and the
// per-session egress routes are the fence's own table (E4 round 2). The seam
// values are read at composition time, before any Load, so each is a lazy
// view the fence resolves against its stores when a request or call arrives.
// An empty URL (a profile without an agent server, such as the Web service
// profile) exempts nothing.
func (j Judge) Proxy(config proxyext.Config, serverURL string) *proxyext.Extension {
	config.ScopeJudge = fenceext.NewScopeJudge(j.Fence)
	config.RequestExemption = fenceext.ControlPlaneExemption(serverURL)
	config.SessionRoutes = j.Fence.SessionRoutes()
	return proxyext.New(config)
}

// Policy composes the judge block for a composition that judges with the
// fence. The guardrail itself stays where upstream put it: the root passes its
// config through BaseConfig.Guardrail.
//
// Living here rather than in pkg/harness keeps the upstream base composition
// free of product blocks: a root that passes no Policy composes none.
func Policy(fence fenceconfig.Config, jevRules guardrailext.Rules) Judge {
	fenceExtension := fenceext.New(fence, jevRules)
	return Judge{
		Ahead: []extension.Extension{fenceExtension},
		Behind: []extension.Extension{extension.Func{LoadFunc: func(scope *extension.Scope) error {
			runtime, err := extension.Use[*guardrailext.Runtime](scope)
			if err != nil {
				return err
			}
			fenceExtension.Bind(runtime)
			return nil
		}}},
		Fence: fenceExtension,
	}
}
