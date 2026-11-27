package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	fenceext "github.com/chainreactors/cyber/exts/4zfence"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
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
