package assembly

import (
	"github.com/chainreactors/cyber/core/extension"
	fenceext "github.com/chainreactors/cyber/exts/4zfence"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
)

// Policy composes the judge block a product root installs explicitly
// (docs/19 E3-2): the fence ahead of the guardrail so its tool.before
// admission (audit + red lines) is consulted first, the bind hook afterwards
// handing the fence the guardrail runtime for the approval lifecycle. The
// returned fence extension lets the same composition wire the proxy's scope
// judge without a second lookup.
//
// The fence owns the judging (E3-3): its constructor takes the fence section
// and the guardrail section's own jev block, which a jev or hybrid stage
// screens with. The guardrail keeps upstream's single-argument constructor
// and only runs the approval queue.
//
// Living here rather than in pkg/harness keeps the upstream base composition
// free of product blocks: a host that skips Policy composes no judge at all.
func Policy(guardrail guardrailext.Config, fence fenceconfig.Config) ([]extension.Extension, *fenceext.Extension) {
	fenceExtension := fenceext.New(fence, guardrail.Rules)
	return []extension.Extension{
		fenceExtension,
		guardrailext.New(guardrail),
		extension.Func{LoadFunc: func(scope *extension.Scope) error {
			runtime, err := extension.Use[*guardrailext.Runtime](scope)
			if err != nil {
				return err
			}
			fenceExtension.Bind(runtime)
			return nil
		}},
	}, fenceExtension
}
