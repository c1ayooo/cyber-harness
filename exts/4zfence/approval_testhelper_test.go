package fence

import (
	"context"
	"testing"
	"time"

	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
)

// The approval runtime comes up through its real construction path — the
// guardrail extension's Load — in every fence test: the fork's test-only
// constructor (guardrailext.NewRuntime) is gone, and engine AGENTS.md keeps
// test-only helpers out of production packages.
//
// The review timeout must be short: the corpus's hold samples block inside
// the approval lifecycle until the review expires, and the production
// default (5m) makes every such sample look like a hang. auto is the mode
// the tests ran in before the constructor moved.
func newApprovalRuntime(t *testing.T, stream *events.Stream) *guardrailext.Runtime {
	t.Helper()
	var runtime *guardrailext.Runtime
	set, err := extension.New(
		extension.Provided[*hooks.Registry](hooks.New()),
		extension.Provided[*events.Stream](stream),
		guardrailext.New(guardrailext.Config{Mode: guardrailext.ModeAuto, ReviewTimeout: "2s"}),
		extension.Func{LoadFunc: func(scope *extension.Scope) error {
			value, err := extension.Use[*guardrailext.Runtime](scope)
			if err != nil {
				return err
			}
			runtime = value
			return nil
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = set.Close(ctx)
	})
	return runtime
}
