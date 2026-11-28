package evaluator

import (
	"hash/fnv"

	aop "github.com/chainreactors/cyber/aop"
)

// Usage accounting for evaluated runs lives here. Two facts drive the
// bookkeeping in RunWithEval:
//
//   - The evaluator is a model call on the same connection: its tokens belong
//     to this run's usage even when the judgement failed. Without this the
//     cost we report for every evaluated turn is systematically low.
//   - A nil usage is not zero usage: the endpoint can answer without one. That
//     case is recorded rather than hidden, because "the fix never ran" and
//     "the fix ran but there was nothing to count" look identical in the turn
//     total otherwise. The routed model goes along as a hash: detail is
//     numeric, and the name is what explains a missing usage field.

// ensureUsage returns a usage record that can carry detail keys, creating it
// when the run has none yet. A usage that exists but has no detail map is
// extended in place, so nothing already counted is lost.
func ensureUsage(u *aop.TokenUsage) *aop.TokenUsage {
	if u == nil {
		return &aop.TokenUsage{Detail: map[string]uint64{}}
	}
	if u.Detail == nil {
		u.Detail = map[string]uint64{}
	}
	return u
}

// fnv64a fingerprints a model name for the usage detail, which only carries
// numbers. The same hash over the candidate names decodes it again.
func fnv64a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}
