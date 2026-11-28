package evaluator

import (
	"hash/fnv"

	aop "github.com/chainreactors/cyber/aop"
)

// Usage accounting for evaluated runs lives here. Three facts drive the
// bookkeeping in RunWithEval and Evaluate:
//
//   - The evaluator is a model call on the same connection: its tokens belong
//     to this run's usage even when the judgement failed. Without this the
//     cost we report for every evaluated turn is systematically low. That is
//     why Evaluate returns the usage rather than logging it away.
//   - A nil usage is not zero usage: the endpoint can answer without one. That
//     case is recorded rather than hidden, because "the fix never ran" and
//     "the fix ran but there was nothing to count" look identical in the turn
//     total otherwise, and an unknown figure must read as unknown, not as a
//     fabricated zero. The routed model goes along as a hash: detail is
//     numeric, and the name is what explains a missing usage field.
//   - A retry is not free: every attempt that reached the provider consumed
//     tokens, including the failed ones.

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

// LastModel returns the model name the endpoint reported for the most recent
// judgement, empty when the endpoint did not report one. An endpoint that
// routes can answer with a different name than the one asked for, and that
// name is the only handle on why a usage field is missing; it is not a
// judgement input.
func (e *Evaluator) LastModel() string { return e.lastModel }

// addTokenUsage sums two usage records. A nil next leaves total untouched, so
// "the provider did not report usage" and "usage was zero" stay distinguishable.
func addTokenUsage(total, next *aop.TokenUsage) *aop.TokenUsage {
	if next == nil {
		return total
	}
	if total == nil {
		total = &aop.TokenUsage{Detail: map[string]uint64{}}
	}
	if total.Detail == nil {
		total.Detail = map[string]uint64{}
	}
	total.InputTokens += next.InputTokens
	total.OutputTokens += next.OutputTokens
	total.TotalTokens += next.TotalTokens
	total.Detail["cache_read"] += next.Detail["cache_read"]
	total.Detail["cache_write"] += next.Detail["cache_write"]
	return total
}
