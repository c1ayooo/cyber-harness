package scoperules

// The request-admission seam types (4zrcin docs/19 P1-4, seam G2). They live
// beside the rule tables they name, so every party — the proxy (tools/proxy
// aliases them), the fence judge (exts/4zfence), and the composition — can
// reference the contract without importing each other.

import (
	"context"

	aop "github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/operation"
)

// ScopeJudge decides whether the proxy may forward one attributed request.
// JudgeScopeConnect judges a CONNECT tunnel (host-form only). The fence's
// judge implements both; it reuses the guardrail runtime's pending-review
// lifecycle for held requests without importing it here.
type ScopeJudge interface {
	JudgeScopeRequest(req ScopeRequest) ScopeDecision
	JudgeScopeConnect(req ScopeRequest) ScopeDecision
}

// ScopeRequest is one proxied request with its attribution.
type ScopeRequest struct {
	Invocation operation.Invocation
	Call       *aop.ToolCall
	Operation  *operationpb.Ref
}

// ScopeDecision is the judge's answer. Judged=false means "not my business":
// forward untouched. Hold is set only for a review verdict; it blocks until
// the review resolves (true = approved, forward) or expires/is refused
// (false = refuse).
//
// Verdict is the judge's own Verdict, carried verbatim so the capture sidecar
// keeps every field the judge set (default_missed, passive, shadow). When it
// is nil — a stub judge, or a path that answered from the action alone — the
// proxy reconstructs {action, rule_id, reason} as before.
type ScopeDecision struct {
	Judged  bool
	Action  string // record | review | block
	RuleID  string
	Reason  string
	Hold    func(ctx context.Context) bool
	Verdict *Verdict
}
