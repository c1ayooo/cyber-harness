package scoperules

// The request-admission seam (4zdesign/19 seam G2) is owned by the proxy
// since the E3 revision: ScopeJudge/ScopeRequest/ScopeDecision and the
// take-once verdict registry live in tools/proxy as pure additions to the
// upstream package. This package keeps the historical spellings as aliases so
// the fence's judge, its tests, and the acceptance corpus read unchanged —
// the alias also makes the fence's judge satisfy the proxy interface with no
// adapter, and the proxy depends on no product package.
//
// Import direction note: the E3 revision weighed owning the types here
// (neutral ground, 4zdesign/19 P1-4c) against owning them in the seam. Ownership
// moved to the seam; this import is the fence block depending on an upstream
// seam, the direction red line 3 permits.

import (
	"github.com/chainreactors/cyber/tools/proxy"
)

// ScopeJudge decides whether the proxy may forward one attributed request.
type ScopeJudge = proxy.ScopeJudge

// ScopeRequest is one proxied request with its attribution.
type ScopeRequest = proxy.ScopeRequest

// ScopeDecision is the judge's answer, including the hold and refusal the
// proxy applies.
type ScopeDecision = proxy.ScopeDecision

// ScopeVerdict is the judge's verdict as the wire sees it.
type ScopeVerdict = proxy.ScopeVerdict

// ScopeCallToolName is the name the proxy gives the synthetic tool call a
// judge verdict refers to.
const ScopeCallToolName = proxy.ScopeCallToolName

// RecordVerdict / TakeVerdict are the seam's take-once verdict registry: the
// judge's answers key by flow id, the sidecar consumer takes each exactly
// once.
var (
	RecordVerdict = proxy.RecordVerdict
	TakeVerdict   = proxy.TakeVerdict
)
