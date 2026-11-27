package payloads

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/anypb"
)

// TrafficVerdict is one proxy-judgment sidecar: how the fence decided one
// exchange, carried verbatim so the control plane sees every field the judge
// set. Action is record | review | block.
type TrafficVerdict struct {
	Action string `json:"action"`
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason,omitempty"`
	// DefaultMissed marks a fallback verdict (no rule row matched, fork patch
	// 30): under the allowlist fence the control plane routes it to the
	// asset-pending flow instead of reading it as a hand-written verdict.
	// Absent on a hit and on every pre-patch sidecar.
	DefaultMissed bool `json:"default_missed,omitempty"`
	// Passive marks a static subresource the page pulled by itself
	// (Sec-Fetch-Dest script/style/image/font, fork patch 34): an
	// out-of-range passive request is forwarded and recorded instead of
	// queueing a pending asset. Absent on every deliberate request.
	Passive bool `json:"passive,omitempty"`
	// Shadow marks a judgment made by a shadow rollout: recorded, never
	// enforced.
	Shadow bool `json:"shadow,omitempty"`
}

// Valid reports whether the verdict carries a known action.
func (v TrafficVerdict) Valid() bool {
	switch v.Action {
	case "record", "review", "block":
		return true
	}
	return false
}

// TrafficVerdictExtension encodes the verdict as a sidecar.
func TrafficVerdictExtension(v TrafficVerdict) *anypb.Any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return &anypb.Any{TypeUrl: TrafficVerdictExtensionURL, Value: raw}
}

// ParseTrafficVerdict decodes one verdict sidecar. ok is false for anything
// that is not a verdict of this namespace with a known action.
func ParseTrafficVerdict(ext *anypb.Any) (TrafficVerdict, bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), ExtensionURLs("TrafficVerdict")) {
		return TrafficVerdict{}, false
	}
	var v TrafficVerdict
	if err := json.Unmarshal(ext.GetValue(), &v); err != nil {
		return TrafficVerdict{}, false
	}
	if !v.Valid() {
		return TrafficVerdict{}, false
	}
	return v, true
}
