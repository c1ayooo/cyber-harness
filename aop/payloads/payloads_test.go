package payloads

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
)

// Round trips through both namespace URLs: the node accepts what either
// generation of the control plane sends, and the decode returns the encode's
// values exactly.
func TestRoundTrips(t *testing.T) {
	t.Run("workdir", func(t *testing.T) {
		ext := WorkDirExtension("/tmp/case")
		payload, ok := ParseWorkDir(&anypb.Any{TypeUrl: WorkDirURLs[1], Value: ext.Value})
		if !ok || payload.WorkDir != "/tmp/case" || !payload.SingleTask {
			t.Fatalf("parse = %+v ok=%v", payload, ok)
		}
		if WorkDirExtension("  ") != nil {
			t.Fatal("blank workspace must omit the extension")
		}
	})
	t.Run("rungoal", func(t *testing.T) {
		ext := RunGoalExtension("g", "3x")
		payload, ok := ParseRunGoal(&anypb.Any{TypeUrl: RunGoalURLs[1], Value: ext.Value})
		if !ok || payload.Goal != "g" || EvalRoundsText(payload.EvalRounds) != "3x" {
			t.Fatalf("parse = %+v ok=%v", payload, ok)
		}
		// A number-shaped pacing spec decodes to its decimal form.
		if got := EvalRoundsText(json.RawMessage(`20`)); got != "20" {
			t.Fatalf("numeric rounds = %q", got)
		}
		if RunGoalExtension("", "") != nil {
			t.Fatal("an empty goal must omit the extension")
		}
	})
	t.Run("toolenv", func(t *testing.T) {
		ext := ToolEnvExtension(map[string]string{"K": "V"})
		pairs, ok := ParseToolEnv(&anypb.Any{TypeUrl: ToolEnvURLs[0], Value: ext.Value})
		if !ok || len(pairs) != 1 || pairs[0] != "K=V" {
			t.Fatalf("parse = %v ok=%v", pairs, ok)
		}
	})
	t.Run("caseseed", func(t *testing.T) {
		ext, err := CaseSeedExtension([]CaseSeedFile{{Path: ".zrcin/c", Mode: 0o640, Data: []byte("{}")}})
		if err != nil || ext == nil {
			t.Fatalf("encode = %v %v", ext, err)
		}
		files, err := ParseCaseSeed(&anypb.Any{TypeUrl: CaseSeedURLs[1], Value: ext.Value})
		if err != nil || len(files) != 1 || string(files[0].Data) != "{}" {
			t.Fatalf("parse = %v / %+v", err, files)
		}
		// Over-limit files are refused at encode: the control plane learns its
		// inputs cannot land instead of the node rejecting the turn.
		if _, err := CaseSeedExtension([]CaseSeedFile{{Path: "big", Data: make([]byte, MaxSeedFileBytes+1)}}); err == nil {
			t.Fatal("an oversized file must be refused at encode")
		}
	})
	t.Run("egressproxy", func(t *testing.T) {
		raw := json.RawMessage(`{"enabled":true,"scheme":"socks5","host":"p","port":1080,"url":"socks5://p:1080"}`)
		ext := EgressProxyExtension(raw)
		payload, ok := ParseEgressProxy(&anypb.Any{TypeUrl: EgressProxyURLs[1], Value: ext.Value})
		if !ok || !payload.Enabled || payload.URL != "socks5://p:1080" {
			t.Fatalf("parse = %+v ok=%v", payload, ok)
		}
	})
	t.Run("raw tables", func(t *testing.T) {
		if ScopeRulesExtension(json.RawMessage("  ")) != nil {
			t.Fatal("an empty rule table must omit the extension")
		}
		if GlobalFenceExtension(nil) != nil {
			t.Fatal("an absent fence must omit the extension")
		}
	})
}

// The verdict and artifact sidecars: known actions only, valid sizes only,
// and both namespace URLs decode.
func TestSidecars(t *testing.T) {
	v := TrafficVerdict{Action: "block", RuleID: "r", Reason: "why", DefaultMissed: true, Passive: false}
	ext := TrafficVerdictExtension(v)
	parsed, ok := ParseTrafficVerdict(&anypb.Any{TypeUrl: ExtensionURLs("TrafficVerdict")[0], Value: ext.Value})
	if !ok || parsed.Action != "block" || parsed.Reason != "why" || !parsed.DefaultMissed {
		t.Fatalf("verdict parse = %+v ok=%v", parsed, ok)
	}
	if _, ok := ParseTrafficVerdict(&anypb.Any{TypeUrl: TrafficVerdictExtensionURL, Value: []byte(`{"action":"wat"}`)}); ok {
		t.Fatal("an unknown action must not parse")
	}

	a := Artifact{Path: ".evidence/x", Size: 2, Data: []byte("hi")}
	extA := ArtifactExtension(a)
	parsedA, ok := ParseArtifact(&anypb.Any{TypeUrl: ExtensionURLs("Artifact")[0], Value: extA.Value})
	if !ok || parsedA.Path != ".evidence/x" || string(parsedA.Data) != "hi" {
		t.Fatalf("artifact parse = %+v ok=%v", parsedA, ok)
	}
	big := Artifact{Path: "big", Size: MaxArtifactBytes + 1, Data: make([]byte, MaxArtifactBytes+1)}
	if _, ok := ParseArtifact(&anypb.Any{TypeUrl: ArtifactExtensionURL, Value: mustJSON(big)}); ok {
		t.Fatal("an oversized artifact must not parse")
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
