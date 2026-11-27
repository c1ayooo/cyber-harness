package globalfence

// The instance fence's sample set (4zrcin docs/19 P1-4's acceptance input):
// a golden corpus of fence tables × commands/hosts → judgments, committed
// and compared. P1-4 moves this package into exts/4zfence; the SAME golden
// file must still pass — deny/allow/review precedence is the behavioral
// equivalence proof the move is judged by.
//
// Regenerate after an INTENDED behavior change with:
//
//	go test ./core/globalfence -run TestGoldenCorpus -update-golden
import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGoldenFence = flag.Bool("update-golden", false, "rewrite the golden corpus file")

type fenceGoldenSample struct {
	Name    string `json:"name"`
	Set     string `json:"set"` // the instance fence JSON the control plane sends
	Command string `json:"command,omitempty"`
	Host    string `json:"host,omitempty"`
	// Expectations
	CommandHit bool   `json:"command_hit,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	DenyHit    bool   `json:"deny_hit,omitempty"`
	AllowHit   bool   `json:"allow_hit,omitempty"`
}

type fenceGoldenEntry struct {
	Name       string `json:"name"`
	CommandHit bool   `json:"command_hit,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	DenyHit    bool   `json:"deny_hit,omitempty"`
	AllowHit   bool   `json:"allow_hit,omitempty"`
}

func TestGoldenCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "fence_samples.json"))
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	var samples []fenceGoldenSample
	if err := json.Unmarshal(raw, &samples); err != nil {
		t.Fatalf("decode samples: %v", err)
	}

	entries := make([]fenceGoldenEntry, 0, len(samples))
	for _, sample := range samples {
		if err := testStore.SetRules("golden-session", []byte(sample.Set)); err != nil {
			t.Fatalf("%s: register: %v", sample.Name, err)
		}
		entry := fenceGoldenEntry{Name: sample.Name}
		if sample.Command != "" {
			rule, hit := testStore.JudgeCommand("golden-session", sample.Command)
			entry.CommandHit = hit
			entry.RuleID = rule.ID
			if hit != sample.CommandHit {
				t.Errorf("%s: command hit %v, want %v", sample.Name, hit, sample.CommandHit)
			}
			if hit && rule.ID != sample.RuleID {
				t.Errorf("%s: rule %q, want %q", sample.Name, rule.ID, sample.RuleID)
			}
		}
		if sample.Host != "" {
			_, denyHit := testStore.DomainHit("golden-session", sample.Host)
			_, allowHit := testStore.AllowDomainHit("golden-session", sample.Host)
			entry.DenyHit, entry.AllowHit = denyHit, allowHit
			// The deny list outranks the allow list on the same name (patch 37).
			if denyHit != sample.DenyHit {
				t.Errorf("%s: deny hit %v, want %v", sample.Name, denyHit, sample.DenyHit)
			}
			if allowHit != sample.AllowHit {
				t.Errorf("%s: allow hit %v, want %v", sample.Name, allowHit, sample.AllowHit)
			}
		}
		entries = append(entries, entry)
	}
	testStore.DropSession("golden-session")

	goldenPath := filepath.Join("testdata", "fence_golden.json")
	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if *updateGoldenFence {
		if err := os.WriteFile(goldenPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (first run: -update-golden): %v", err)
	}
	var committed []fenceGoldenEntry
	if err := json.Unmarshal(existing, &committed); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(committed) != len(entries) {
		t.Fatalf("golden corpus size %d, want %d — the fence behavior changed", len(committed), len(entries))
	}
	for i, want := range committed {
		if entries[i] != want {
			t.Errorf("sample %d (%s): judgment drifted — got %+v, golden %+v", i, want.Name, entries[i], want)
		}
	}
}
