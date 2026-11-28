package scoperules

// The fence sample set (4zdesign/19 P1-4's acceptance input): a golden
// corpus of rule sets × requests → verdicts, committed and compared
// byte-for-byte. P1-4 moves this package into exts/4zfence; the SAME golden
// file must still pass there — verdict-for-verbatim is the behavioral
// equivalence proof the move is judged by.
//
// Regenerate after an INTENDED behavior change with:
//
//	go test ./core/scoperules -run TestGoldenCorpus -update-golden
import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden corpus file")

type goldenSample struct {
	Name   string `json:"name"`
	Set    string `json:"set"`  // scope_rules JSON the control plane sends
	Get    string `json:"get"`  // request URL (GET unless noted)
	Want   string `json:"want"` // action: record|review|block|"" (unjudged)
	Rule   string `json:"rule,omitempty"`
	Missed bool   `json:"default_missed,omitempty"`
}

type goldenEntry struct {
	Name    string  `json:"name"`
	Set     string  `json:"set"`
	Get     string  `json:"get"`
	Verdict Verdict `json:"verdict"`
	Judged  bool    `json:"judged"`
}

func TestGoldenCorpus(t *testing.T) {
	samplesJSON, err := os.ReadFile(filepath.Join("testdata", "fence_samples.json"))
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	var samples []goldenSample
	if err := json.Unmarshal(samplesJSON, &samples); err != nil {
		t.Fatalf("decode samples: %v", err)
	}

	entries := make([]goldenEntry, 0, len(samples))
	for _, sample := range samples {
		set, err := Parse([]byte(sample.Set))
		if err != nil {
			t.Fatalf("%s: parse: %v", sample.Name, err)
		}
		verdict, judged := set.Judge("GET", sample.Get)
		if sample.Want == "" {
			if judged {
				t.Errorf("%s: judged, want unjudged", sample.Name)
			}
		} else {
			if !judged {
				t.Errorf("%s: unjudged, want %s", sample.Name, sample.Want)
			}
			if verdict.Action != sample.Want {
				t.Errorf("%s: action %q, want %q", sample.Name, verdict.Action, sample.Want)
			}
			if verdict.RuleID != sample.Rule {
				t.Errorf("%s: rule %q, want %q", sample.Name, verdict.RuleID, sample.Rule)
			}
			if verdict.DefaultMissed != sample.Missed {
				t.Errorf("%s: default_missed %v, want %v", sample.Name, verdict.DefaultMissed, sample.Missed)
			}
		}
		entries = append(entries, goldenEntry{
			Name: sample.Name, Set: sample.Set, Get: sample.Get,
			Verdict: verdict, Judged: judged,
		})
	}

	goldenPath := filepath.Join("testdata", "fence_golden.json")
	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if *updateGolden {
		if err := os.WriteFile(goldenPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (first run: -update-golden): %v", err)
	}
	var committed []goldenEntry
	if err := json.Unmarshal(existing, &committed); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(committed) != len(entries) {
		t.Fatalf("golden corpus size %d, want %d — the fence behavior changed", len(committed), len(entries))
	}
	for i, want := range committed {
		if entries[i].Verdict != want.Verdict || entries[i].Judged != want.Judged {
			t.Errorf("sample %d (%s): verdict drifted — got %+v judged=%v, golden %+v judged=%v",
				i, want.Name, entries[i].Verdict, entries[i].Judged, want.Verdict, want.Judged)
		}
	}
}
