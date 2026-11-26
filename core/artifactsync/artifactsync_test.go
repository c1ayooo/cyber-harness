package artifactsync

import "testing"

// The .zrcin handoff contract (fork patch 27): default-deny under .zrcin, with
// exactly the two files a control plane reads back allowed through.
func TestSkipsArtifactAllowsOnlyTheHandoffFiles(t *testing.T) {
	cases := map[string]bool{
		"results.jsonl":               false,
		"raw/x.bin":                   false,
		".zrcin/facts.jsonl":          false,
		".zrcin/worker-note.md":       false,
		"cases/a/.zrcin/facts.jsonl":  false,
		".zrcin/auth":                 true,
		".zrcin/identity.json":        true,
		".zrcin/aop-session.json":     true,
		".zrcin/facts.offset":         true,
		".zrcin/cursor-repair-1.json": true,
		".zrcin/future-secret":        true,
		".zrcin/nested/facts.jsonl":   true,
		".zrcin":                      true,
	}
	for path, want := range cases {
		if got := skipsArtifact(path); got != want {
			t.Errorf("skipsArtifact(%q) = %v, want %v", path, got, want)
		}
	}
}
