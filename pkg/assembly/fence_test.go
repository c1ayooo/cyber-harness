package assembly

import (
	"testing"

	"github.com/chainreactors/cyber/core/resource"
	fenceext "github.com/chainreactors/cyber/exts/4zfence"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	proxyext "github.com/chainreactors/cyber/exts/proxy"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

// resolve builds a resolved configuration with the guardrail section and,
// optionally, the fence section declared — the two shapes Fence must read.
func resolve(t *testing.T, withFence bool, file cfg.Values) *cfg.Resolved {
	t.Helper()
	resources := resource.New()
	sections := cfg.NewSections()
	if _, err := resource.Define[cfg.Section](resources, sections); err != nil {
		t.Fatal(err)
	}
	if err := guardrailext.Declare(resources); err != nil {
		t.Fatal(err)
	}
	if withFence {
		if err := fenceext.Declare(resources); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := sections.ResolveValues(file, nil, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func guardrailOf(t *testing.T, resolved *cfg.Resolved) guardrailext.Config {
	t.Helper()
	value, err := cfg.Get[*guardrailext.Config](resolved, guardrailext.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	return *value
}

// The judge's provider is the fence section's, falling back to the guardrail
// section's; JEV is needed exactly when that provider is jev or hybrid.
func TestFenceProviderAndJEVNeed(t *testing.T) {
	llm := map[string]any{"base_url": "http://127.0.0.1:1/v1", "model": "judge"}
	for _, test := range []struct {
		name    string
		withF   bool
		file    cfg.Values
		wantJEV bool
	}{
		{name: "fence_jev", withF: true, file: cfg.Values{"fence": {"provider": "jev"}}, wantJEV: true},
		{name: "fence_hybrid", withF: true, file: cfg.Values{"fence": {"provider": "hybrid", "llm": llm}}, wantJEV: true},
		{name: "fence_llm", withF: true, file: cfg.Values{"fence": {"provider": "llm", "llm": llm}}},
		{name: "fence_none", withF: true, file: cfg.Values{"fence": {"provider": "none"}, "guardrail": {"provider": "jev"}}},
		{name: "fence_empty_falls_back_to_guardrail_jev", withF: true, file: cfg.Values{"fence": {}, "guardrail": {"provider": "jev"}}, wantJEV: true},
		{name: "no_fence_section_guardrail_jev", file: cfg.Values{"guardrail": {"provider": "jev"}}, wantJEV: true},
		{name: "no_fence_section_guardrail_none", file: cfg.Values{"guardrail": {"provider": "none"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolve(t, test.withF, test.file)
			judge := Fence(resolved, guardrailOf(t, resolved))
			if judge.Fence == nil || len(judge.Ahead) != 1 || len(judge.Behind) != 1 {
				t.Fatalf("judge block = fence %v, ahead %d, behind %d", judge.Fence != nil, len(judge.Ahead), len(judge.Behind))
			}
			if judge.Fence != judge.Ahead[0] {
				t.Fatalf("the entry loading ahead of the guardrail is not the fence the proxy judges with")
			}
			if judge.NeedsJEV() != test.wantJEV {
				t.Fatalf("NeedsJEV = %v, want %v", judge.NeedsJEV(), test.wantJEV)
			}
			proxy := judge.Proxy(proxyext.Config{WorkDir: t.TempDir()}, "")
			if proxy == nil {
				t.Fatal("Proxy returned no extension")
			}
		})
	}
}
