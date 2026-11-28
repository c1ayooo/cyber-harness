package assembly

import (
	"context"
	"strings"
	"testing"

	cfg "github.com/chainreactors/cyber/pkg/config"
)

func guardrailLLMSection() map[string]any {
	return map[string]any{"base_url": "http://127.0.0.1:1/v1", "model": "judge"}
}

// TestGuardrailProviderConfigurationEnumeration pins the declared section's
// provider enumeration and the new field validation at the configuration
// boundary (the same path the Web settings and `--init` use).
func TestGuardrailProviderConfigurationEnumeration(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	for _, provider := range []string{"none", "jev"} {
		if _, err := defaultSections().ResolveValues(cfg.Values{"guardrail": {"provider": provider}}, nil, lookup); err != nil {
			t.Fatalf("provider %q rejected: %v", provider, err)
		}
	}
	for _, provider := range []string{"llm", "hybrid"} {
		if _, err := defaultSections().ResolveValues(cfg.Values{"fence": {"provider": provider, "llm": guardrailLLMSection()}}, nil, lookup); err != nil {
			t.Fatalf("provider %q rejected: %v", provider, err)
		}
	}
	// The legacy spelling (judge keys inside the guardrail section) still
	// reads: the read path migrates it in memory (已决 19).
	if _, err := defaultSections().ResolveValues(cfg.Values{"guardrail": {"provider": "llm", "llm": guardrailLLMSection()}}, nil, lookup); err != nil {
		t.Fatalf("legacy llm spelling rejected: %v", err)
	}
	_, err := defaultSections().ResolveValues(cfg.Values{"guardrail": {"provider": "off"}}, nil, lookup)
	if err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("invalid provider accepted or unclear: %v", err)
	}
	_, err = defaultSections().ResolveValues(cfg.Values{"fence": {"allow_prefixes": []any{"ls "}}}, nil, lookup)
	if err == nil || !strings.Contains(err.Error(), "allow_prefixes") {
		t.Fatalf("allow_prefixes outside safe mode accepted or unclear: %v", err)
	}
	_, err = defaultSections().ResolveValues(cfg.Values{"guardrail": {"provider": "llm"}}, nil, lookup)
	if err == nil || !strings.Contains(err.Error(), "base_url") {
		t.Fatalf("llm without base_url accepted or unclear: %v", err)
	}
}

// TestGuardrailProviderControlsJEVClient pins the composition contract:
// provider=llm must install without JEV credentials, while jev and hybrid still
// require the shared JEV client (hybrid escalates to JEV).
func TestGuardrailProviderControlsJEVClient(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	profile := func(fields cfg.Values) (interface {
		Load(context.Context) error
		Close(context.Context) error
	}, error) {
		config := minimalConfig(nil)
		config.Option.Extensions = fields
		value, err := buildCyberScanProfile(config)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	for _, test := range []struct {
		name    string
		fields  cfg.Values
		wantErr string
	}{
		{
			name: "llm_without_jev_credentials",
			fields: cfg.Values{
				"fence": {"provider": "llm", "llm": guardrailLLMSection()},
				"jev":   {"mode": "off"},
			},
		},
		{
			name: "jev_requires_credentials",
			fields: cfg.Values{
				"guardrail": {"provider": "jev"},
				"jev":       {"mode": "off"},
			},
			wantErr: "JEV requires",
		},
		{
			name: "hybrid_requires_credentials",
			fields: cfg.Values{
				"fence": {"provider": "hybrid", "llm": guardrailLLMSection()},
				"jev":   {"mode": "off"},
			},
			wantErr: "JEV requires",
		},
		{
			name: "hybrid_with_credentials",
			fields: cfg.Values{
				"fence": {"provider": "hybrid", "llm": guardrailLLMSection()},
				"jev":   {"mode": "off", "api_key": "fixture-key", "directory": t.TempDir()},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := profile(test.fields)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("build error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := value.Load(t.Context()); err != nil {
				_ = value.Close(context.Background())
				t.Fatal(err)
			}
			if err := value.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
