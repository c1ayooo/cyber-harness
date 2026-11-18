package guardrail

import (
	"strings"
	"testing"
	"time"
)

func TestGuardrailDefaults(t *testing.T) {
	config := Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: " https://judge.example/v1/ ", Model: " judge "}}.defaults()
	if config.Mode != ModeAuto || config.ReviewTimeout != "5m" || config.Timeout != "3s" || config.Concurrency != 8 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
	if config.OnError != "review" {
		t.Fatalf("on_error default = %q", config.OnError)
	}
	if config.LLM.BaseURL != "https://judge.example/v1" || config.LLM.Model != "judge" || config.LLM.MaxTokens != 128 || config.LLM.Temperature != 0 {
		t.Fatalf("unexpected LLM defaults: %+v", config.LLM)
	}
	if _, err := (Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: "https://judge.example/v1", Model: "judge"}}).timeout(); err != nil {
		t.Fatalf("valid llm config rejected: %v", err)
	}
	if _, err := (Config{}).timeout(); err != nil {
		t.Fatalf("empty config rejected: %v", err)
	}
}

func TestGuardrailProviderEnumeration(t *testing.T) {
	for _, provider := range []string{"", ProviderNone, ProviderJEV} {
		if _, err := (Config{Provider: provider}).timeout(); err != nil {
			t.Fatalf("provider %q rejected: %v", provider, err)
		}
	}
	for _, provider := range []string{ProviderLLM, ProviderHybrid} {
		config := Config{Provider: provider, LLM: LLMConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "judge"}}
		if _, err := config.timeout(); err != nil {
			t.Fatalf("provider %q rejected: %v", provider, err)
		}
	}
	_, err := (Config{Provider: "off"}).timeout()
	if err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("invalid provider accepted or unclear: %v", err)
	}
}

func TestGuardrailConfigValidationReasons(t *testing.T) {
	llm := LLMConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "judge"}
	for _, test := range []struct {
		name   string
		config Config
		want   string
	}{
		{name: "mode", config: Config{Mode: "off"}, want: "mode"},
		{name: "review_timeout", config: Config{ReviewTimeout: "0"}, want: "review_timeout"},
		{name: "scope_empty", config: Config{Scope: []string{"bash", " "}}, want: "scope"},
		{name: "allow_prefixes_without_safe", config: Config{AllowPrefixes: []string{"ls"}}, want: "allow_prefixes"},
		{name: "allow_prefixes_empty", config: Config{Mode: ModeSafe, AllowPrefixes: []string{""}}, want: "allow_prefixes"},
		{name: "on_error_enum", config: Config{Provider: ProviderLLM, OnError: "maybe", LLM: llm}, want: "on_error"},
		{name: "on_error_jev", config: Config{Provider: ProviderJEV, OnError: "review"}, want: "on_error"},
		{name: "timeout", config: Config{Timeout: "soon"}, want: "timeout"},
		{name: "timeout_zero", config: Config{Timeout: "0s"}, want: "timeout"},
		{name: "concurrency_negative", config: Config{Concurrency: -1}, want: "concurrency"},
		{name: "concurrency_huge", config: Config{Concurrency: 4096}, want: "concurrency"},
		{name: "llm_missing_base_url", config: Config{Provider: ProviderLLM, LLM: LLMConfig{Model: "judge"}}, want: "base_url"},
		{name: "llm_missing_model", config: Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: "http://127.0.0.1:1/v1"}}, want: "model"},
		{name: "llm_bad_scheme", config: Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: "ftp://judge.example/v1", Model: "judge"}}, want: "http"},
		{name: "llm_temperature", config: Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "judge", Temperature: 3}}, want: "temperature"},
		{name: "llm_max_tokens", config: Config{Provider: ProviderLLM, LLM: LLMConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "judge", MaxTokens: 8000}}, want: "max_tokens"},
		{name: "llm_without_provider", config: Config{LLM: llm}, want: "provider=llm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.config.timeout()
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not explain %q", err, test.want)
			}
			if !hasChinese(err.Error()) {
				t.Fatalf("error %q is not a readable Chinese reason", err)
			}
		})
	}
	// Valid combinations that touch every new field.
	valid := []Config{
		{Mode: ModeSafe, Scope: []string{"bash", "subagent"}, AllowPrefixes: []string{"ls ", "cat "}, Shadow: true},
		{Provider: ProviderJEV, Scope: []string{"bash"}, Shadow: true},
		{Provider: ProviderLLM, LLM: llm, OnError: "allow", Timeout: "1500ms", Concurrency: 2, Shadow: true},
		{Provider: ProviderHybrid, LLM: llm, Mode: ModeSafe, AllowPrefixes: []string{"id "}, OnError: "block"},
	}
	for index, config := range valid {
		if _, err := config.timeout(); err != nil {
			t.Fatalf("valid config %d rejected: %v", index, err)
		}
	}
	if timeout, err := (Config{Provider: ProviderLLM, LLM: llm, Timeout: "1500ms"}).timeout(); err != nil || timeout != 5*time.Minute {
		t.Fatalf("review timeout = %v, %v", timeout, err)
	}
}

// hasChinese reports whether the text contains a CJK character.
func hasChinese(text string) bool {
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			return true
		}
	}
	return false
}
