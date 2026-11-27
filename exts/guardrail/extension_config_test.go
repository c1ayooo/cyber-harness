package guardrail

// The two sections' validation: the guardrail section keeps the upstream
// rules (none/jev, mode, review timeout); the fence section owns the extended
// judges and their knobs (fenceconfig's own tests cover the details).

import (
	"strings"
	"testing"
	"time"

	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
)

func TestGuardrailSectionValidation(t *testing.T) {
	for _, provider := range []string{"", ProviderNone, ProviderJEV} {
		if _, err := (Config{Provider: provider}).timeout(); err != nil {
			t.Fatalf("provider %q rejected: %v", provider, err)
		}
	}
	_, err := (Config{Provider: "off"}).timeout()
	if err == nil || !strings.Contains(err.Error(), "none 或 jev") {
		t.Fatalf("unknown provider error = %v", err)
	}
	_, err = (Config{Provider: ProviderLLM}).timeout()
	if err == nil {
		t.Fatal("guardrail section must not accept llm (it lives in the fence section)")
	}
	_, err = (Config{Mode: "yolo"}).timeout()
	if err == nil || !strings.Contains(err.Error(), "safe 或 auto") {
		t.Fatalf("mode error = %v", err)
	}
	if _, err := (Config{ReviewTimeout: "500ms"}).timeout(); err != nil {
		t.Fatalf("review_timeout rejected: %v", err)
	}
	_, err = (Config{ReviewTimeout: "0s"}).timeout()
	if err == nil {
		t.Fatal("non-positive review_timeout accepted")
	}
	if d, err := (Config{}).timeout(); err != nil || d != 5*time.Minute {
		t.Fatalf("default review timeout = %v err=%v", d, err)
	}
}

func TestFenceSectionDefaults(t *testing.T) {
	fence := fenceconfig.Config{Provider: fenceconfig.ProviderLLM,
		LLM: fenceconfig.LLMConfig{BaseURL: " https://judge.example/v1/ ", Model: " judge "}}.Defaults()
	if fence.Mode != "auto" || fence.Timeout != "3s" || fence.Concurrency != 8 {
		t.Fatalf("unexpected defaults: %+v", fence)
	}
	if fence.OnError != "review" {
		t.Fatalf("on_error default = %q", fence.OnError)
	}
	if fence.LLM.BaseURL != "https://judge.example/v1" || fence.LLM.Model != "judge" || fence.LLM.MaxTokens != 128 {
		t.Fatalf("unexpected LLM defaults: %+v", fence.LLM)
	}
	if err := fence.Validate(); err != nil {
		t.Fatalf("valid fence config rejected: %v", err)
	}
}
