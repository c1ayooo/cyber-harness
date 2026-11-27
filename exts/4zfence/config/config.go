// Package fenceconfig is the fence's own configuration section (已决 15/20,
// 4zrcin docs/19): the admission judge's knobs live under the `fence` key —
// who judges (none/jev/llm/hybrid), how verdicts enforce (mode), what happens
// when the judge fails (on_error), shadow observation, and the OpenAI-
// compatible judge endpoint. The section's struct and validation are the
// single source shared by the node's Declare and the shell's settings writer:
// the package depends on nothing from the engine, so the shell imports the
// same file through the engine module without linking any of it.
//
// Migration (已决 19): older documents carried these keys inside the
// `guardrail` section. Both read paths recognize the legacy spelling; any
// save writes the `fence` section, prunes the legacy keys and records one
// diagnostic. An operator's file is never rewritten at startup.
package fenceconfig

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Provider selects the admission judge. The empty value keeps the historical
// "none" default so an omitted section installs no policy.
const (
	ProviderNone   = "none"
	ProviderJEV    = "jev"
	ProviderLLM    = "llm"
	ProviderHybrid = "hybrid"
)

// ConfigKey is the section key.
const ConfigKey = "fence"

// Config is the fence judge's configuration.
// ReviewTimeout stays in the guardrail section: it times the approval queue,
// which is the guardrail runtime's own concern. The rest of the judge's
// knobs live here.
type Config struct {
	Provider string `config:"provider" json:"provider" description:"none (default), jev, llm or hybrid"`
	Mode     string `config:"mode" json:"mode" description:"auto asks the judge to assess consequences (default); safe asks a human; screening always applies"`
	// Scope limits judgment to the named tools. Empty means every tool call.
	Scope []string `config:"scope" json:"scope" description:"Only judge these tool names (default all); for example bash and subagent"`
	// AllowPrefixes is a deterministic safe-mode allow list matched against the
	// tool's command text. It is intentionally not a semantic classifier.
	AllowPrefixes []string  `config:"allow_prefixes" json:"allow_prefixes" description:"safe mode only: literal command prefixes that bypass human review"`
	OnError       string    `config:"on_error" json:"on_error" description:"llm/hybrid only: allow, review (default) or block when the judge fails"`
	Timeout       string    `config:"timeout" json:"timeout" description:"judge request timeout (default 3s)"`
	Concurrency   int       `config:"concurrency" json:"concurrency" description:"judge maximum concurrent requests (default 8)"`
	Shadow        bool      `config:"shadow" json:"shadow" description:"observe and record judgments, always allow execution"`
	LLM           LLMConfig `config:"llm" json:"llm" description:"OpenAI-compatible judge used by provider llm and hybrid"`
}

// Defaults applies the documented defaults without mutating the caller's copy.
func (c Config) Defaults() Config {
	if c.Mode == "" {
		c.Mode = "auto"
	}
	if c.Timeout == "" {
		c.Timeout = "3s"
	}
	if c.Concurrency == 0 {
		c.Concurrency = DefaultLLMConcurrency
	}
	if c.OnError == "" && (c.Provider == ProviderLLM || c.Provider == ProviderHybrid) {
		c.OnError = "review"
	}
	c.Scope = NormalizeList(c.Scope)
	c.LLM = c.LLM.Defaults()
	return c
}

// NormalizeList trims entries and drops empty ones from a name list.
func NormalizeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// Validate checks every field and returns a readable Chinese reason.
func (c Config) Validate() error {
	original := c
	c = c.Defaults()
	switch c.Provider {
	case "", ProviderNone, ProviderJEV, ProviderLLM, ProviderHybrid:
	default:
		return fmt.Errorf("fence provider 必须是 none、jev、llm 或 hybrid，当前为 %q", original.Provider)
	}
	if c.Mode != "safe" && c.Mode != "auto" {
		return fmt.Errorf("fence mode 必须是 safe 或 auto，当前为 %q", c.Mode)
	}
	for _, name := range original.Scope {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("fence scope 中的工具名不能为空")
		}
	}
	if len(original.AllowPrefixes) > 0 {
		if c.Mode != "safe" {
			return fmt.Errorf("fence allow_prefixes 仅在 mode=safe 时生效，请将 mode 设为 safe")
		}
		for _, prefix := range original.AllowPrefixes {
			if strings.TrimSpace(prefix) == "" {
				return fmt.Errorf("fence allow_prefixes 不能包含空字符串前缀")
			}
		}
	}
	switch c.OnError {
	case "":
		// Defaults fill llm/hybrid; empty remains valid for none/jev.
	case "allow", "review", "block":
	default:
		return fmt.Errorf("fence on_error 必须是 allow、review 或 block，当前为 %q", original.OnError)
	}
	if c.OnError != "" && c.Provider != ProviderLLM && c.Provider != ProviderHybrid {
		return fmt.Errorf("fence on_error 仅适用于 provider=llm 或 provider=hybrid")
	}
	if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
		return fmt.Errorf("fence timeout 必须是正 duration，例如 3s，当前为 %q", c.Timeout)
	}
	if c.Concurrency < 1 || c.Concurrency > 1024 {
		return fmt.Errorf("fence concurrency 必须在 1 到 1024 之间，当前为 %d", c.Concurrency)
	}
	return c.LLM.Validate(c.Provider)
}

// LLMTimeout returns the judge request timeout.
func (c Config) LLMTimeout() time.Duration {
	c = c.Defaults()
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// DefaultLLMConcurrency and DefaultLLMMaxTokens mirror the documented judge
// defaults.
const (
	DefaultLLMConcurrency = 8
	DefaultLLMMaxTokens   = 128
)

// LLMConfig is the OpenAI-compatible judge endpoint. The API key is optional
// so local gateways that do not authenticate remain usable.
type LLMConfig struct {
	BaseURL     string  `config:"base_url" json:"base_url" description:"OpenAI-compatible base URL, for example https://api.openai.com/v1"`
	Model       string  `config:"model" json:"model" description:"Judge model name"`
	APIKey      string  `config:"api_key" json:"api_key" description:"Optional bearer token for the judge endpoint"`
	Temperature float64 `config:"temperature" json:"temperature" description:"Judge sampling temperature (default 0)"`
	MaxTokens   int     `config:"max_tokens" json:"max_tokens" description:"Judge output token limit (default 128)"`
}

// Defaults normalizes the endpoint fields.
func (c LLMConfig) Defaults() LLMConfig {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Model = strings.TrimSpace(c.Model)
	if c.MaxTokens == 0 {
		c.MaxTokens = DefaultLLMMaxTokens
	}
	return c
}

// Validate checks the endpoint against the selected provider.
func (c LLMConfig) Validate(provider string) error {
	if provider != ProviderLLM && provider != ProviderHybrid {
		if c.BaseURL != "" || c.Model != "" || c.APIKey != "" || c.Temperature != 0 {
			return fmt.Errorf("fence.llm 仅在 provider=llm 或 provider=hybrid 时生效")
		}
		return nil
	}
	if c.BaseURL == "" {
		return fmt.Errorf("fence.llm.base_url 是 provider=llm/hybrid 的必填项")
	}
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("fence.llm.base_url 必须是 http(s) 地址，当前为 %q", c.BaseURL)
	}
	if c.Model == "" {
		return fmt.Errorf("fence.llm.model 是 provider=llm/hybrid 的必填项")
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("fence.llm.temperature 必须在 0 到 2 之间，当前为 %v", c.Temperature)
	}
	if c.MaxTokens < 1 || c.MaxTokens > 4096 {
		return fmt.Errorf("fence.llm.max_tokens 必须在 1 到 4096 之间，当前为 %d", c.MaxTokens)
	}
	return nil
}

// LegacySection is the section older documents carried the judge knobs in.
const LegacySection = "guardrail"

// legacyKeys lists the guardrail-section keys this section owns since the
// migration (已决 15). provider/mode stay in the guardrail section's own
// spelling: they name the approval queue's mode and its none/jev default; the
// fence section's provider (when set) overrides the effective judge.
var legacyKeys = []string{"on_error", "shadow", "scope", "allow_prefixes", "timeout", "concurrency", "llm"}

// legacyProviders name the judges that only exist in the fence section; a
// legacy guardrail section carrying one migrates its provider key too.
var legacyProviders = map[string]bool{"llm": true, "hybrid": true}

// MigrateDocument moves the judge keys from a document's legacy guardrail
// section into the fence section, in memory only — an operator's file is
// never rewritten at startup (已决 19). The save path (the shell's settings
// writer) performs the same move on disk and records the diagnostic. It
// reports whether anything moved; an existing fence section wins and the
// legacy keys are only removed, never merged field-by-field.
func MigrateDocument(document map[string]any) (bool, string) {
	raw, ok := document[LegacySection]
	if !ok {
		return false, ""
	}
	section, ok := raw.(map[string]any)
	if !ok {
		return false, ""
	}
	var fence map[string]any
	if existing, ok := document[ConfigKey].(map[string]any); ok {
		fence = existing
	} else {
		fence = map[string]any{}
	}
	moved := []string{}
	for _, key := range legacyKeys {
		if value, ok := section[key]; ok {
			if _, taken := fence[key]; !taken {
				fence[key] = value
			}
			delete(section, key)
			moved = append(moved, key)
		}
	}
	if provider, ok := section["provider"].(string); ok && legacyProviders[provider] {
		if _, taken := fence["provider"]; !taken {
			fence["provider"] = provider
		}
		delete(section, "provider")
		moved = append(moved, "provider")
	}
	if len(moved) == 0 {
		return false, ""
	}
	document[ConfigKey] = fence
	if len(section) == 0 {
		delete(document, LegacySection)
	}
	return true, "guardrail 节的判定键（" + strings.Join(moved, "、") + "）已迁到 fence 节（内存态，保存时落盘）"
}
