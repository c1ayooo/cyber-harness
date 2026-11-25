// Package guardrail implements tool admission as an optional extension over
// pluggable policy providers (JEV, an OpenAI-compatible judge, or a hybrid of
// both). It has no dependency on Reflex declaration or execution.
package guardrail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	jevapi "github.com/c1ayooo/cyber/agent/provider/jev"
	"github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/hooks"
	"github.com/c1ayooo/cyber/core/operation"
	"github.com/c1ayooo/cyber/core/resource"
	toolhooks "github.com/c1ayooo/cyber/core/tool/hooks"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	"google.golang.org/protobuf/proto"
)

const ConfigKey = "guardrail"

// Provider selects the admission judge. The empty value keeps the historical
// "none" default so an omitted section installs no policy.
const (
	ProviderNone   = "none"
	ProviderJEV    = "jev"
	ProviderLLM    = "llm"
	ProviderHybrid = "hybrid"
)

type Config struct {
	Provider      string    `config:"provider" json:"provider" description:"none (default), jev, llm or hybrid"`
	JEV           JEVConfig `config:"jev" json:"jev"`
	Mode          Mode      `config:"mode" json:"mode" description:"auto asks the policy provider to assess consequences (default); safe asks a human; screening always applies"`
	ReviewTimeout string    `config:"review_timeout" json:"review_timeout" description:"Maximum wait for tool approval (default 5m)"`
	// Scope limits judgment to the named tools. Empty means every tool call.
	Scope []string `config:"scope" json:"scope" description:"Only judge these tool names (default all); for example bash and subagent"`
	// AllowPrefixes is a deterministic safe-mode allow list matched against the
	// tool's command text. It is intentionally not a semantic classifier.
	AllowPrefixes []string  `config:"allow_prefixes" json:"allow_prefixes" description:"safe mode only: literal command prefixes that bypass human review"`
	OnError       string    `config:"on_error" json:"on_error" description:"llm/hybrid only: allow, review (default) or block when the judge fails"`
	Timeout       string    `config:"timeout" json:"timeout" description:"llm judge request timeout (default 3s)"`
	Concurrency   int       `config:"concurrency" json:"concurrency" description:"llm judge maximum concurrent requests (default 8)"`
	Shadow        bool      `config:"shadow" json:"shadow" description:"observe and record judgments, always allow execution"`
	LLM           LLMConfig `config:"llm" json:"llm" description:"OpenAI-compatible judge used by provider llm and hybrid"`
}

// defaults applies the documented defaults without mutating the caller's copy.
func (c Config) defaults() Config {
	if c.Mode == "" {
		c.Mode = ModeAuto
	}
	if c.ReviewTimeout == "" {
		c.ReviewTimeout = "5m"
	}
	if c.Timeout == "" {
		c.Timeout = "3s"
	}
	if c.Concurrency == 0 {
		c.Concurrency = defaultLLMConcurrency
	}
	if c.OnError == "" && (c.Provider == ProviderLLM || c.Provider == ProviderHybrid) {
		c.OnError = "review"
	}
	c.Scope = normalizeList(c.Scope)
	c.LLM = c.LLM.defaults()
	return c
}

// normalizeList trims entries and drops empty ones from a name list.
func normalizeList(values []string) []string {
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

// validate checks every field of the section and returns a readable Chinese
// reason. It runs both when configuration is resolved and when an Extension is
// constructed directly.
func (c Config) validate() error {
	original := c
	c = c.defaults()
	switch c.Provider {
	case "", ProviderNone, ProviderJEV, ProviderLLM, ProviderHybrid:
	default:
		return fmt.Errorf("guardrail provider 必须是 none、jev、llm 或 hybrid，当前为 %q", original.Provider)
	}
	if err := c.JEV.validate(); err != nil {
		return err
	}
	if c.Mode != ModeSafe && c.Mode != ModeAuto {
		return fmt.Errorf("guardrail mode 必须是 safe 或 auto，当前为 %q", c.Mode)
	}
	for _, name := range original.Scope {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("guardrail scope 中的工具名不能为空")
		}
	}
	if len(original.AllowPrefixes) > 0 {
		if c.Mode != ModeSafe {
			return fmt.Errorf("guardrail allow_prefixes 仅在 mode=safe 时生效，请将 mode 设为 safe")
		}
		for _, prefix := range original.AllowPrefixes {
			if strings.TrimSpace(prefix) == "" {
				return fmt.Errorf("guardrail allow_prefixes 不能包含空字符串前缀")
			}
		}
	}
	switch c.OnError {
	case "":
		// Defaults fill llm/hybrid; empty remains valid for none/jev.
	case "allow", "review", "block":
	default:
		return fmt.Errorf("guardrail on_error 必须是 allow、review 或 block，当前为 %q", c.OnError)
	}
	if c.OnError != "" && c.Provider != ProviderLLM && c.Provider != ProviderHybrid {
		return fmt.Errorf("guardrail on_error 仅适用于 provider=llm 或 provider=hybrid")
	}
	if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
		return fmt.Errorf("guardrail timeout 必须是正 duration，例如 3s，当前为 %q", c.Timeout)
	}
	if c.Concurrency < 1 || c.Concurrency > 1024 {
		return fmt.Errorf("guardrail concurrency 必须在 1 到 1024 之间，当前为 %d", c.Concurrency)
	}
	return c.LLM.validate(c.Provider)
}

// timeout returns the human review timeout. It keeps the original method name
// because configuration validation historically ran through it.
func (c Config) timeout() (time.Duration, error) {
	if err := c.validate(); err != nil {
		return 0, err
	}
	c = c.defaults()
	d, err := time.ParseDuration(c.ReviewTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("guardrail review_timeout 必须是正 duration，例如 5m，当前为 %q", c.ReviewTimeout)
	}
	return d, nil
}

func (c Config) llmTimeout() time.Duration {
	c = c.defaults()
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

func Declare(resources *resource.Registry) error {
	_, err := resource.Add[cfg.Section](resources, cfg.Section{
		Key: ConfigKey, New: func() any {
			return &Config{Mode: ModeAuto, ReviewTimeout: "5m", Timeout: "3s", Concurrency: defaultLLMConcurrency, LLM: LLMConfig{MaxTokens: defaultLLMMaxTokens}}
		},
		Secrets: []string{"llm.api_key"},
		Validate: func(v any) error {
			_, err := v.(*Config).timeout()
			return err
		},
	})
	return err
}

type Extension struct {
	config  Config
	runtime *Runtime
	before  *hooks.Subscription
}

func New(config Config) *Extension { return &Extension{config: config} }

// usageEmitterJEV and usageEmitterLLM tag referee token usage by judge. The
// ledger classifies both as guardrail (referee) cost while still separating the
// JEV vendor from the OpenAI-compatible judge. The JEV emitter keeps its
// historical value for old control planes.
const (
	usageEmitterJEV = "guardrail"
	usageEmitterLLM = "guardrail-llm"
)

// policy builds the selected judge. It is deliberately tiny: every provider
// owns its transport and failure handling behind the Policy interface.
func (e *Extension) policy(config Config, scope *extension.Scope, stream *events.Stream) (Policy, error) {
	switch config.Provider {
	case ProviderJEV, ProviderHybrid:
		client, err := extension.Use[*jevapi.Client](scope)
		if err != nil {
			return nil, err
		}
		jev := newJEVPolicy(config.JEV, client)
		jev.reportUsage = usageReporter(stream, usageEmitterJEV)
		if config.Provider == ProviderJEV {
			return jev, nil
		}
		// Hybrid keeps two independent reporters: the LLM stage reports its own
		// request usage and JEV reports its own, never merged into one event.
		llm := newLLMPolicy(config.LLM, config.OnError, config.llmTimeout(), config.Concurrency)
		llm.reportUsage = usageReporter(stream, usageEmitterLLM)
		return newHybridPolicy(llm, jev), nil
	case ProviderLLM:
		llm := newLLMPolicy(config.LLM, config.OnError, config.llmTimeout(), config.Concurrency)
		llm.reportUsage = usageReporter(stream, usageEmitterLLM)
		return llm, nil
	default:
		return nil, nil
	}
}

// usageReporter publishes vendor token usage as an AOP usage fact under one
// emitter. Missing usage stays missing: the canonical event is only emitted for
// real data.
func usageReporter(stream *events.Stream, emitter string) func(context.Context, *aop.TokenUsage) {
	if stream == nil {
		return nil
	}
	return func(ctx context.Context, usage *aop.TokenUsage) {
		if usage == nil {
			return
		}
		invocation := operation.InvocationFromContext(ctx)
		stream.Publish(&aop.Event{SessionId: invocation.SessionID, TurnId: invocation.TurnID, Emitter: emitter,
			Payload: &aop.Event_Usage{Usage: proto.Clone(usage).(*aop.TokenUsage)}})
	}
}

func (e *Extension) Load(scope *extension.Scope) error {
	timeout, err := e.config.timeout()
	if err != nil {
		return err
	}
	config := e.config.defaults()
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	policy, err := e.policy(config, scope, stream)
	if err != nil {
		return err
	}
	if config.OnError == "allow" && (config.Provider == ProviderLLM || config.Provider == ProviderHybrid) {
		slog.Warn("guardrail is fail-open: on_error=allow lets tool calls execute when the LLM judge fails", "provider", config.Provider, "model", config.LLM.Model)
	}
	options := runtimeOptions{timeout: timeout, mode: config.Mode, scope: config.Scope, allowPrefixes: config.AllowPrefixes, shadow: config.Shadow}
	if policy == nil {
		// Provider none keeps the function-level seam so the historical disabled
		// runtime and its direct tests remain unchanged.
		e.runtime = newRuntime(scope.Lifetime(), stream, timeout, config.Mode, nil, nil)
		e.runtime.configure(options.scope, options.allowPrefixes, options.shadow)
	} else {
		e.runtime = newRuntimeWithPolicy(scope.Lifetime(), stream, options, policy)
	}
	e.before = toolhooks.Before.On(registry, "guardrail", e.runtime.Admit)
	return extension.Provide[*Runtime](scope, e.runtime)
}

func (e *Extension) Close(ctx context.Context) error {
	// Close the runtime before unregistering the gate, canceling waiters/checks
	// while every remaining invocation still sees a closed admission boundary.
	if e.runtime != nil {
		if err := e.runtime.Close(ctx); err != nil {
			return errors.Join(extension.ErrCloseIncomplete, err)
		}
	}
	if e.before != nil {
		return e.before.Close(ctx)
	}
	return nil
}

var _ extension.Extension = (*Extension)(nil)

// LLMConfig is the OpenAI-compatible judge endpoint. The API key is optional so
// local gateways that do not authenticate remain usable.
type LLMConfig struct {
	BaseURL     string  `config:"base_url" json:"base_url" description:"OpenAI-compatible base URL, for example https://api.openai.com/v1"`
	Model       string  `config:"model" json:"model" description:"Judge model name"`
	APIKey      string  `config:"api_key" json:"api_key" description:"Optional bearer token for the judge endpoint"`
	Temperature float64 `config:"temperature" json:"temperature" description:"Judge sampling temperature (default 0)"`
	MaxTokens   int     `config:"max_tokens" json:"max_tokens" description:"Judge output token limit (default 128)"`
}

func (c LLMConfig) defaults() LLMConfig {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Model = strings.TrimSpace(c.Model)
	if c.MaxTokens == 0 {
		c.MaxTokens = defaultLLMMaxTokens
	}
	return c
}

func (c LLMConfig) validate(provider string) error {
	if provider != ProviderLLM && provider != ProviderHybrid {
		if c.BaseURL != "" || c.Model != "" || c.APIKey != "" || c.Temperature != 0 {
			return fmt.Errorf("guardrail.llm 仅在 provider=llm 或 provider=hybrid 时生效")
		}
		return nil
	}
	if c.BaseURL == "" {
		return fmt.Errorf("guardrail.llm.base_url 是 provider=llm/hybrid 的必填项")
	}
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("guardrail.llm.base_url 必须是 http(s) 地址，当前为 %q", c.BaseURL)
	}
	if c.Model == "" {
		return fmt.Errorf("guardrail.llm.model 是 provider=llm/hybrid 的必填项")
	}
	if c.Temperature < 0 || c.Temperature > 2 {
		return fmt.Errorf("guardrail.llm.temperature 必须在 0 到 2 之间，当前为 %v", c.Temperature)
	}
	if c.MaxTokens < 1 || c.MaxTokens > 4096 {
		return fmt.Errorf("guardrail.llm.max_tokens 必须在 1 到 4096 之间，当前为 %d", c.MaxTokens)
	}
	return nil
}
