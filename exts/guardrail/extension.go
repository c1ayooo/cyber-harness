// Package guardrail implements tool admission as an optional extension over
// pluggable policy providers (JEV, an OpenAI-compatible judge, or a hybrid of
// both). It has no dependency on Reflex declaration or execution.
package guardrail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	jevapi "github.com/chainreactors/cyber/agent/provider/jev"
	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/core/resource"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	cfg "github.com/chainreactors/cyber/pkg/config"
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
	Provider      string    `config:"provider" json:"provider" description:"none (default) or jev; the llm/hybrid judges live in the fence section"`
	JEV           JEVConfig `config:"jev" json:"jev"`
	Mode          Mode      `config:"mode" json:"mode" description:"auto asks the policy provider to assess consequences (default); safe asks a human; screening always applies"`
	ReviewTimeout string    `config:"review_timeout" json:"review_timeout" description:"Maximum wait for tool approval (default 5m)"`
}

// validate keeps the upstream section's rules: the guardrail section names
// the approval queue and its none/jev judge; the fence section (fenceconfig)
// owns the extended judges and their knobs and validates itself.
func (c Config) validate() error {
	switch c.Provider {
	case "", ProviderNone, ProviderJEV:
	default:
		return fmt.Errorf("guardrail provider 必须是 none 或 jev（llm/hybrid 在 fence 节配置），当前为 %q", c.Provider)
	}
	if err := c.JEV.validate(); err != nil {
		return err
	}
	if c.Mode != "" && c.Mode != ModeSafe && c.Mode != ModeAuto {
		return fmt.Errorf("guardrail mode 必须是 safe 或 auto，当前为 %q", c.Mode)
	}
	return nil
}

func (c Config) timeout() (time.Duration, error) {
	if err := c.validate(); err != nil {
		return 0, err
	}
	if c.ReviewTimeout == "" {
		return 5 * time.Minute, nil
	}
	d, err := time.ParseDuration(c.ReviewTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("guardrail review_timeout 必须是正 duration，例如 5m，当前为 %q", c.ReviewTimeout)
	}
	return d, nil
}

func Declare(resources *resource.Registry) error {
	_, err := resource.Add[cfg.Section](resources, cfg.Section{
		Key: ConfigKey, New: func() any { return &Config{Mode: ModeAuto, ReviewTimeout: "5m"} },
		Validate: func(v any) error { _, err := v.(*Config).timeout(); return err },
	})
	return err
}

type Extension struct {
	config  Config
	fence   fenceconfig.Config
	runtime *Runtime
	before  *hooks.Subscription
}

// New builds the extension. The fence config (section fence) carries the
// judge knobs; an empty provider there defers to the guardrail section's own.
func New(config Config, fence fenceconfig.Config) *Extension {
	return &Extension{config: config, fence: fence}
}

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
func (e *Extension) policy(fence fenceconfig.Config, scope *extension.Scope, stream *events.Stream) (Policy, error) {
	// The fence section's provider overrides; empty defers to the guardrail
	// section's own none/jev default.
	provider := fence.Provider
	if provider == "" {
		provider = string(e.config.Provider)
	}
	switch provider {
	case ProviderJEV, ProviderHybrid:
		client, err := extension.Use[*jevapi.Client](scope)
		if err != nil {
			return nil, err
		}
		jev := newJEVPolicy(e.config.JEV, client)
		jev.reportUsage = usageReporter(stream, usageEmitterJEV)
		if fence.Provider == ProviderJEV {
			return jev, nil
		}
		// Hybrid keeps two independent reporters: the LLM stage reports its own
		// request usage and JEV reports its own, never merged into one event.
		llm := newLLMPolicy(fence.LLM, fence.OnError, fence.LLMTimeout(), fence.Concurrency)
		llm.reportUsage = usageReporter(stream, usageEmitterLLM)
		return newHybridPolicy(llm, jev), nil
	case ProviderLLM:
		llm := newLLMPolicy(fence.LLM, fence.OnError, fence.LLMTimeout(), fence.Concurrency)
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
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	fence := e.fence.Defaults()
	if fence.Provider == "" {
		fence.Provider = string(e.config.Provider)
	}
	policy, err := e.policy(fence, scope, stream)
	if err != nil {
		return err
	}
	if fence.OnError == "allow" && (fence.Provider == ProviderLLM || fence.Provider == ProviderHybrid) {
		slog.Warn("guardrail is fail-open: on_error=allow lets tool calls execute when the LLM judge fails", "provider", fence.Provider, "model", fence.LLM.Model)
	}
	options := runtimeOptions{timeout: timeout, mode: e.config.Mode, scope: fence.Scope, allowPrefixes: fence.AllowPrefixes, shadow: fence.Shadow}
	if policy == nil {
		// Provider none keeps the function-level seam so the historical disabled
		// runtime and its direct tests remain unchanged.
		e.runtime = newRuntime(scope.Lifetime(), stream, timeout, e.config.Mode, nil, nil)
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
