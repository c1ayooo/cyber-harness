package policy

import (
	"context"
	"time"

	"github.com/chainreactors/cyber/aop"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
)

// NewLLM builds the OpenAI-compatible judge. reportUsage may be nil: outside
// the extension composition there is no canonical stream to publish on.
func NewLLM(config fenceconfig.LLMConfig, onError string, timeout time.Duration, concurrency int, reportUsage func(context.Context, *aop.TokenUsage)) Policy {
	p := newLLMPolicy(config, onError, timeout, concurrency)
	p.reportUsage = reportUsage
	return p
}

// NewHybrid composes the LLM screen with the JEV escalation. Each stage keeps
// its own usage reporter: the LLM stage reports its own request usage and JEV
// reports its own, never merged into one event.
func NewHybrid(llm, jev Policy) Policy { return newHybridPolicy(llm, jev) }

// SetUsage wires a JEV stage's usage reporter after NewJEV (the hybrid needs
// the two stages' reporters to differ).
func SetUsage(p Policy, report func(context.Context, *aop.TokenUsage)) {
	switch typed := p.(type) {
	case *jevPolicy:
		typed.reportUsage = report
	case *llmPolicy:
		typed.reportUsage = report
	}
}
