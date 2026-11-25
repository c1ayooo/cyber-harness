package sessionexec

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/c1ayooo/cyber/agent"
	provider "github.com/c1ayooo/cyber/agent/provider"
	"github.com/c1ayooo/cyber/agent/session"
	"github.com/c1ayooo/cyber/agent/subagent"
	aop "github.com/c1ayooo/cyber/aop"
	coreevents "github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/hooks"
	coretool "github.com/c1ayooo/cyber/core/tool"
	loopext "github.com/c1ayooo/cyber/exts/agent"
	promptext "github.com/c1ayooo/cyber/exts/prompt"
	sessionext "github.com/c1ayooo/cyber/exts/session"
	"github.com/c1ayooo/cyber/pkg/testutil/apptest"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
)

type testTool struct {
	*Tool
	registry     *subagent.Registry
	closeRuntime func(context.Context) error
}

func newSubagentTestTool(t *testing.T, cfg agent.Config) *testTool {
	t.Helper()
	base := cfg.Lifetime
	if base == nil {
		base = t.Context()
	}
	stream, _ := cfg.Bus.(*coreevents.Stream)
	application := apptest.NewFixture(t, cfg.Logger, stream)
	application.Providers.Set(cfg.Provider, provider.ProviderConfig{Model: cfg.Model})
	values := apptest.Entries(t, application)
	registry := cfg.Hooks
	if registry == nil {
		registry = hooks.New()
	}
	values[0] = extension.Provided[*hooks.Registry](registry)
	loop := cfg.Loop
	if loop == nil {
		loop = agent.NoLoop()
	}
	se := sessionext.New(session.Config{})
	values = append(values, promptext.New(), loopext.New(loop), se)
	hosttest.Load(t, t.Context(), values...)
	rt := se.Runtime()
	if _, err := rt.OpenSession(base, session.SessionOptions{ID: cfg.SessionID, SingleTask: true}); err != nil {
		t.Fatal(err)
	}
	definitions := subagent.NewRegistry()
	if err := definitions.Activate(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := definitions.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	tool := New(rt, definitions, base)
	t.Cleanup(func() {
		if err := tool.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return &testTool{Tool: tool, registry: definitions, closeRuntime: se.Close}
}

type scriptedProvider struct {
	mu        sync.Mutex
	responses []*provider.ChatCompletionResponse
	requests  []*provider.ChatCompletionRequest
}

func (p *scriptedProvider) Name() string { return "scripted" }
func (p *scriptedProvider) ChatCompletion(_ context.Context, req *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, req)
	if len(p.responses) == 0 {
		return nil, fmt.Errorf("no scripted response left")
	}
	response := p.responses[0]
	p.responses = p.responses[1:]
	return response, nil
}
func (p *scriptedProvider) requestsSnapshot() []*provider.ChatCompletionRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*provider.ChatCompletionRequest(nil), p.requests...)
}
func chatResponse(msg *aop.Message) *provider.ChatCompletionResponse {
	return &provider.ChatCompletionResponse{Choices: []provider.Choice{{Message: msg}}}
}
func newTestTools(t testing.TB, tools ...coretool.Tool) coretool.Executor {
	return hosttest.Tools(t, tools...)
}

type callbackProvider struct {
	fn func(context.Context, *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error)
}

func (p *callbackProvider) Name() string { return "callback" }
func (p *callbackProvider) ChatCompletion(ctx context.Context, req *provider.ChatCompletionRequest) (*provider.ChatCompletionResponse, error) {
	return p.fn(ctx, req)
}

func newTextMessage(role, text string) *aop.Message {
	return &aop.Message{Role: role, Content: []*aop.Content{aop.Text(text)}}
}
