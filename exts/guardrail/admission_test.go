package guardrail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jevapi "github.com/chainreactors/cyber/agent/provider/jev"
	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"google.golang.org/protobuf/proto"
)

func policyFixture(t *testing.T, options runtimeOptions, policy Policy) (*Runtime, *hooks.Registry, *events.Stream) {
	t.Helper()
	stream := events.New()
	runtime := newRuntimeWithPolicy(t.Context(), stream, options, policy)
	registry := hooks.New()
	sub := toolhooks.Before.On(registry, "guardrail", runtime.Admit)
	t.Cleanup(func() {
		sub.Cancel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return runtime, registry, stream
}

func executionCounter() (func(context.Context, string) (*aop.ToolResult, error), *atomic.Int32) {
	var executed atomic.Int32
	return func(context.Context, string) (*aop.ToolResult, error) {
		executed.Add(1)
		return &aop.ToolResult{}, nil
	}, &executed
}

func TestScopeFiltersWithoutCallingPolicy(t *testing.T) {
	policy := &scriptedPolicy{check: fixedDecision(Action_ACTION_BLOCK, "blocked")}
	_, registry, _ := policyFixture(t, runtimeOptions{timeout: time.Second, mode: ModeAuto, scope: []string{"bash"}}, policy)
	run, executed := executionCounter()
	if _, err := toolhooks.Execute(callContext(), registry, "read", `{"path":"README.md"}`, run); err != nil {
		t.Fatalf("out-of-scope tool was judged: %v", err)
	}
	if executed.Load() != 1 || policy.checks.Load() != 0 {
		t.Fatalf("executions=%d policy calls=%d", executed.Load(), policy.checks.Load())
	}
	if _, err := toolhooks.Execute(callContext(), registry, "bash", `{"command":"id"}`, run); !errors.Is(err, operation.ErrDenied) {
		t.Fatalf("in-scope tool bypassed judgment: %v", err)
	}
	if policy.checks.Load() != 1 || executed.Load() != 1 {
		t.Fatalf("policy calls=%d executions=%d", policy.checks.Load(), executed.Load())
	}
}

func TestShadowRecordsJudgmentAndAlwaysAllows(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   Mode
		policy Policy
	}{
		{name: "auto_block", mode: ModeAuto, policy: &scriptedPolicy{check: fixedDecision(Action_ACTION_BLOCK, "shadow block")}},
		{name: "safe_review", mode: ModeSafe, policy: &scriptedPolicy{check: fixedDecision(Action_ACTION_REVIEW, "shadow review")}},
		{name: "invalid_policy", mode: ModeAuto, policy: &scriptedPolicy{check: func(context.Context, toolhooks.CallEvent) (*Decision, error) {
			return nil, errors.New("broken")
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, registry, stream := policyFixture(t, runtimeOptions{timeout: time.Second, mode: test.mode, shadow: true}, test.policy)
			var mu sync.Mutex
			var decisions []Action
			stream.Observe(testObserver(func(event *aop.Event) {
				var decision Decision
				if payload := event.GetExtension(); payload != nil && payload.MessageIs(&decision) && payload.UnmarshalTo(&decision) == nil {
					mu.Lock()
					decisions = append(decisions, decision.Action)
					mu.Unlock()
				}
			}))
			run, executed := executionCounter()
			if _, err := toolhooks.Execute(callContext(), registry, "bash", `{"command":"id"}`, run); err != nil {
				t.Fatalf("shadow judgment blocked execution: %v", err)
			}
			if executed.Load() != 1 {
				t.Fatalf("executions=%d", executed.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			if len(decisions) == 0 {
				t.Fatal("shadow judgment was not recorded")
			}
		})
	}
}

func TestAllowPrefixesReleaseSafeModeCalls(t *testing.T) {
	policy := &scriptedPolicy{check: fixedDecision(Action_ACTION_BLOCK, "flagged")}
	runtime, registry, _ := policyFixture(t, runtimeOptions{timeout: time.Second, mode: ModeSafe, allowPrefixes: []string{"ls "}}, policy)
	run, executed := executionCounter()
	if _, err := toolhooks.Execute(callContext(), registry, "bash", `{"command":"ls -la /tmp"}`, run); err != nil {
		t.Fatalf("allowlisted prefix was not released: %v", err)
	}
	if executed.Load() != 1 {
		t.Fatal("allowlisted call did not execute")
	}
	if len(runtime.Pending("session")) != 0 {
		t.Fatal("allowlisted call created a review")
	}
	// A judged call outside the prefix stays in human review.
	done := make(chan error, 1)
	go func() {
		_, err := toolhooks.Execute(callContext(), registry, "bash", `{"command":"rm -rf /tmp/guarded"}`, run)
		done <- err
	}()
	pending := waitPending(t, runtime)
	if err := runtime.Resolve(callContext(), pending.Operation.OperationId, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, operation.ErrDenied) || executed.Load() != 1 {
		t.Fatalf("non-allowlisted call: err=%v executions=%d", err, executed.Load())
	}
}

func waitPending(t *testing.T, runtime *Runtime) *Review {
	t.Helper()
	for range 200 {
		if pending := runtime.Pending("session"); len(pending) > 0 {
			return pending[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending review missing")
	return nil
}

func TestRuntimeScopeAndShadowSnapshot(t *testing.T) {
	// configure replaces the option sets before admission; unset scope means all.
	runtime := newRuntime(t.Context(), events.New(), time.Second, ModeAuto, nil, nil)
	runtime.configure([]string{" bash ", "", "subagent"}, []string{"ls "}, true)
	defer runtime.Close(t.Context())
	if !runtime.inScope("bash") || !runtime.inScope("subagent") || runtime.inScope("read") || runtime.inScope("") {
		t.Fatal("scope snapshot is wrong")
	}
	if len(runtime.scope) != 2 || !runtime.shadow || len(runtime.allowPrefixes) != 1 {
		t.Fatal("admission options not applied")
	}
	commandCases := map[string]string{
		`{"command":"ls -la"}`:   "ls -la",
		`{"command":" ls -la"}`:  "ls -la",
		`{"script":"echo hi"}`:   "echo hi",
		`"plain arguments"`:      "plain arguments",
		`{"unexpected":"value"}`: `{"unexpected":"value"}`,
		``:                       "",
	}
	for raw, want := range commandCases {
		ev := toolhooks.CallEvent{Call: &aop.ToolCall{Arguments: &aop.EncodedValue{Data: []byte(raw)}}}
		if got := strings.TrimSpace(toolCommandText(ev.Call)); got != want {
			t.Errorf("command text for %q = %q want %q", raw, got, want)
		}
	}
	if !runtime.allowedPrefix(toolhooks.CallEvent{Call: &aop.ToolCall{Arguments: &aop.EncodedValue{Data: []byte(`{"command":"ls -la"}`)}}}) {
		t.Fatal("literal prefix not matched")
	}
	if runtime.allowedPrefix(toolhooks.CallEvent{Call: &aop.ToolCall{Arguments: &aop.EncodedValue{Data: []byte(`{"command":"lsof"}`)}}}) {
		t.Fatal("unrelated command matched")
	}
}

// TestJEVUsageIsReportedAsAOPUsageFact proves the JEV client's response usage
// becomes an AOP usage event, and that a response without usage emits none.
func TestJEVUsageIsReportedAsAOPUsageFact(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      string
		wantUsage bool
	}{
		{name: "usage_present", body: `{"answers":{"action":{"type":"choice","choice":"record"}},"usage":{"input_tokens":20,"output_tokens":3}}`, wantUsage: true},
		{name: "usage_missing", body: `{"answers":{"action":{"type":"choice","choice":"record"}}}`, wantUsage: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			client := jevapi.New("fixture-key", "", time.Second)
			client.Endpoint = server.URL
			defer client.Close()
			stream := events.New()
			registry := hooks.New()
			set, err := extension.New(
				extension.Provided[*events.Stream](stream),
				extension.Provided[*hooks.Registry](registry),
				extension.Provided[*jevapi.Client](client),
				New(Config{Provider: ProviderJEV, Mode: ModeAuto, ReviewTimeout: "1s"}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Load(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer set.Close(t.Context())
			type usageFact struct {
				emitter string
				usage   *aop.TokenUsage
			}
			var mu sync.Mutex
			var facts []usageFact
			stream.Observe(testObserver(func(event *aop.Event) {
				if event.GetUsage() == nil {
					return
				}
				mu.Lock()
				facts = append(facts, usageFact{emitter: event.GetEmitter(), usage: proto.Clone(event.GetUsage()).(*aop.TokenUsage)})
				mu.Unlock()
			}))
			ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{SessionID: "session", TurnID: "turn"})
			executed := 0
			if _, err := toolhooks.Execute(ctx, registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
				executed++
				return &aop.ToolResult{}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if executed != 1 {
				t.Fatal("allowed JEV call did not execute")
			}
			mu.Lock()
			defer mu.Unlock()
			if !test.wantUsage {
				if len(facts) != 0 {
					t.Fatalf("usage fabricated: %+v", facts)
				}
				return
			}
			if len(facts) != 1 || facts[0].emitter != "guardrail" || facts[0].usage.InputTokens != 20 || facts[0].usage.OutputTokens != 3 || facts[0].usage.TotalTokens != 23 {
				t.Fatalf("usage facts = %+v", facts)
			}
		})
	}
}

// usageEvent is one observed AOP usage fact with its accounting envelope.
type usageEvent struct {
	emitter string
	session string
	turn    string
	usage   *aop.TokenUsage
}

// observeUsageEvents subscribes to the stream and returns a snapshot accessor
// for the usage facts published after the call.
func observeUsageEvents(stream *events.Stream) func() []usageEvent {
	var mu sync.Mutex
	var facts []usageEvent
	stream.Observe(testObserver(func(event *aop.Event) {
		usage := event.GetUsage()
		if usage == nil {
			return
		}
		mu.Lock()
		facts = append(facts, usageEvent{emitter: event.GetEmitter(), session: event.GetSessionId(), turn: event.GetTurnId(), usage: proto.Clone(usage).(*aop.TokenUsage)})
		mu.Unlock()
	}))
	return func() []usageEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]usageEvent(nil), facts...)
	}
}

// TestLLMUsageIsReportedAsAOPUsageFact proves the LLM judge's response usage
// becomes an AOP usage event under its own emitter, and a response without
// usage emits none.
func TestLLMUsageIsReportedAsAOPUsageFact(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      string
		wantUsage bool
	}{
		{
			name: "usage_present",
			body: llmAnswerWithUsage("ALLOW", map[string]any{
				"prompt_tokens": 100, "completion_tokens": 7, "total_tokens": 107,
				"prompt_tokens_details": map[string]any{"cached_tokens": 60},
			}),
			wantUsage: true,
		},
		{name: "usage_missing", body: llmAnswer("ALLOW"), wantUsage: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			stream := events.New()
			registry := hooks.New()
			set, err := extension.New(
				extension.Provided[*events.Stream](stream),
				extension.Provided[*hooks.Registry](registry),
				New(Config{Provider: ProviderLLM, Mode: ModeAuto, LLM: LLMConfig{BaseURL: server.URL, Model: "fixture-judge"}}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Load(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer set.Close(t.Context())
			facts := observeUsageEvents(stream)
			ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{SessionID: "session", TurnID: "turn"})
			executed := 0
			if _, err := toolhooks.Execute(ctx, registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
				executed++
				return &aop.ToolResult{}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if executed != 1 {
				t.Fatal("allowed LLM call did not execute")
			}
			got := facts()
			if !test.wantUsage {
				if len(got) != 0 {
					t.Fatalf("usage fabricated: %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("usage facts = %+v", got)
			}
			fact := got[0]
			if fact.emitter != usageEmitterLLM || fact.session != "session" || fact.turn != "turn" {
				t.Fatalf("usage envelope = %+v", fact)
			}
			want := &aop.TokenUsage{InputTokens: 100, OutputTokens: 7, TotalTokens: 107, Detail: map[string]uint64{"cache_read": 60}}
			if !proto.Equal(fact.usage, want) {
				t.Fatalf("usage = %v want %v", fact.usage, want)
			}
		})
	}
}

// TestHybridUsagesKeepTheirJudgeEmitters proves hybrid publishes one event per
// stage under distinct emitters instead of merging the two judges' accounting.
// The JEV stage is a fake HTTP endpoint injected as the client, so no real JEV
// service is involved.
func TestHybridUsagesKeepTheirJudgeEmitters(t *testing.T) {
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswerWithUsage("REVIEW", map[string]any{"prompt_tokens": 100, "completion_tokens": 7, "total_tokens": 107}))
	}))
	defer llmServer.Close()
	jevServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"answers":{"action":{"type":"choice","choice":"record"}},"usage":{"input_tokens":20,"output_tokens":3}}`)
	}))
	defer jevServer.Close()
	client := jevapi.New("fixture-key", "", time.Second)
	client.Endpoint = jevServer.URL
	defer client.Close()
	stream := events.New()
	registry := hooks.New()
	set, err := extension.New(
		extension.Provided[*events.Stream](stream),
		extension.Provided[*hooks.Registry](registry),
		extension.Provided[*jevapi.Client](client),
		New(Config{Provider: ProviderHybrid, Mode: ModeAuto, LLM: LLMConfig{BaseURL: llmServer.URL, Model: "fixture-judge"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer set.Close(t.Context())
	facts := observeUsageEvents(stream)
	ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{SessionID: "session", TurnID: "turn"})
	executed := 0
	if _, err := toolhooks.Execute(ctx, registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
		executed++
		return &aop.ToolResult{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if executed != 1 {
		t.Fatal("hybrid JEV record did not execute")
	}
	got := facts()
	if len(got) != 2 {
		t.Fatalf("hybrid usage facts = %+v", got)
	}
	byEmitter := make(map[string]*aop.TokenUsage, 2)
	for _, fact := range got {
		if fact.session != "session" || fact.turn != "turn" {
			t.Fatalf("usage envelope = %+v", fact)
		}
		byEmitter[fact.emitter] = fact.usage
	}
	llmUsage, llmOK := byEmitter[usageEmitterLLM]
	jevUsage, jevOK := byEmitter[usageEmitterJEV]
	if !llmOK || !jevOK || len(byEmitter) != 2 {
		t.Fatalf("hybrid emitters = %+v", byEmitter)
	}
	if !proto.Equal(llmUsage, &aop.TokenUsage{InputTokens: 100, OutputTokens: 7, TotalTokens: 107}) {
		t.Fatalf("LLM usage = %v", llmUsage)
	}
	if jevUsage.InputTokens != 20 || jevUsage.OutputTokens != 3 || jevUsage.TotalTokens != 23 {
		t.Fatalf("JEV usage = %v", jevUsage)
	}
	if jevUsage.Detail["requests"] != 1 {
		t.Fatalf("JEV usage detail = %v", jevUsage.Detail)
	}
}

// TestLLMProviderExtensionDoesNotRequireJEVClient pins the composition contract:
// provider=llm installs a working policy without any JEV capability.
func TestLLMProviderExtensionDoesNotRequireJEVClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	stream := events.New()
	registry := hooks.New()
	set, err := extension.New(
		extension.Provided[*events.Stream](stream),
		extension.Provided[*hooks.Registry](registry),
		New(Config{Provider: ProviderLLM, Mode: ModeAuto, LLM: LLMConfig{BaseURL: server.URL, Model: "fixture-judge", APIKey: "fixture-key"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer set.Close(t.Context())
	executed := false
	if _, err := toolhooks.Execute(t.Context(), registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
		executed = true
		return &aop.ToolResult{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !executed {
		t.Fatal("LLM ALLOW did not execute")
	}
	// Hybrid always needs the JEV client provided by the composition root.
	hybrid, err := extension.New(
		extension.Provided[*events.Stream](events.New()),
		extension.Provided[*hooks.Registry](hooks.New()),
		New(Config{Provider: ProviderHybrid, LLM: LLMConfig{BaseURL: server.URL, Model: "fixture-judge"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := hybrid.Load(t.Context()); err == nil {
		_ = hybrid.Close(t.Context())
		t.Fatal("hybrid loaded without a JEV client")
	}
}
