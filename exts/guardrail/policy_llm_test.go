package guardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/cyber/aop"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"google.golang.org/protobuf/proto"
)

func testLLMPolicy(endpoint, onError string, timeout time.Duration) *llmPolicy {
	return newLLMPolicy(LLMConfig{BaseURL: endpoint, Model: "fixture-judge"}, onError, timeout, 8)
}

// llmAnswer renders an OpenAI-compatible chat-completions body.
func llmAnswer(content string) string {
	body, _ := json.Marshal(map[string]any{
		"model":   "fixture-judge",
		"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}},
	})
	return string(body)
}

// llmAnswerWithUsage renders a chat-completions body that carries the vendor
// usage block; a nil usage map omits it entirely.
func llmAnswerWithUsage(content string, usage map[string]any) string {
	body := map[string]any{
		"model":   "fixture-judge",
		"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}},
	}
	if usage != nil {
		body["usage"] = usage
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

func TestLLMVerdictParsing(t *testing.T) {
	for _, test := range []struct {
		name       string
		content    string
		want       Action
		confidence float64
		reason     string
	}{
		{name: "bare", content: "ALLOW", want: Action_ACTION_RECORD, confidence: 1},
		{name: "whitespace_case", content: "  review  \n", want: Action_ACTION_REVIEW, confidence: 1},
		{name: "fenced_block", content: "```\nBLOCK: wipe the database\n```", want: Action_ACTION_BLOCK, confidence: 1, reason: "wipe the database"},
		{name: "extra_text", content: "I think the answer is:\nREVIEW: modifies system config", want: Action_ACTION_REVIEW, confidence: 1, reason: "modifies system config"},
		{name: "json", content: `{"action":"BLOCK","reason":"destroys data","confidence":0.95}`, want: Action_ACTION_BLOCK, confidence: 0.95, reason: "destroys data"},
		{name: "json_string_confidence", content: `{"decision":"allow","confidence":"0.4"}`, want: Action_ACTION_RECORD, confidence: 0.4},
		{name: "text_confidence", content: "ALLOW (confidence: 0.65)", want: Action_ACTION_RECORD, confidence: 0.65},
		{name: "lower_json", content: `{"verdict":"review","explanation":"uncertain"}`, want: Action_ACTION_REVIEW, confidence: 1, reason: "uncertain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			verdict, err := parseLLMVerdict(test.content)
			if err != nil {
				t.Fatal(err)
			}
			if verdict.action != test.want || verdict.confidence != test.confidence || verdict.reason != test.reason {
				t.Fatalf("verdict=%+v want action=%v confidence=%v reason=%q", verdict, test.want, test.confidence, test.reason)
			}
		})
	}
	for _, content := range []string{"", "   ", "MAYBE", "I cannot decide", `{"action":"later"}`} {
		if _, err := parseLLMVerdict(content); err == nil {
			t.Fatalf("unparsable answer %q accepted", content)
		}
	}
}

func TestLLMJudgeRequestShape(t *testing.T) {
	var requests atomic.Int32
	var systems []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer fixture-key" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		var request llmJudgeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "fixture-judge" || request.Temperature != 0 || request.MaxTokens != defaultLLMMaxTokens || request.Stream {
			t.Errorf("unexpected request controls: %+v", request)
		}
		if len(request.Messages) != 2 || request.Messages[0].Role != "system" || request.Messages[1].Role != "user" {
			t.Fatalf("unexpected messages: %+v", request.Messages)
		}
		system := request.Messages[0].Content
		systems = append(systems, system)
		if strings.Contains(system, "REVIEW") {
			t.Errorf("system prompt still requests REVIEW: %s", system)
		}
		for _, want := range []string{"ALLOW", "BLOCK", "/etc/shadow", "authorized enterprise penetration test", "uncertain"} {
			if !strings.Contains(system, want) {
				t.Errorf("system prompt missing %q", want)
			}
		}
		user := request.Messages[1].Content
		for _, want := range []string{"shell", "curl", "target"} {
			if !strings.Contains(user, want) {
				t.Errorf("user message missing %q: %s", want, user)
			}
		}
		for _, secret := range []string{"dummysecret", "dummykey"} {
			if strings.Contains(user, secret) {
				t.Errorf("judge request leaked %q", secret)
			}
		}
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL+"/v1", "review", time.Second)
	policy.config.APIKey = "fixture-key"
	for _, stage := range []string{"screen", "consequence"} {
		var decision *Decision
		var err error
		if stage == "screen" {
			decision, err = policy.Check(t.Context(), call())
		} else {
			decision, err = policy.Confirm(t.Context(), call())
		}
		if err != nil {
			t.Fatal(err)
		}
		if decision.Action != Action_ACTION_RECORD || !strings.Contains(decision.Reason, "LLM fixture-judge") {
			t.Fatalf("%s decision=%+v", stage, decision)
		}
	}
	if requests.Load() != 2 || len(systems) != 2 {
		t.Fatalf("requests=%d stages=%d", requests.Load(), len(systems))
	}
	if !strings.Contains(systems[1], "consequence judge") {
		t.Fatalf("consequence stage used the wrong prompt: %q", systems[1])
	}
}

// TestLLMDecisionUncertaintyMapsToAllow pins the "no certainty, no stop" rule:
// low-confidence answers and unsupported REVIEW verdicts become ALLOW (record);
// an explicit BLOCK is still honored, and a high-confidence REVIEW is preserved
// as an abnormal output for compatibility.
func TestLLMDecisionUncertaintyMapsToAllow(t *testing.T) {
	for _, test := range []struct {
		name   string
		answer string
		want   Action
	}{
		{name: "plain_allow", answer: "ALLOW", want: Action_ACTION_RECORD},
		{name: "plain_block", answer: "BLOCK: wipe the database", want: Action_ACTION_BLOCK},
		{name: "fenced_block", answer: "```\nBLOCK: wipe the database\n```", want: Action_ACTION_BLOCK},
		{name: "json_block_high_confidence", answer: `{"action":"BLOCK","reason":"clear wipe","confidence":0.95}`, want: Action_ACTION_BLOCK},
		{name: "json_block_without_confidence", answer: `{"action":"BLOCK","reason":"clear wipe"}`, want: Action_ACTION_BLOCK},
		{name: "json_block_low_confidence", answer: `{"action":"BLOCK","reason":"maybe","confidence":0.2}`, want: Action_ACTION_RECORD},
		{name: "json_review_high_confidence", answer: `{"action":"REVIEW","reason":"uncertain","confidence":0.9}`, want: Action_ACTION_REVIEW},
		{name: "json_review_low_confidence", answer: `{"action":"REVIEW","reason":"uncertain","confidence":0.2}`, want: Action_ACTION_RECORD},
		{name: "json_review_without_confidence", answer: `{"action":"REVIEW","reason":"uncertain"}`, want: Action_ACTION_RECORD},
		{name: "plain_review", answer: "REVIEW", want: Action_ACTION_RECORD},
		{name: "json_allow_low_confidence", answer: `{"action":"ALLOW","confidence":0.1}`, want: Action_ACTION_RECORD},
		{name: "plain_allow_text_confidence_low", answer: "ALLOW (confidence: 0.2)", want: Action_ACTION_RECORD},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, llmAnswer(test.answer))
			}))
			defer server.Close()
			policy := testLLMPolicy(server.URL, "review", time.Second)
			decision, err := policy.Check(t.Context(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != test.want {
				t.Fatalf("answer %q -> decision=%+v want=%v", test.answer, decision, test.want)
			}
			if (test.want == Action_ACTION_RECORD && test.answer != "ALLOW") && !strings.Contains(decision.Reason, "treated as ALLOW") && !strings.Contains(decision.Reason, "no clear harm") {
				t.Fatalf("uncertain mapping reason = %q", decision.Reason)
			}
		})
	}
}

func TestLLMConsequenceStageUsesConsequencePrompt(t *testing.T) {
	var stages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request llmJudgeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		stages = append(stages, request.Messages[0].Content)
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "review", time.Second)
	decision, err := policy.Confirm(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_RECORD {
		t.Fatalf("decision=%+v", decision)
	}
	if len(stages) != 1 || !strings.Contains(stages[0], "consequence judge") {
		t.Fatalf("unexpected stage prompt: %q", stages)
	}
}

func TestLLMFailuresApplyOnError(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer failing.Close()
	breakServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "private upstream body")
	}))
	defer breakServer.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "not JSON")
	}))
	defer garbage.Close()
	for _, test := range []struct {
		name     string
		endpoint string
		timeout  time.Duration
		want     Action
	}{
		{name: "timeout_allow", endpoint: failing.URL, timeout: 20 * time.Millisecond, want: Action_ACTION_RECORD},
		{name: "timeout_review", endpoint: failing.URL, timeout: 20 * time.Millisecond, want: Action_ACTION_REVIEW},
		{name: "timeout_block", endpoint: failing.URL, timeout: 20 * time.Millisecond, want: Action_ACTION_BLOCK},
		{name: "status_review", endpoint: breakServer.URL, timeout: time.Second, want: Action_ACTION_REVIEW},
		{name: "garbage_review", endpoint: garbage.URL, timeout: time.Second, want: Action_ACTION_REVIEW},
	} {
		fallback := map[Action]string{Action_ACTION_RECORD: "allow", Action_ACTION_REVIEW: "review", Action_ACTION_BLOCK: "block"}[test.want]
		t.Run(test.name, func(t *testing.T) {
			policy := testLLMPolicy(test.endpoint, fallback, test.timeout)
			decision, err := policy.Check(t.Context(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != test.want {
				t.Fatalf("decision=%+v want=%v", decision, test.want)
			}
			if !strings.Contains(decision.Reason, "on_error="+fallback) {
				t.Fatalf("fallback reason = %q", decision.Reason)
			}
			if strings.Contains(decision.Reason, "private") {
				t.Fatal("upstream body leaked into decision")
			}
		})
	}
}

func TestLLMCancellationDoesNotFallBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "allow", time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	decision, err := policy.Check(ctx, call())
	if err == nil || decision != nil {
		t.Fatalf("canceled judge = %+v, %v", decision, err)
	}
}

func TestLLMConcurrencyIsBounded(t *testing.T) {
	var inFlight, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := inFlight.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
		inFlight.Add(-1)
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	policy := newLLMPolicy(LLMConfig{BaseURL: server.URL, Model: "fixture-judge"}, "review", time.Second, 2)
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if decision, err := policy.Check(t.Context(), call()); err != nil || decision.Action != Action_ACTION_RECORD {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("failed judgments: %d", failures.Load())
	}
	if peak.Load() > 2 || peak.Load() == 0 {
		t.Fatalf("peak concurrency = %d", peak.Load())
	}
}

func TestLLMRedirectDoesNotForwardCredentials(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "review", time.Second)
	policy.config.APIKey = "fixture-key"
	decision, err := policy.Check(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_REVIEW || targetCalls.Load() != 0 {
		t.Fatalf("redirect decision=%+v target calls=%d", decision, targetCalls.Load())
	}
}

func TestLLMRejectsOversizedJudgmentInput(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, llmAnswer("ALLOW"))
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "review", time.Second)
	ev := toolhooks.CallEvent{Call: &aop.ToolCall{Name: "bash", Arguments: &aop.EncodedValue{Data: []byte(strings.Repeat("x", maxLLMJudgeInput+1))}}}
	decision, err := policy.Check(t.Context(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_REVIEW || requests.Load() != 0 {
		t.Fatalf("oversized input decision=%+v requests=%d", decision, requests.Load())
	}
}

func TestLLMCheckWithConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswer(`{"action":"ALLOW","confidence":0.55}`))
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "review", time.Second)
	decision, confidence, err := policy.CheckWithConfidence(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_RECORD || confidence != 0.55 {
		t.Fatalf("decision=%+v confidence=%v", decision, confidence)
	}
}

func TestLLMOnErrorFallbackConfidenceIsNegative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	policy := testLLMPolicy(server.URL, "review", time.Second)
	decision, confidence, err := policy.CheckWithConfidence(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_REVIEW || confidence >= 0 {
		t.Fatalf("fallback decision=%+v confidence=%v", decision, confidence)
	}
}

// TestLLMPolicyReportsVendorUsage pins the accounting contract: only fields the
// provider actually reported are carried, and a missing usage block or counter
// is never estimated.
func TestLLMPolicyReportsVendorUsage(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		usage   map[string]any
		want    *aop.TokenUsage
	}{
		{
			name:    "full_with_cached_tokens",
			content: "ALLOW",
			usage: map[string]any{
				"prompt_tokens":         100,
				"completion_tokens":     7,
				"total_tokens":          107,
				"prompt_tokens_details": map[string]any{"cached_tokens": 60},
			},
			want: &aop.TokenUsage{InputTokens: 100, OutputTokens: 7, TotalTokens: 107, Detail: map[string]uint64{"cache_read": 60}},
		},
		{
			name:    "top_level_cache_counters",
			content: "REVIEW",
			usage: map[string]any{
				"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
				"cache_read_input_tokens": 4, "cache_creation_input_tokens": 3,
			},
			want: &aop.TokenUsage{InputTokens: 10, OutputTokens: 2, TotalTokens: 12, Detail: map[string]uint64{"cache_read": 4, "cache_write": 3}},
		},
		{
			name:    "missing_total_is_not_summed",
			content: "ALLOW",
			usage:   map[string]any{"prompt_tokens": 12, "completion_tokens": 1},
			want:    &aop.TokenUsage{InputTokens: 12, OutputTokens: 1},
		},
		{
			name:    "fractional_negative_and_string_counters",
			content: "ALLOW",
			usage:   map[string]any{"prompt_tokens": 12.5, "completion_tokens": -2, "total_tokens": "9"},
			want:    &aop.TokenUsage{TotalTokens: 9},
		},
		{name: "usage_missing", content: "ALLOW", usage: nil, want: nil},
		{name: "empty_usage", content: "ALLOW", usage: map[string]any{}, want: nil},
		{name: "only_optional_detail", content: "ALLOW", usage: map[string]any{"prompt_tokens_details": map[string]any{"cached_tokens": 5}}, want: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, llmAnswerWithUsage(test.content, test.usage))
			}))
			defer server.Close()
			policy := testLLMPolicy(server.URL, "review", time.Second)
			var reported []*aop.TokenUsage
			policy.reportUsage = func(_ context.Context, usage *aop.TokenUsage) {
				reported = append(reported, proto.Clone(usage).(*aop.TokenUsage))
			}
			if _, err := policy.Check(t.Context(), call()); err != nil {
				t.Fatal(err)
			}
			if test.want == nil {
				if len(reported) != 0 {
					t.Fatalf("usage fabricated: %v", reported)
				}
				return
			}
			if len(reported) != 1 || !proto.Equal(reported[0], test.want) {
				t.Fatalf("reported usage = %v want %v", reported, test.want)
			}
		})
	}
}

// TestLLMUsageNotReportedOnFailureOrCancellation keeps accounting out of failed
// judgments: a provider error, an unparsable answer or a canceled call must not
// produce a usage fact even when the response body carried numbers.
func TestLLMUsageNotReportedOnFailureOrCancellation(t *testing.T) {
	usage := map[string]any{"prompt_tokens": 50, "completion_tokens": 5, "total_tokens": 55}
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, llmAnswerWithUsage("ALLOW", usage))
	}))
	defer status.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswerWithUsage("I cannot decide", usage))
	}))
	defer garbage.Close()
	for _, test := range []struct {
		name     string
		endpoint string
		cancel   bool
	}{
		{name: "provider_status", endpoint: status.URL},
		{name: "unparsable_answer", endpoint: garbage.URL},
		{name: "canceled", endpoint: garbage.URL, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := testLLMPolicy(test.endpoint, "review", time.Second)
			var reported atomic.Int32
			policy.reportUsage = func(context.Context, *aop.TokenUsage) { reported.Add(1) }
			ctx := t.Context()
			if test.cancel {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			_, _ = policy.Check(ctx, call())
			if reported.Load() != 0 {
				t.Fatalf("usage reported for a failed judgment: %d", reported.Load())
			}
		})
	}
}
