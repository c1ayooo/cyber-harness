package guardrail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/hooks"
	toolhooks "github.com/c1ayooo/cyber/core/tool/hooks"
)

// scriptedPolicy is a Policy double: hybrid unit tests never touch a real JEV
// endpoint or LLM.
type scriptedPolicy struct {
	check    func(context.Context, toolhooks.CallEvent) (*Decision, error)
	confirm  func(context.Context, toolhooks.CallEvent) (*Decision, error)
	checks   atomic.Int32
	confirms atomic.Int32
}

func (p *scriptedPolicy) Check(ctx context.Context, ev toolhooks.CallEvent) (*Decision, error) {
	p.checks.Add(1)
	return p.check(ctx, ev)
}

func (p *scriptedPolicy) Confirm(ctx context.Context, ev toolhooks.CallEvent) (*Decision, error) {
	p.confirms.Add(1)
	if p.confirm == nil {
		return nil, errNoConsequence
	}
	return p.confirm(ctx, ev)
}

type confidentPolicy struct {
	*scriptedPolicy
	confidence float64
}

func (p *confidentPolicy) CheckWithConfidence(ctx context.Context, ev toolhooks.CallEvent) (*Decision, float64, error) {
	decision, err := p.Check(ctx, ev)
	return decision, p.confidence, err
}

func fixedDecision(action Action, reason string) func(context.Context, toolhooks.CallEvent) (*Decision, error) {
	return func(context.Context, toolhooks.CallEvent) (*Decision, error) {
		return &Decision{Action: action, Reason: reason}, nil
	}
}

func TestHybridEscalationTable(t *testing.T) {
	for _, test := range []struct {
		name           string
		llmAction      Action
		confidence     float64
		plainLLM       bool
		jevAction      Action
		want           Action
		wantJEV        bool
		wantEscalation string
	}{
		{name: "allow", llmAction: Action_ACTION_RECORD, confidence: 1, plainLLM: true, want: Action_ACTION_RECORD},
		{name: "block", llmAction: Action_ACTION_BLOCK, confidence: 1, want: Action_ACTION_BLOCK},
		{name: "review_jev_record", llmAction: Action_ACTION_REVIEW, confidence: 1, jevAction: Action_ACTION_RECORD, want: Action_ACTION_RECORD, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "review_jev_block", llmAction: Action_ACTION_REVIEW, confidence: 1, jevAction: Action_ACTION_BLOCK, want: Action_ACTION_BLOCK, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "review_jev_review", llmAction: Action_ACTION_REVIEW, confidence: 1, jevAction: Action_ACTION_REVIEW, want: Action_ACTION_REVIEW, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "low_confidence_allow_is_final", llmAction: Action_ACTION_RECORD, confidence: 0.4, want: Action_ACTION_RECORD},
		{name: "high_confidence_allow", llmAction: Action_ACTION_RECORD, confidence: 0.9, want: Action_ACTION_RECORD},
	} {
		t.Run(test.name, func(t *testing.T) {
			llmScripted := &scriptedPolicy{check: fixedDecision(test.llmAction, "llm")}
			jevScripted := &scriptedPolicy{check: fixedDecision(test.jevAction, "jev")}
			var llm Policy = llmScripted
			if !test.plainLLM {
				llm = &confidentPolicy{scriptedPolicy: llmScripted, confidence: test.confidence}
			}
			hybrid := newHybridPolicy(llm, jevScripted)
			decision, err := hybrid.Check(context.Background(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != test.want {
				t.Fatalf("decision=%+v want=%v", decision, test.want)
			}
			if test.wantJEV {
				if jevScripted.checks.Load() != 1 {
					t.Fatalf("JEV calls = %d", jevScripted.checks.Load())
				}
				if !strings.Contains(decision.Reason, "Hybrid JEV review ("+test.wantEscalation+")") || !strings.Contains(decision.Reason, "llm") || !strings.Contains(decision.Reason, "jev") {
					t.Fatalf("hybrid reason = %q", decision.Reason)
				}
			} else if jevScripted.checks.Load() != 0 {
				t.Fatal("JEV consulted without escalation")
			}
		})
	}
}

// TestHybridDoesNotEscalateUncertainLLMAnswers exercises the real llmPolicy
// against a fake OpenAI server plus a fake JEV double: low-confidence or
// unsupported answers must become a final ALLOW and must never consume a JEV
// review.
func TestHybridDoesNotEscalateUncertainLLMAnswers(t *testing.T) {
	for _, answer := range []string{
		"ALLOW",
		`{"action":"ALLOW","confidence":0.3}`,
		`{"action":"REVIEW","confidence":0.2}`,
		"REVIEW",
	} {
		t.Run(answer, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, llmAnswer(answer))
			}))
			defer server.Close()
			llm := testLLMPolicy(server.URL, "review", time.Second)
			jev := &scriptedPolicy{check: fixedDecision(Action_ACTION_BLOCK, "jev would block")}
			decision, err := newHybridPolicy(llm, jev).Check(t.Context(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != Action_ACTION_RECORD || jev.checks.Load() != 0 {
				t.Fatalf("uncertain answer %q escalated: decision=%+v JEV calls=%d", answer, decision, jev.checks.Load())
			}
		})
	}
}

// TestHybridEscalatesExplicitHighConfidenceReview keeps the documented JEV
// escalation path for an explicit, confident REVIEW.
func TestHybridEscalatesExplicitHighConfidenceReview(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, llmAnswer(`{"action":"REVIEW","reason":"maybe","confidence":0.9}`))
	}))
	defer server.Close()
	llm := testLLMPolicy(server.URL, "review", time.Second)
	jev := &scriptedPolicy{check: fixedDecision(Action_ACTION_RECORD, "jev record")}
	decision, err := newHybridPolicy(llm, jev).Check(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != Action_ACTION_RECORD || jev.checks.Load() != 1 {
		t.Fatalf("explicit REVIEW was not escalated: decision=%+v JEV calls=%d", decision, jev.checks.Load())
	}
	if !strings.Contains(decision.Reason, "Hybrid JEV review (explicit REVIEW)") {
		t.Fatalf("hybrid reason = %q", decision.Reason)
	}
}

func TestHybridLLMErrorPropagates(t *testing.T) {
	llm := &scriptedPolicy{check: func(context.Context, toolhooks.CallEvent) (*Decision, error) {
		return nil, errors.New("canceled")
	}}
	jev := &scriptedPolicy{check: fixedDecision(Action_ACTION_RECORD, "jev")}
	if _, err := newHybridPolicy(llm, jev).Check(context.Background(), call()); err == nil {
		t.Fatal("LLM error was swallowed")
	}
	if jev.checks.Load() != 0 {
		t.Fatal("JEV consulted after an LLM error")
	}
}

func TestHybridKeepsOnErrorDecisionFinal(t *testing.T) {
	for _, action := range []Action{Action_ACTION_RECORD, Action_ACTION_REVIEW, Action_ACTION_BLOCK} {
		t.Run(action.String(), func(t *testing.T) {
			llm := &confidentPolicy{scriptedPolicy: &scriptedPolicy{check: fixedDecision(action, "on_error decision")}, confidence: -1}
			jev := &scriptedPolicy{check: fixedDecision(Action_ACTION_RECORD, "jev")}
			decision, err := newHybridPolicy(llm, jev).Check(context.Background(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != action || jev.checks.Load() != 0 {
				t.Fatalf("decision=%+v JEV calls=%d", decision, jev.checks.Load())
			}
		})
	}
}

func TestHybridHasNoConsequenceStage(t *testing.T) {
	hybrid := newHybridPolicy(&scriptedPolicy{check: fixedDecision(Action_ACTION_RECORD, "llm")}, &scriptedPolicy{check: fixedDecision(Action_ACTION_RECORD, "jev")})
	if _, err := hybrid.Confirm(context.Background(), call()); !errors.Is(err, errNoConsequence) {
		t.Fatalf("confirm = %v", err)
	}
}

// TestHybridThroughRuntime feeds the runtime the two fake policies and proves
// the combined decision drives the real admission path.
func TestHybridThroughRuntime(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      Mode
		llmAction Action
		jevAction Action
		executed  bool
	}{
		{name: "safe_review_jev_record", mode: ModeSafe, llmAction: Action_ACTION_REVIEW, jevAction: Action_ACTION_RECORD, executed: true},
		{name: "safe_review_jev_review", mode: ModeSafe, llmAction: Action_ACTION_REVIEW, jevAction: Action_ACTION_REVIEW, executed: false},
		{name: "auto_review_jev_block", mode: ModeAuto, llmAction: Action_ACTION_REVIEW, jevAction: Action_ACTION_BLOCK, executed: false},
		{name: "auto_confident_allow", mode: ModeAuto, llmAction: Action_ACTION_RECORD, jevAction: Action_ACTION_BLOCK, executed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			llm := &scriptedPolicy{check: fixedDecision(test.llmAction, "llm")}
			jev := &scriptedPolicy{check: fixedDecision(test.jevAction, "jev")}
			policy := newHybridPolicy(llm, jev)
			stream := events.New()
			runtime := newRuntimeWithPolicy(t.Context(), stream, runtimeOptions{timeout: time.Second, mode: test.mode}, policy)
			registry := hooks.New()
			sub := toolhooks.Before.On(registry, "guardrail", runtime.Admit)
			defer sub.Cancel()
			defer runtime.Close(t.Context())
			var executed atomic.Int32
			reviews := make(chan *Review, 8)
			stream.Observe(testObserver(func(event *aop.Event) {
				var review Review
				if payload := event.GetExtension(); payload != nil && payload.MessageIs(&review) && payload.UnmarshalTo(&review) == nil {
					reviews <- &review
				}
			}))
			done := make(chan error, 1)
			go func() {
				ctx := callContext()
				_, err := toolhooks.Execute(ctx, registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
					executed.Add(1)
					return &aop.ToolResult{}, nil
				})
				done <- err
			}()
			if test.mode == ModeSafe && !test.executed {
				review := nextReview(t, reviews)
				if err := runtime.Resolve(callContext(), review.Operation.OperationId, false); err != nil {
					t.Fatal(err)
				}
			}
			err := <-done
			if test.executed {
				if err != nil || executed.Load() != 1 {
					t.Fatalf("allowed invocation: err=%v executions=%d", err, executed.Load())
				}
			} else if err == nil || executed.Load() != 0 {
				t.Fatalf("denied invocation ran: err=%v executions=%d", err, executed.Load())
			}
		})
	}
}
