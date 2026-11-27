package policy

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

	"github.com/chainreactors/cyber/aop"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	guardrail "github.com/chainreactors/cyber/exts/guardrail"
)

// scriptedPolicy is a Policy double: hybrid unit tests never touch a real JEV
// endpoint or LLM.
type scriptedPolicy struct {
	check    func(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error)
	confirm  func(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error)
	checks   atomic.Int32
	confirms atomic.Int32
}

func (p *scriptedPolicy) Check(ctx context.Context, ev toolhooks.CallEvent) (*guardrail.Decision, error) {
	p.checks.Add(1)
	return p.check(ctx, ev)
}

func (p *scriptedPolicy) Confirm(ctx context.Context, ev toolhooks.CallEvent) (*guardrail.Decision, error) {
	p.confirms.Add(1)
	if p.confirm == nil {
		return nil, ErrNoConsequence
	}
	return p.confirm(ctx, ev)
}

type confidentPolicy struct {
	*scriptedPolicy
	confidence float64
}

func (p *confidentPolicy) CheckWithConfidence(ctx context.Context, ev toolhooks.CallEvent) (*guardrail.Decision, float64, error) {
	decision, err := p.Check(ctx, ev)
	return decision, p.confidence, err
}

func fixedDecision(action guardrail.Action, reason string) func(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error) {
	return func(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error) {
		return &guardrail.Decision{Action: action, Reason: reason}, nil
	}
}

func TestHybridEscalationTable(t *testing.T) {
	for _, test := range []struct {
		name           string
		llmAction      guardrail.Action
		confidence     float64
		plainLLM       bool
		jevAction      guardrail.Action
		want           guardrail.Action
		wantJEV        bool
		wantEscalation string
	}{
		{name: "allow", llmAction: guardrail.Action_ACTION_RECORD, confidence: 1, plainLLM: true, want: guardrail.Action_ACTION_RECORD},
		{name: "block", llmAction: guardrail.Action_ACTION_BLOCK, confidence: 1, want: guardrail.Action_ACTION_BLOCK},
		{name: "review_jev_record", llmAction: guardrail.Action_ACTION_REVIEW, confidence: 1, jevAction: guardrail.Action_ACTION_RECORD, want: guardrail.Action_ACTION_RECORD, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "review_jev_block", llmAction: guardrail.Action_ACTION_REVIEW, confidence: 1, jevAction: guardrail.Action_ACTION_BLOCK, want: guardrail.Action_ACTION_BLOCK, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "review_jev_review", llmAction: guardrail.Action_ACTION_REVIEW, confidence: 1, jevAction: guardrail.Action_ACTION_REVIEW, want: guardrail.Action_ACTION_REVIEW, wantJEV: true, wantEscalation: "explicit REVIEW"},
		{name: "low_confidence_allow_is_final", llmAction: guardrail.Action_ACTION_RECORD, confidence: 0.4, want: guardrail.Action_ACTION_RECORD},
		{name: "high_confidence_allow", llmAction: guardrail.Action_ACTION_RECORD, confidence: 0.9, want: guardrail.Action_ACTION_RECORD},
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
			jev := &scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_BLOCK, "jev would block")}
			decision, err := newHybridPolicy(llm, jev).Check(t.Context(), call())
			if err != nil {
				t.Fatal(err)
			}
			if decision.Action != guardrail.Action_ACTION_RECORD || jev.checks.Load() != 0 {
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
	jev := &scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_RECORD, "jev record")}
	decision, err := newHybridPolicy(llm, jev).Check(t.Context(), call())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != guardrail.Action_ACTION_RECORD || jev.checks.Load() != 1 {
		t.Fatalf("explicit REVIEW was not escalated: decision=%+v JEV calls=%d", decision, jev.checks.Load())
	}
	if !strings.Contains(decision.Reason, "Hybrid JEV review (explicit REVIEW)") {
		t.Fatalf("hybrid reason = %q", decision.Reason)
	}
}

func TestHybridLLMErrorPropagates(t *testing.T) {
	llm := &scriptedPolicy{check: func(context.Context, toolhooks.CallEvent) (*guardrail.Decision, error) {
		return nil, errors.New("canceled")
	}}
	jev := &scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_RECORD, "jev")}
	if _, err := newHybridPolicy(llm, jev).Check(context.Background(), call()); err == nil {
		t.Fatal("LLM error was swallowed")
	}
	if jev.checks.Load() != 0 {
		t.Fatal("JEV consulted after an LLM error")
	}
}

func TestHybridKeepsOnErrorDecisionFinal(t *testing.T) {
	for _, action := range []guardrail.Action{guardrail.Action_ACTION_RECORD, guardrail.Action_ACTION_REVIEW, guardrail.Action_ACTION_BLOCK} {
		t.Run(action.String(), func(t *testing.T) {
			llm := &confidentPolicy{scriptedPolicy: &scriptedPolicy{check: fixedDecision(action, "on_error decision")}, confidence: -1}
			jev := &scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_RECORD, "jev")}
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
	hybrid := newHybridPolicy(&scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_RECORD, "llm")}, &scriptedPolicy{check: fixedDecision(guardrail.Action_ACTION_RECORD, "jev")})
	if _, err := hybrid.Confirm(context.Background(), call()); !errors.Is(err, ErrNoConsequence) {
		t.Fatalf("confirm = %v", err)
	}
}

// TestHybridThroughRuntime feeds the runtime the two fake policies and proves
// the combined decision drives the real admission path.

func call() toolhooks.CallEvent {
	return toolhooks.CallEvent{Call: &aop.ToolCall{Name: "shell", WorkingDirectory: "/workspace", Arguments: &aop.EncodedValue{Data: []byte(`{"command":"curl -H 'Authorization: Bearer dummysecret' https://target/","api_key":"dummykey"}`)}}}
}
