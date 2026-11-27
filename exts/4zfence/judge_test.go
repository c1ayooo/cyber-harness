package fence

// The fence judge's admission semantics (ported from the old guardrail
// admission tests, docs/19 E3-3): the scope filter is a routing decision, a
// shadow judgment is recorded but never enforced, a safe-mode allow prefix
// releases a judged call without a human, and the mode routes every other
// risky judgment through the approval lifecycle. The policies are doubles:
// these tests never touch a real JEV endpoint or LLM.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	"github.com/chainreactors/cyber/exts/4zfence/policy"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
)

// scriptedJudge is a policy.Policy double with a call counter.
type scriptedJudge struct {
	check   func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error)
	confirm func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error)
	checks  atomic.Int32
}

func (s *scriptedJudge) Check(ctx context.Context, ev toolhooks.CallEvent) (*guardrailext.Decision, error) {
	s.checks.Add(1)
	return s.check(ctx, ev)
}

func (s *scriptedJudge) Confirm(ctx context.Context, ev toolhooks.CallEvent) (*guardrailext.Decision, error) {
	if s.confirm == nil {
		return nil, policy.ErrNoConsequence
	}
	return s.confirm(ctx, ev)
}

func fixedDecision(action guardrailext.Action, reason string) func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error) {
	return func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error) {
		return &guardrailext.Decision{Action: action, Reason: reason}, nil
	}
}

func judgeCallContext() context.Context {
	return operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "session", CallID: "same-call"})
}

func executionCounter() (func(context.Context, string) (*aop.ToolResult, error), *atomic.Int32) {
	var executed atomic.Int32
	return func(context.Context, string) (*aop.ToolResult, error) {
		executed.Add(1)
		return &aop.ToolResult{}, nil
	}, &executed
}

// judgeFixture builds the fence extension with one judge and its knobs, and
// registers its admit hook on a fresh registry.
func judgeFixture(t *testing.T, cfg fenceconfig.Config, judge policy.Policy) (*Extension, *guardrailext.Runtime, *hooks.Registry, *events.Stream) {
	t.Helper()
	stream := events.New()
	rt := newApprovalRuntime(t, stream)
	e := &Extension{stream: stream, policy: judge, options: newJudgeOptions(cfg.Defaults()), fence: cfg.Defaults()}
	e.Bind(rt)
	registry := hooks.New()
	sub := toolhooks.Before.On(registry, "4zfence", e.admit)
	t.Cleanup(sub.Cancel)
	return e, rt, registry, stream
}

func TestJudgeScopeFiltersWithoutCallingPolicy(t *testing.T) {
	judge := &scriptedJudge{check: fixedDecision(guardrailext.Action_ACTION_BLOCK, "blocked")}
	_, _, registry, _ := judgeFixture(t, fenceconfig.Config{Mode: "auto", Scope: []string{"bash"}}, judge)
	run, executed := executionCounter()
	if _, err := toolhooks.Execute(judgeCallContext(), registry, "read", `{"path":"README.md"}`, run); err != nil {
		t.Fatalf("out-of-scope tool was judged: %v", err)
	}
	if executed.Load() != 1 || judge.checks.Load() != 0 {
		t.Fatalf("executions=%d policy calls=%d", executed.Load(), judge.checks.Load())
	}
	if _, err := toolhooks.Execute(judgeCallContext(), registry, "bash", `{"command":"id"}`, run); !errors.Is(err, operation.ErrDenied) {
		t.Fatalf("in-scope tool bypassed judgment: %v", err)
	}
	if judge.checks.Load() != 1 || executed.Load() != 1 {
		t.Fatalf("policy calls=%d executions=%d", judge.checks.Load(), executed.Load())
	}
}

func TestJudgeShadowRecordsAndAlwaysAllows(t *testing.T) {
	for _, test := range []struct {
		name  string
		mode  string
		judge policy.Policy
	}{
		{name: "auto_block", mode: "auto", judge: &scriptedJudge{check: fixedDecision(guardrailext.Action_ACTION_BLOCK, "shadow block")}},
		{name: "safe_review", mode: "safe", judge: &scriptedJudge{check: fixedDecision(guardrailext.Action_ACTION_REVIEW, "shadow review")}},
		{name: "invalid_policy", mode: "auto", judge: &scriptedJudge{check: func(context.Context, toolhooks.CallEvent) (*guardrailext.Decision, error) {
			return nil, errors.New("broken")
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, registry, stream := judgeFixture(t, fenceconfig.Config{Mode: test.mode, Shadow: true}, test.judge)
			var mu sync.Mutex
			var decisions []guardrailext.Action
			stream.Observe(func(event *aop.Event) {
				var decision guardrailext.Decision
				if payload := event.GetExtension(); payload != nil && payload.MessageIs(&decision) && payload.UnmarshalTo(&decision) == nil {
					mu.Lock()
					decisions = append(decisions, decision.Action)
					mu.Unlock()
				}
			})
			run, executed := executionCounter()
			if _, err := toolhooks.Execute(judgeCallContext(), registry, "bash", `{"command":"id"}`, run); err != nil {
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

func TestJudgeAllowPrefixesReleaseSafeModeCalls(t *testing.T) {
	judge := &scriptedJudge{check: fixedDecision(guardrailext.Action_ACTION_BLOCK, "flagged")}
	e, rt, registry, _ := judgeFixture(t, fenceconfig.Config{Mode: "safe", AllowPrefixes: []string{"ls "}}, judge)
	run, executed := executionCounter()
	if _, err := toolhooks.Execute(judgeCallContext(), registry, "bash", `{"command":"ls -la /tmp"}`, run); err != nil {
		t.Fatalf("allowlisted prefix was not released: %v", err)
	}
	if executed.Load() != 1 {
		t.Fatal("allowlisted call did not execute")
	}
	if len(rt.Pending("session")) != 0 {
		t.Fatal("allowlisted call created a review")
	}
	// A judged call outside the prefix stays in human review.
	done := make(chan error, 1)
	go func() {
		_, err := toolhooks.Execute(judgeCallContext(), registry, "bash", `{"command":"rm -rf /tmp/guarded"}`, run)
		done <- err
	}()
	var pending *guardrailext.Review
	for i := 0; i < 200 && pending == nil; i++ {
		if reviews := rt.Pending("session"); len(reviews) > 0 {
			pending = reviews[0]
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pending == nil {
		t.Fatal("pending review missing")
	}
	if err := rt.Resolve(judgeCallContext(), pending.Operation.OperationId, false); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, operation.ErrDenied) || executed.Load() != 1 {
		t.Fatalf("non-allowlisted call: err=%v executions=%d", err, executed.Load())
	}
	_ = e
}

// The hybrid policy routes through the fence judge with the mode semantics:
// auto runs the confirm stage, safe holds on review, a high-confidence record
// executes without a human.
func TestHybridThroughJudge(t *testing.T) {
	for _, test := range []struct {
		name      string
		mode      string
		llmAction guardrailext.Action
		jevAction guardrailext.Action
		executed  bool
	}{
		{name: "safe_review_jev_record", mode: "safe", llmAction: guardrailext.Action_ACTION_REVIEW, jevAction: guardrailext.Action_ACTION_RECORD, executed: true},
		{name: "safe_review_jev_review", mode: "safe", llmAction: guardrailext.Action_ACTION_REVIEW, jevAction: guardrailext.Action_ACTION_REVIEW, executed: false},
		{name: "auto_review_jev_block", mode: "auto", llmAction: guardrailext.Action_ACTION_REVIEW, jevAction: guardrailext.Action_ACTION_BLOCK, executed: false},
		{name: "auto_confident_allow", mode: "auto", llmAction: guardrailext.Action_ACTION_RECORD, jevAction: guardrailext.Action_ACTION_BLOCK, executed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			llm := &scriptedJudge{check: fixedDecision(test.llmAction, "llm")}
			jev := &scriptedJudge{check: fixedDecision(test.jevAction, "jev")}
			judge := policy.NewHybrid(llm, jev)
			_, rt, registry, _ := judgeFixture(t, fenceconfig.Config{Mode: test.mode}, judge)
			done := make(chan error, 1)
			go func() {
				_, err := toolhooks.Execute(judgeCallContext(), registry, "bash", `{"command":"id"}`, func(context.Context, string) (*aop.ToolResult, error) {
					return &aop.ToolResult{}, nil
				})
				done <- err
			}()
			if test.mode == "safe" && !test.executed {
				// Safe mode holds; the operator refuses. Auto mode denies
				// outright, so there is nothing to resolve there.
				var released bool
				for i := 0; i < 200 && !released; i++ {
					if reviews := rt.Pending("session"); len(reviews) > 0 {
						if err := rt.Resolve(judgeCallContext(), reviews[0].Operation.OperationId, false); err != nil {
							t.Fatal(err)
						}
						released = true
					} else {
						time.Sleep(5 * time.Millisecond)
					}
				}
				if !released {
					t.Fatal("pending review missing")
				}
			}
			err := <-done
			if test.executed {
				if err != nil {
					t.Fatalf("allowed invocation denied: %v", err)
				}
			} else if err == nil {
				t.Fatal("denied invocation ran")
			}
		})
	}
}
