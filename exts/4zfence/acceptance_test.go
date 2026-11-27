package fence

// The fence acceptance corpus (4zrcin docs/19 P1-4 acceptance): every sample
// drives the FULL admission path — the fence's tool.before admission for the
// tool calls (guaranteed audit, red lines, review holds) and the fence's
// scope judge for the proxied requests — and prints one stable verdict line
// per sample. scripts/fence-parity.sh runs this same file in a P0-era
// worktree (via its baseline twin) and diffs the tables, so a refactor that
// changes interception behavior fails the parity gate.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
)

type acceptanceConfig struct {
	GlobalFence json.RawMessage `json:"globalfence"`
	ScopeRules  json.RawMessage `json:"scoperules"`
}

type acceptanceSample struct {
	Name   string           `json:"name"`
	Config acceptanceConfig `json:"config"`
	Call   struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"call"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Passive    bool   `json:"passive"`
	WantAudit  string `json:"want_audit"`
	WantDeny   bool   `json:"want_deny"`
	WantHold   bool   `json:"hold"`
	WantReason string `json:"want_reason"`
	WantAction string `json:"want_action"`
	WantRule   string `json:"want_rule"`
}

func TestAcceptanceCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/acceptance_samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		ToolCalls    []acceptanceSample `json:"tool_calls"`
		HTTPRequests []acceptanceSample `json:"http_requests"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}

	for _, sample := range corpus.ToolCalls {
		t.Run(sample.Name, func(t *testing.T) {
			stream := events.New()
			rt := guardrailext.NewRuntime(t.Context(), stream, 2*time.Second, guardrailext.ModeAuto)
			defer func() { _ = rt.Close(context.Background()) }()
			e := &Extension{stream: stream}
			e.Bind(rt)
			if sample.Config.GlobalFence != nil {
				if err := globalfence.SetRules("sess-acc", sample.Config.GlobalFence); err != nil {
					t.Fatal(err)
				}
				defer globalfence.DropSession("sess-acc")
			}
			var decisions []string
			var decisionsMu sync.Mutex
			stop := stream.Observe(func(event *aop.Event) {
				var d guardrailext.Decision
				ext := event.GetExtension()
				if ext == nil || !ext.MessageIs(&d) || ext.UnmarshalTo(&d) != nil {
					return
				}
				decisionsMu.Lock()
				decisions = append(decisions, d.Reason)
				decisionsMu.Unlock()
			})
			defer stop.Cancel()

			ev := toolhooks.CallEvent{Call: buildAcceptanceCall(sample), Operation: &operationpb.Ref{OperationId: "op-" + sample.Name}}
			ctx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "sess-acc", CallID: sample.Name})
			if sample.WantHold {
				done := make(chan toolhooks.Admission, 1)
				go func() {
					admission, _ := e.admit(ctx, ev)
					done <- admission
				}()
				waitAcceptanceReview(t, stream, ev.Operation.GetOperationId())
				resolveCtx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "sess-acc", Emitter: "control"})
				if err := rt.Resolve(resolveCtx, ev.Operation.GetOperationId(), true); err != nil {
					t.Fatal(err)
				}
				select {
				case admission := <-done:
					if admission.Deny != nil {
						t.Fatalf("approved hold still denied: %v", admission.Deny)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("approval did not release the hold")
				}
				audit := firstAuditReason(&decisionsMu, decisions)
				if !strings.HasPrefix(audit, sample.WantAudit) {
					t.Fatalf("audit = %q, want prefix %q", audit, sample.WantAudit)
				}
				t.Logf("VERDICT %s audit=%s deny=false hold=true", sample.Name, audit)
				return
			}
			admission, err := e.admit(ctx, ev)
			if err != nil {
				t.Fatal(err)
			}
			audit := firstAuditReason(&decisionsMu, decisions)
			deny := admission.Deny != nil
			reason := ""
			if deny {
				reason = admission.Deny.Error()
			}
			if deny != sample.WantDeny {
				t.Fatalf("deny = %v (%v), want %v", deny, reason, sample.WantDeny)
			}
			if sample.WantReason != "" && !strings.Contains(reason, sample.WantReason) {
				t.Fatalf("reason %q lacks %q", reason, sample.WantReason)
			}
			if !strings.HasPrefix(audit, sample.WantAudit) {
				t.Fatalf("audit = %q, want prefix %q", audit, sample.WantAudit)
			}
			t.Logf("VERDICT %s audit=%s deny=%t hold=%t", sample.Name, audit, deny, sample.WantHold)
		})
	}

	for _, sample := range corpus.HTTPRequests {
		t.Run(sample.Name, func(t *testing.T) {
			stream := events.New()
			rt := guardrailext.NewRuntime(t.Context(), stream, 2*time.Second, guardrailext.ModeAuto)
			defer func() { _ = rt.Close(context.Background()) }()
			e := &Extension{stream: stream}
			e.Bind(rt)
			if sample.Config.GlobalFence != nil {
				if err := globalfence.SetRules("sess-acc", sample.Config.GlobalFence); err != nil {
					t.Fatal(err)
				}
				defer globalfence.DropSession("sess-acc")
			}
			if sample.Config.ScopeRules != nil {
				if err := scoperules.SetRules("sess-acc", sample.Config.ScopeRules); err != nil {
					t.Fatal(err)
				}
				defer scoperules.DropSession("sess-acc")
			}
			judge := NewScopeJudge(e)
			decision := judge.JudgeScopeRequest(scoperules.ScopeRequest{
				Invocation: operation.Invocation{SessionID: "sess-acc"},
				Call:       acceptanceHTTPCall(sample),
				Operation:  &operationpb.Ref{OperationId: "op-http-" + sample.Name},
			})
			if !decision.Judged || decision.Action != sample.WantAction || decision.RuleID != sample.WantRule {
				t.Fatalf("decision = %+v, want action=%s rule=%s", decision, sample.WantAction, sample.WantRule)
			}
			held := decision.Hold != nil
			if held != sample.WantHold {
				t.Fatalf("hold = %v, want %v", held, sample.WantHold)
			}
			t.Logf("VERDICT %s action=%s rule=%s hold=%t", sample.Name, decision.Action, decision.RuleID, held)
		})
	}
}

// firstAuditReason returns the first Decision reason that starts with the
// builtin prefix (the guaranteed audit row), or "".
func firstAuditReason(mu *sync.Mutex, decisions []string) string {
	mu.Lock()
	defer mu.Unlock()
	for _, reason := range decisions {
		if strings.HasPrefix(reason, "builtin.") {
			return reason
		}
	}
	return ""
}

func buildAcceptanceCall(sample acceptanceSample) *aop.ToolCall {
	return &aop.ToolCall{Name: sample.Call.Name, Arguments: &aop.EncodedValue{Data: sample.Call.Arguments}}
}

func acceptanceHTTPCall(sample acceptanceSample) *aop.ToolCall {
	var value any = map[string]any{}
	if sample.Passive {
		value = map[string]any{"method": sample.Method, "url": sample.URL, "passive": true}
	} else {
		value = map[string]any{"method": sample.Method, "url": sample.URL}
	}
	data, _ := json.Marshal(value)
	return &aop.ToolCall{Name: "http.request", Arguments: &aop.EncodedValue{Data: data}}
}

// waitAcceptanceReview blocks until the runtime publishes the pending review
// for one operation.
func waitAcceptanceReview(t *testing.T, stream *events.Stream, operationID string) {
	t.Helper()
	found := make(chan struct{}, 1)
	stop := stream.Observe(func(event *aop.Event) {
		var r guardrailext.Review
		ext := event.GetExtension()
		if ext == nil || !ext.MessageIs(&r) || ext.UnmarshalTo(&r) != nil {
			return
		}
		if r.GetState() == guardrailext.ReviewState_REVIEW_STATE_PENDING && r.GetOperation().GetOperationId() == operationID {
			found <- struct{}{}
		}
	})
	defer stop.Cancel()
	select {
	case <-found:
	case <-time.After(2 * time.Second):
		t.Fatal("pending review never appeared")
	}
}
