package policy

// The JEV stage's vendor token usage becomes an AOP usage fact under the
// guardrail emitter — the control plane's token accounting reads these. A
// response without usage emits none. Ported with the stage from the old
// guardrail admission tests (4zdesign/19 E3-3): the reporter moved, so does its
// test.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jevapi "github.com/chainreactors/cyber/agent/provider/jev"
	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/operation"
)

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
			type usageFact struct {
				emitter string
				usage   *aop.TokenUsage
			}
			var mu sync.Mutex
			var facts []usageFact
			stream.Observe(func(event *aop.Event) {
				if event.GetUsage() == nil {
					return
				}
				mu.Lock()
				facts = append(facts, usageFact{emitter: event.GetEmitter(), usage: event.GetUsage()})
				mu.Unlock()
			})
			jev := NewJEV(JEVRules{}, client, UsageReporter(stream, EmitterJEV))
			ctx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: "session", TurnID: "turn"})
			if _, err := jev.Check(ctx, call()); err != nil {
				t.Fatal(err)
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
