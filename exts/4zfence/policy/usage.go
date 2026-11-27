package policy

import (
	"context"

	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/operation"
	"google.golang.org/protobuf/proto"
)

// The emitter tags tag referee token usage by judge. The ledger classifies
// both as guardrail (referee) cost while still separating the JEV vendor from
// the OpenAI-compatible judge. The JEV emitter keeps its historical value for
// old control planes.
const (
	EmitterJEV = "guardrail"
	EmitterLLM = "guardrail-llm"
)

// UsageReporter publishes vendor token usage as an AOP usage fact under one
// emitter. Missing usage stays missing: the canonical event is only emitted
// for real data. A nil stream yields a nil reporter — outside the extension
// composition there is no canonical stream to publish on.
func UsageReporter(stream *events.Stream, emitter string) func(context.Context, *aop.TokenUsage) {
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
