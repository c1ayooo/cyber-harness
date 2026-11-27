package observe

import (
	"context"
	"encoding/json"

	"github.com/chainreactors/cyber/aop/payloads"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// verdictSidecar takes the fence's verdict for one flow (registered fork hook,
// docs/19 patches 21/30/33): the registry keys by flow id and this take
// consumes it exactly once. The Any is pre-built with the control plane's type
// URL so the JSON verdict stays the extension's payload.
func verdictSidecar(flowID string) *anypb.Any {
	verdict, ok := scoperules.TakeVerdict(flowID)
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(verdict)
	if err != nil {
		return nil
	}
	return &anypb.Any{TypeUrl: payloads.TrafficVerdictExtensionURL, Value: encoded}
}

// emitWithSidecars publishes payload with pre-built Any sidecars appended
// verbatim. SetTypedExtension re-wraps its argument with anypb.New, so an Any
// passed through it would nest Any-in-Any and hide the real type URL.
func (e *Extension) emitWithSidecars(ctx context.Context, payload proto.Message, correlation *operationpb.Ref, sidecars ...*anypb.Any) {
	event, err := eventFor(ctx, payload, correlation)
	if err != nil {
		e.logger.Warnf("observe encode: %v", err)
		return
	}
	for _, sidecar := range sidecars {
		if sidecar != nil {
			event.Extensions = append(event.Extensions, sidecar)
		}
	}
	e.events.Publish(event)
}
