package toolnode_test

import (
	"context"
	"sync"
	"testing"
	"time"

	aop "github.com/c1ayooo/cyber/aop"
	operationpb "github.com/c1ayooo/cyber/aop/operation"
	toolpb "github.com/c1ayooo/cyber/aop/tool"
	coreevents "github.com/c1ayooo/cyber/core/events"
	coretool "github.com/c1ayooo/cyber/core/tool"
	toolnode "github.com/c1ayooo/cyber/pkg/node/tool"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type drainingTool struct{ started, canceled, release chan struct{} }

func (*drainingTool) Name() string        { return "drain" }
func (*drainingTool) Description() string { return "wait for cleanup after cancellation" }
func (d *drainingTool) Definition() *aop.ToolDefinition {
	return coretool.Def(d.Name(), d.Description(), struct{}{})
}
func (d *drainingTool) Execute(ctx context.Context, _ string) (*aop.ToolResult, error) {
	close(d.started)
	<-ctx.Done()
	close(d.canceled)
	<-d.release
	return nil, ctx.Err()
}

func TestCallsRejectDuplicateCancelArtifactsAndDrainBeforeClose(t *testing.T) {
	d := &drainingTool{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	events := coreevents.New()
	var mu sync.Mutex
	var sent []proto.Message
	h := &toolnode.CallHandler{Executor: hosttest.Tools(t, d), Publish: events.Publish, Send: func(_ string, message proto.Message) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, message)
	}}
	sub := events.Observe(h.Forward)
	defer sub.Cancel()
	args, _ := aop.JSONValue(map[string]any{})
	request := &toolpb.ProtocolMessage{Message: &toolpb.ProtocolMessage_Call{Call: &toolpb.Call{Call: &aop.ToolCall{Id: "call", Name: d.Name(), Arguments: args}}}}
	if err := h.Handle(t.Context(), &aop.Envelope{Id: "call"}, request, nil); err != nil {
		t.Fatal(err)
	}
	<-d.started
	if err := h.Handle(t.Context(), &aop.Envelope{Id: "call"}, request, nil); err != nil {
		t.Fatal(err)
	}
	payload, _ := anypb.New(&toolpb.Artifact{ResultId: "artifact"})
	artifact := &aop.Event{Payload: &aop.Event_Extension{Extension: payload}}
	_ = aop.SetTypedExtension(artifact, &operationpb.Ref{CallId: "call"})
	h.Forward(artifact)
	if !h.Cancel(aop.MustWrap("cancel", "", &aop.ProtocolMessage{Message: &aop.ProtocolMessage_CancelOperation{CancelOperation: &aop.CancelOperation{TargetId: "call"}}})) {
		t.Fatal("cancel was not handled")
	}
	<-d.canceled
	h.Forward(artifact)
	h.ForwardProgress(&toolpb.Progress{CallId: "call", Text: "late"})
	done := make(chan struct{})
	go func() { h.Close(); close(done) }()
	select {
	case <-done:
		t.Fatal("closed before execution drained")
	default:
	}
	close(d.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not drain")
	}
	h.Forward(artifact)
	mu.Lock()
	defer mu.Unlock()
	var duplicates, artifacts, terminals int
	for _, message := range sent {
		core, ok := message.(*aop.ProtocolMessage)
		if !ok {
			t.Fatalf("unexpected message %T", message)
		}
		if core.GetProtocolError().GetCode() == "DUPLICATE_OPERATION" {
			duplicates++
		}
		if core.GetEvent().GetExtension() != nil {
			artifacts++
		}
		if core.GetEvent().GetToolResult() != nil {
			terminals++
		}
	}
	if duplicates != 1 || artifacts != 1 || terminals != 1 {
		t.Fatalf("duplicate=%d artifact=%d terminal=%d", duplicates, artifacts, terminals)
	}
}
