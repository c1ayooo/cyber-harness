package observe_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	filepb "github.com/chainreactors/cyber/aop/file"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/aop/payloads"
	trafficpb "github.com/chainreactors/cyber/aop/traffic"
	coreevents "github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/core/telemetry"
	coretool "github.com/chainreactors/cyber/core/tool"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/exts/4zfence/scoperules"
	fileext "github.com/chainreactors/cyber/exts/files"
	observe "github.com/chainreactors/cyber/exts/observe"
	"github.com/chainreactors/cyber/tools/files"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestObservePublishesOneCorrelatedAOPStream(t *testing.T) {
	hookRegistry := hooks.New()
	stream := coreevents.New()
	observer, err := observe.New(observe.Options{Kinds: []observe.Kind{observe.Tools, observe.Files}})
	if err != nil {
		t.Fatal(err)
	}
	registry := coretool.NewToolRegistry()
	fileTools := fileext.New(files.Config{Directory: t.TempDir()})
	set, err := extension.New(
		extension.Provided[*hooks.Registry](hookRegistry),
		extension.Provided[*coreevents.Stream](stream),
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		registry,
		observer,
		fileTools,
	)
	if err != nil {
		t.Fatal(err)
	}
	var events []*aop.Event
	sub := stream.Observe(func(event *aop.Event) { events = append(events, event) })
	defer sub.Cancel()
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{
		CallID: "call-1", SessionID: "session-1", TurnID: "turn-1", Emitter: "test",
	})
	if _, err := registry.ExecuteTool(ctx, "write", `{"path":"note","content":"committed"}`); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want started, access, completed", len(events))
	}

	refs := make([]*operationpb.Ref, len(events))
	for i, event := range events {
		ref := new(operationpb.Ref)
		if ok, err := aop.FindTypedExtension(event, ref); err != nil || !ok {
			t.Fatalf("event %d operation: ok=%v err=%v", i, ok, err)
		}
		if ref.GetCallId() != "call-1" || ref.GetOperationId() == "" {
			t.Fatalf("event %d operation = %v", i, ref)
		}
		if event.GetSessionId() != "session-1" || event.GetTurnId() != "turn-1" || event.GetEmitter() != "test" {
			t.Fatalf("event %d invocation metadata = %v", i, event)
		}
		refs[i] = ref
	}
	if refs[0].GetOperationId() != refs[2].GetOperationId() {
		t.Fatalf("tool lifecycle operation changed: %v", refs)
	}
	if refs[1].GetOperationId() == refs[0].GetOperationId() || refs[1].GetParentOperationId() != refs[0].GetOperationId() {
		t.Fatalf("file access is not a child of the tool operation: %v", refs)
	}

	started := new(operationpb.Started)
	access := new(filepb.Access)
	completed := new(operationpb.Completed)
	if err := events[0].GetExtension().UnmarshalTo(started); err != nil || started.GetKind() != "tool" || started.GetName() != "write" {
		t.Fatalf("started = %v, %v", started, err)
	}
	if err := events[1].GetExtension().UnmarshalTo(access); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("committed"))
	if access.GetOp() != filepb.AccessOp_ACCESS_OP_CREATE || access.GetDigest() != hex.EncodeToString(digest[:]) {
		t.Fatalf("access = %v", access)
	}
	if err := events[2].GetExtension().UnmarshalTo(completed); err != nil || completed.GetKind() != "tool" || completed.GetStartedAt() == nil || completed.GetFailure() != nil {
		t.Fatalf("completed = %v, %v", completed, err)
	}
}

func TestObserveAttachesVerdictSidecarWithoutNesting(t *testing.T) {
	hookRegistry := hooks.New()
	stream := coreevents.New()
	observer, err := observe.New(observe.Options{Kinds: []observe.Kind{observe.HTTP}})
	if err != nil {
		t.Fatal(err)
	}
	set, err := extension.New(
		extension.Provided[*hooks.Registry](hookRegistry),
		extension.Provided[*coreevents.Stream](stream),
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		observer,
	)
	if err != nil {
		t.Fatal(err)
	}
	var events []*aop.Event
	sub := stream.Observe(func(event *aop.Event) { events = append(events, event) })
	defer sub.Cancel()
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := operation.ContextWithInvocation(t.Context(), operation.Invocation{
		CallID: "call-1", SessionID: "session-1", TurnID: "turn-1", Emitter: "test",
	})
	scoperules.RecordVerdict("flow-1", scoperules.Verdict{Action: "block", RuleID: "rule-1"})
	flow := &trafficpb.Flow{Id: "flow-1"}
	if _, err := toolhooks.FlowCompletedObserved.Emit(ctx, hookRegistry, toolhooks.FlowEvent{
		Operation: &operationpb.Ref{CallId: "call-1"}, Flow: flow,
	}); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	// The sidecar must be a directly-readable TrafficVerdict extension: an
	// Any-in-Any wrap hides the type URL and the control plane never sees the
	// verdict (docs/19 appendix E2-1).
	var raw *anypb.Any
	for _, ext := range events[0].GetExtensions() {
		if ext.GetTypeUrl() == payloads.TrafficVerdictExtensionURL {
			raw = ext
			break
		}
	}
	if raw == nil {
		t.Fatalf("event extensions = %v", events[0].GetExtensions())
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw.GetValue(), &decoded); err != nil {
		t.Fatalf("sidecar value is not JSON: %v", err)
	}
	if decoded["action"] != "block" || decoded["rule_id"] != "rule-1" {
		t.Fatalf("sidecar = %v", decoded)
	}
	// And the payload decoder must accept it end to end.
	if v, ok := payloads.ParseTrafficVerdict(raw); !ok || v.Action != "block" {
		t.Fatalf("ParseTrafficVerdict = %v, %v", v, ok)
	}
}

func TestObserveRejectsInvalidSelection(t *testing.T) {
	if _, err := observe.New(observe.Options{Kinds: []observe.Kind{"unknown"}}); err == nil {
		t.Fatal("accepted unknown observation kind")
	}
	if _, err := observe.New(observe.Options{Kinds: []observe.Kind{observe.Files, observe.Files}}); err == nil {
		t.Fatal("accepted duplicate observation kind")
	}
	if err := (*observe.Extension)(nil).Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
