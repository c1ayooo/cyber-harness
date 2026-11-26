// Package observe converts public execution hooks into typed AOP observations.
package observe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	aop "github.com/c1ayooo/cyber/aop"
	filepb "github.com/c1ayooo/cyber/aop/file"
	operationpb "github.com/c1ayooo/cyber/aop/operation"
	"github.com/c1ayooo/cyber/core/artifactsync"
	coreevents "github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	corehooks "github.com/c1ayooo/cyber/core/hooks"
	"github.com/c1ayooo/cyber/core/operation"
	procbus "github.com/c1ayooo/cyber/core/proc"
	"github.com/c1ayooo/cyber/core/scoperules"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
	toolhooks "github.com/c1ayooo/cyber/core/tool/hooks"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Kind string

const (
	Tools     Kind = "tools"
	Commands  Kind = "commands"
	Processes Kind = "processes"
	Files     Kind = "files"
	HTTP      Kind = "http"
	// Artifacts (fork patch 23c): changed files under the case directory are
	// shipped back to the control plane as 4zrcin.Artifact sidecars, so a
	// remote node without a shared filesystem still delivers its evidence.
	Artifacts Kind = "artifacts"
)

type Options struct {
	Kinds []Kind
	File  FileOptions
}

type Extension struct {
	hooks  *corehooks.Registry
	events *coreevents.Stream
	kinds  map[Kind]bool

	mu        sync.RWMutex
	file      FileOptions
	subs      []*corehooks.Subscription
	snapshots map[string]Snapshot
	closing   bool
	closed    bool
	logger    telemetry.Logger
}

var _ extension.Extension = (*Extension)(nil)

func New(options Options) (*Extension, error) {
	kinds := make(map[Kind]bool, len(options.Kinds))
	for _, kind := range options.Kinds {
		switch kind {
		case Tools, Commands, Processes, Files, HTTP, Artifacts:
			if kinds[kind] {
				return nil, fmt.Errorf("duplicate observation kind %q", kind)
			}
			kinds[kind] = true
		default:
			return nil, fmt.Errorf("unknown observation kind %q", kind)
		}
	}
	fileOptions := options.File
	if fileOptions.MaxEntries == 0 && fileOptions.Ignore == nil && !fileOptions.Enabled {
		fileOptions = defaultFileOptions()
	}
	return &Extension{
		kinds: kinds, file: fileOptions,
		snapshots: make(map[string]Snapshot),
	}, nil
}

func (e *Extension) Load(scope *extension.Scope) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.closing {
		return fmt.Errorf("observe is closed")
	}
	if err := scope.Init().Err(); err != nil {
		return err
	}
	logger, err := extension.Use[telemetry.Logger](scope)
	if err != nil {
		return err
	}
	e.logger = logger
	registry, err := extension.Use[*corehooks.Registry](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*coreevents.Stream](scope)
	if err != nil {
		return err
	}
	e.hooks, e.events = registry, stream
	const source = "observe"
	if e.kinds[Tools] {
		e.subs = append(e.subs,
			toolhooks.Started.On(e.hooks, source, e.toolStarted),
			toolhooks.Completed.On(e.hooks, source, e.toolCompleted),
		)
	}
	if e.kinds[Commands] {
		e.subs = append(e.subs,
			toolhooks.CommandStarted.On(e.hooks, source, e.commandStarted),
			toolhooks.CommandCompleted.On(e.hooks, source, e.commandCompleted),
		)
	}
	// The artifacts kind needs the same hooks as processes/files: its sidecars
	// ride the process-completion snapshot diff and the in-band file writes
	// (fork patch 28). Without this, `--observe artifacts` alone parsed but
	// subscribed to nothing and shipped nothing.
	if e.kinds[Processes] || e.kinds[Files] || e.kinds[Artifacts] {
		e.subs = append(e.subs,
			toolhooks.ProcessStarting.On(e.hooks, source, e.processStarting),
			toolhooks.ProcessStartedObserved.On(e.hooks, source, e.processStarted),
			toolhooks.ProcessCompleted.On(e.hooks, source, e.processCompleted),
		)
	}
	if e.kinds[Files] || e.kinds[Artifacts] {
		e.subs = append(e.subs, toolhooks.FileAccessObserved.On(e.hooks, source, e.fileAccess))
	}
	if e.kinds[HTTP] {
		e.subs = append(e.subs, toolhooks.FlowCompletedObserved.On(e.hooks, source, e.flowCompleted))
	}
	return nil
}

func eventFor(ctx context.Context, payload proto.Message, correlation *operationpb.Ref, sidecars ...proto.Message) (*aop.Event, error) {
	encoded, err := anypb.New(payload)
	if err != nil {
		return nil, err
	}
	invocation := operation.InvocationFromContext(ctx)
	event := &aop.Event{
		SessionId: invocation.SessionID, TurnId: invocation.TurnID, Emitter: invocation.Emitter,
		Payload: &aop.Event_Extension{Extension: encoded},
	}
	if correlation != nil {
		if err := aop.SetTypedExtension(event, correlation); err != nil {
			return nil, err
		}
	}
	for _, sidecar := range sidecars {
		if sidecar == nil {
			continue
		}
		if anyMsg, ok := sidecar.(*anypb.Any); ok {
			// Pre-built sidecars are already typed Any values (the JSON-in-Any
			// fork extensions such as 4zrcin.TrafficVerdict and 4zrcin.Artifact).
			// Wrapping them again would nest Any-in-Any and the control plane's
			// exact-URL match would never see the real type URL.
			event.Extensions = append(event.Extensions, anyMsg)
			continue
		}
		if err := aop.SetTypedExtension(event, sidecar); err != nil {
			return nil, err
		}
	}
	return event, nil
}

func (e *Extension) emit(ctx context.Context, payload proto.Message, correlation *operationpb.Ref, sidecars ...proto.Message) {
	event, err := eventFor(ctx, payload, correlation, sidecars...)
	if err != nil {
		e.logger.Warnf("observe encode: %v", err)
		return
	}
	// Publication is synchronous at the hook boundary. Cancel prevents new
	// callback admission; callbacks already admitted are drained by Close and
	// must still publish their observation while that drain is in progress.
	e.events.Publish(event)
}

func (e *Extension) toolStarted(ctx context.Context, event toolhooks.CallEvent) (struct{}, error) {
	e.emit(ctx, &operationpb.Started{Kind: "tool", Name: event.Call.GetName()}, event.Operation)
	return struct{}{}, nil
}

func (e *Extension) toolCompleted(ctx context.Context, event toolhooks.Completion) (struct{}, error) {
	// ToolResult.IsError is model-visible failure feedback even when the tool
	// deliberately returns no Go error (for example, a shell's nonzero exit).
	if event.Err == nil && event.Result.GetIsError() {
		message := coretool.ResultText(event.Result)
		if message == "" {
			message = "tool returned an error result"
		}
		event.Err = errors.New(message)
	}
	e.emitCompleted(ctx, "tool", event.Call.GetName(), event.Lifecycle)
	return struct{}{}, nil
}

func (e *Extension) commandStarted(ctx context.Context, event toolhooks.CommandEvent) (struct{}, error) {
	e.emit(ctx, &operationpb.Started{Kind: "command", Name: event.Name}, event.Operation)
	return struct{}{}, nil
}

func (e *Extension) commandCompleted(ctx context.Context, event toolhooks.CommandCompletion) (struct{}, error) {
	e.emitCompleted(ctx, "command", event.Command.Name, event.Lifecycle)
	return struct{}{}, nil
}

func (e *Extension) processStarting(ctx context.Context, event toolhooks.ProcessEvent) (struct{}, error) {
	// Snapshot preparation is deliberately synchronous with the real pre-start
	// boundary; no work is performed when neither file observation nor artifact
	// sync is selected — both live off the same before/after diff.
	if e.kinds[Files] || e.kinds[Artifacts] {
		e.processSnapshot(ctx, event)
	}
	return struct{}{}, nil
}

func (e *Extension) processStarted(ctx context.Context, event toolhooks.ProcessEvent) (struct{}, error) {
	if e.kinds[Processes] {
		e.emit(ctx, &operationpb.Started{Kind: "process", Name: event.Command}, event.Operation)
	}
	return struct{}{}, nil
}

func (e *Extension) processCompleted(ctx context.Context, event toolhooks.ProcessCompletion) (struct{}, error) {
	// The artifact sidecars ride the process-completed event: one batch per
	// command, derived from the same snapshot diff the file observations use.
	var sidecars []proto.Message
	if e.kinds[Artifacts] || e.kinds[Files] {
		sidecars = e.finishSnapshot(ctx, event)
	}
	// Emit the carrier when the process observation itself is wanted, or when
	// this batch actually carries artifacts: an artifacts-only node ships a
	// minimal completion per changed batch and nothing otherwise (patch 28).
	if e.kinds[Processes] || (e.kinds[Artifacts] && len(sidecars) > 0) {
		if event.Session != nil {
			args := append([]proto.Message{procbus.SessionToProto(event.Session)}, sidecars...)
			e.emitCompleted(ctx, "process", event.Process.Command, event.Lifecycle, args...)
		} else {
			e.emitCompleted(ctx, "process", event.Process.Command, event.Lifecycle, sidecars...)
		}
	}
	return struct{}{}, nil
}

func (e *Extension) fileAccess(ctx context.Context, event toolhooks.FileEvent) (struct{}, error) {
	access := &filepb.Access{
		Id: aop.EnvelopeID(), Op: event.Op, Source: event.Source, Path: event.Path,
		WorkDir: event.Directory, Size: event.Size, Bytes: int64(len(event.Data)), Edits: event.Edits,
		Timestamp: timestamppb.Now(),
	}
	if event.Err != nil {
		access.Error = event.Err.Error()
	} else if event.Op == filepb.AccessOp_ACCESS_OP_WRITE || event.Op == filepb.AccessOp_ACCESS_OP_CREATE || event.Op == filepb.AccessOp_ACCESS_OP_EDIT {
		sum := sha256.Sum256(event.Data)
		access.Digest = hex.EncodeToString(sum[:])
	}
	var sidecars []proto.Message
	// In-band artifact (fork patch 23c): a write/create whose content the hook
	// already carried ships as a sidecar without a second disk read.
	if e.kinds[Artifacts] && len(event.Data) > 0 &&
		(event.Op == filepb.AccessOp_ACCESS_OP_WRITE || event.Op == filepb.AccessOp_ACCESS_OP_CREATE || event.Op == filepb.AccessOp_ACCESS_OP_EDIT) {
		rel := event.Path
		if event.Directory != "" {
			if r, err := filepath.Rel(event.Directory, event.Path); err == nil {
				rel = r
			}
		}
		if encoded, err := artifactsync.FromData("file", rel, event.Data, 0); err == nil {
			sidecars = append(sidecars, encoded)
		}
	}
	// Same rule as the process carrier: a file observation is only published
	// when someone asked for it, or when it carries artifact sidecars.
	if e.kinds[Files] || len(sidecars) > 0 {
		e.emit(ctx, access, event.Operation, sidecars...)
	}
	return struct{}{}, nil
}

func (e *Extension) flowCompleted(ctx context.Context, event toolhooks.FlowEvent) (struct{}, error) {
	// ProxyHub gives this boundary an owned, hydrated copy after FlowStore commit.
	// A judged request additionally carries its scope-rule verdict as the
	// control plane's TrafficVerdict sidecar; the registry keys by flow id and
	// this take consumes it exactly once.
	var sidecars []proto.Message
	if verdict, ok := scoperules.TakeVerdict(event.Flow.GetId()); ok {
		if encoded, err := json.Marshal(verdict); err == nil {
			sidecars = append(sidecars, &anypb.Any{TypeUrl: "type.googleapis.com/4zrcin.TrafficVerdict", Value: encoded})
		}
	}
	e.emit(ctx, event.Flow, event.Operation, sidecars...)
	return struct{}{}, nil
}

func (e *Extension) emitCompleted(ctx context.Context, kind, name string, lifecycle toolhooks.Lifecycle, sidecars ...proto.Message) {
	completed := &operationpb.Completed{Kind: kind, Name: name}
	if !lifecycle.StartedAt.IsZero() {
		completed.StartedAt = timestamppb.New(lifecycle.StartedAt)
	}
	if lifecycle.Err != nil {
		completed.Failure = failure(lifecycle.Err)
	}
	e.emit(ctx, completed, lifecycle.Operation, sidecars...)
}

func failure(err error) *operationpb.Failure {
	kind := operationpb.FailureKind_FAILURE_KIND_ERROR
	switch {
	case errors.Is(err, operation.ErrDenied):
		kind = operationpb.FailureKind_FAILURE_KIND_DENIED
	case errors.Is(err, operation.ErrStartFailed):
		kind = operationpb.FailureKind_FAILURE_KIND_START_FAILED
	case errors.Is(err, operation.ErrPanicked):
		kind = operationpb.FailureKind_FAILURE_KIND_PANIC
	case errors.Is(err, context.DeadlineExceeded):
		kind = operationpb.FailureKind_FAILURE_KIND_TIMEOUT
	case errors.Is(err, context.Canceled):
		kind = operationpb.FailureKind_FAILURE_KIND_CANCELED
	}
	return &operationpb.Failure{Kind: kind, Message: err.Error()}
}

func (e *Extension) processSnapshot(ctx context.Context, event toolhooks.ProcessEvent) {
	if !e.fileOptions().Enabled {
		return
	}
	id := event.Operation.GetOperationId()
	before, err := TakeSnapshot(event.Directory, e.fileOptions())
	e.mu.Lock()
	if err == nil && !e.closed {
		e.snapshots[id] = before
	}
	e.mu.Unlock()
	if err != nil {
		e.snapshotError(ctx, event.Operation, event.Directory, err)
	}
}

// finishSnapshot diffs the pre-start snapshot against the case directory,
// emits the FileAccess observations (Files kind) and returns the artifact
// sidecars for the changed files (fork patch 23c) to ride the caller's
// completed event.
func (e *Extension) finishSnapshot(ctx context.Context, event toolhooks.ProcessCompletion) []proto.Message {
	id := event.Operation.GetOperationId()
	e.mu.Lock()
	before, ok := e.snapshots[id]
	delete(e.snapshots, id)
	e.mu.Unlock()
	if !ok {
		return nil
	}
	after, err := TakeSnapshot(event.Process.Directory, e.fileOptions())
	if err != nil {
		e.snapshotError(ctx, event.Operation, event.Process.Directory, err)
		return nil
	}
	var sidecars []proto.Message
	for _, change := range DiffSnapshots(before, after) {
		if e.kinds[Files] {
			e.emit(ctx, &filepb.Access{
				Id: aop.EnvelopeID(), Op: change.Op, Source: filepb.AccessSource_ACCESS_SOURCE_SNAPSHOT,
				Path: change.Path, WorkDir: event.Process.Directory, Size: change.Size, Timestamp: timestamppb.Now(),
			}, event.Operation)
		}
		if !e.kinds[Artifacts] || change.Op == filepb.AccessOp_ACCESS_OP_DELETE {
			continue
		}
		rel, relErr := filepath.Rel(event.Process.Directory, change.Path)
		if relErr != nil || rel == "." {
			continue
		}
		for _, encoded := range artifactsync.Collect("process", []artifactsync.Change{
			{RelPath: rel, AbsPath: change.Path},
		}, artifactsync.Limits{}) {
			sidecars = append(sidecars, encoded)
		}
	}
	return sidecars
}

func (e *Extension) snapshotError(ctx context.Context, correlation *operationpb.Ref, directory string, err error) {
	e.emit(ctx, &filepb.Access{
		Id: aop.EnvelopeID(), Source: filepb.AccessSource_ACCESS_SOURCE_SNAPSHOT,
		Path: directory, WorkDir: directory, Error: err.Error(), Timestamp: timestamppb.Now(),
	}, correlation)
}

func (e *Extension) fileOptions() FileOptions {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := e.file
	result.Ignore = append([]string(nil), result.Ignore...)
	return result
}

func (e *Extension) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	e.closing = true
	subs := append([]*corehooks.Subscription(nil), e.subs...)
	e.mu.Unlock()
	for _, sub := range subs {
		sub.Cancel()
	}
	var closeErr error
	for _, sub := range subs {
		if err := sub.Close(ctx); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	if closeErr != nil {
		return closeErr
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
	}
	pendingSnapshots := len(e.snapshots)
	e.mu.Unlock()
	if pendingSnapshots > 0 {
		closeErr = errors.Join(closeErr, fmt.Errorf("observe incomplete: %d process snapshots unresolved", pendingSnapshots))
	}
	return closeErr
}
