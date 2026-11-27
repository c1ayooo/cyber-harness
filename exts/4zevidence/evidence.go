// Package 4zevidence owns the evidence-return contract for remote nodes
// (4zrcin docs/19 P1-2a, fork patches 23c/27/28): changed files under a
// process's case directory — and in-band write/create/edit content — ship to
// the control plane as 4zrcin.Artifact sidecars riding Event_Extension, so a
// node without a shared filesystem still delivers its evidence.
//
// It was extracted from exts/observe so observe could return to its upstream
// form. The snapshot machinery (TakeSnapshot/DiffSnapshots/FileOptions) is
// owned here (snapshot.go, docs/19 E5): reusing observe's copy via import
// left evidence depending on an extension it does not compose, so the pure
// functions moved into this package and observe keeps its own upstream copy.
//
// The emission rule that keeps capture nodes honest: a carrier event is only
// published when it actually carries sidecars (a completion that changed
// nothing publishes nothing, fork patch 28), and every sidecar is appended as
// a pre-built *anypb.Any — never wrapped again — so the control plane's
// exact-URL match sees the real type URL.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	aop "github.com/chainreactors/cyber/aop"
	filepb "github.com/chainreactors/cyber/aop/file"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/artifactsync"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/operation"
	procbus "github.com/chainreactors/cyber/core/proc"
	"github.com/chainreactors/cyber/core/telemetry"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Extension ships changed case-directory files as artifact sidecars.
type Extension struct {
	hooks     *hooks.Registry
	events    *events.Stream
	file      FileOptions
	mu        sync.RWMutex
	subs      []*hooks.Subscription
	snapshots map[string]Snapshot
	closing   bool
	closed    bool
	logger    telemetry.Logger
}

var _ extension.Extension = (*Extension)(nil)

// Options configures the extension. Enabled gates composition: a capture node
// composes it, everything else omits the line (docs/04 §3.3's recipe
// boundary).
type Options struct {
	Enabled bool
	File    FileOptions
}

// New builds the extension without loading it.
func New(options Options) *Extension {
	file := options.File
	if file.MaxEntries == 0 && file.Ignore == nil && !file.Enabled {
		file = defaultFileOptions()
	}
	return &Extension{file: file, snapshots: make(map[string]Snapshot)}
}

// Load subscribes the evidence hooks. Every subscription is owned here —
// observe is not involved.
func (e *Extension) Load(scope *extension.Scope) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.closing {
		return fmt.Errorf("evidence is closed")
	}
	if err := scope.Init().Err(); err != nil {
		return err
	}
	logger, err := extension.Use[telemetry.Logger](scope)
	if err != nil {
		return err
	}
	e.logger = logger
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	e.hooks, e.events = registry, stream
	const source = "4zevidence"
	e.subs = append(e.subs,
		toolhooks.ProcessStarting.On(e.hooks, source, e.processStarting),
		toolhooks.ProcessCompleted.On(e.hooks, source, e.processCompleted),
		toolhooks.FileAccessObserved.On(e.hooks, source, e.fileAccess),
	)
	return nil
}

// Close stops accepting work and waits for in-flight emissions.
func (e *Extension) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed || e.closing {
		e.mu.Unlock()
		return nil
	}
	e.closing = true
	subs := e.subs
	e.subs = nil
	e.mu.Unlock()
	drain := context.Background()
	for _, sub := range subs {
		sub.Close(drain)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

// processStarting takes the case-directory snapshot a completion diffs
// against.
func (e *Extension) processStarting(ctx context.Context, event toolhooks.ProcessEvent) (struct{}, error) {
	if !e.file.Enabled {
		return struct{}{}, nil
	}
	id := event.Operation.GetOperationId()
	before, err := TakeSnapshot(event.Directory, e.file)
	e.mu.Lock()
	if err == nil && !e.closed {
		e.snapshots[id] = before
	}
	e.mu.Unlock()
	if err != nil {
		e.snapshotError(ctx, event.Operation, event.Directory, err)
	}
	return struct{}{}, nil
}

// processCompleted diffs the snapshot and publishes one carrier per changed
// batch — only when the batch actually carries artifacts.
func (e *Extension) processCompleted(ctx context.Context, event toolhooks.ProcessCompletion) (struct{}, error) {
	id := event.Operation.GetOperationId()
	e.mu.Lock()
	before, ok := e.snapshots[id]
	delete(e.snapshots, id)
	e.mu.Unlock()
	if !ok {
		return struct{}{}, nil
	}
	after, err := TakeSnapshot(event.Process.Directory, e.file)
	if err != nil {
		e.snapshotError(ctx, event.Operation, event.Process.Directory, err)
		return struct{}{}, nil
	}
	var sidecars []protobuf.Message
	for _, change := range DiffSnapshots(before, after) {
		if change.Op == filepb.AccessOp_ACCESS_OP_DELETE {
			continue
		}
		rel, relErr := filepath.Rel(event.Process.Directory, change.Path)
		if relErr != nil || rel == "." {
			continue
		}
		for _, encoded := range artifactsync.Collect("process", []artifactsync.Change{{
			RelPath: rel, AbsPath: change.Path, Deleted: false,
		}}, artifactsync.Limits{}) {
			sidecars = append(sidecars, encoded)
		}
	}
	if len(sidecars) == 0 {
		return struct{}{}, nil
	}
	if event.Session != nil {
		args := append([]protobuf.Message{procbus.SessionToProto(event.Session)}, sidecars...)
		e.emitCompleted(ctx, "process", event.Process.Command, event.Lifecycle, args...)
	} else {
		e.emitCompleted(ctx, "process", event.Process.Command, event.Lifecycle, sidecars...)
	}
	return struct{}{}, nil
}

// fileAccess ships in-band write/create/edit content as a sidecar without a
// second disk read, and publishes the carrier only when it carries one.
func (e *Extension) fileAccess(ctx context.Context, event toolhooks.FileEvent) (struct{}, error) {
	if len(event.Data) == 0 ||
		(event.Op != filepb.AccessOp_ACCESS_OP_WRITE && event.Op != filepb.AccessOp_ACCESS_OP_CREATE && event.Op != filepb.AccessOp_ACCESS_OP_EDIT) {
		return struct{}{}, nil
	}
	rel := event.Path
	if event.Directory != "" {
		if r, err := filepath.Rel(event.Directory, event.Path); err == nil {
			rel = r
		}
	}
	encoded, err := artifactsync.FromData("file", rel, event.Data, 0)
	if err != nil {
		return struct{}{}, nil
	}
	access := &filepb.Access{
		Id: aop.EnvelopeID(), Op: event.Op, Source: event.Source, Path: event.Path,
		WorkDir: event.Directory, Size: event.Size, Bytes: int64(len(event.Data)),
		Timestamp: timestamppb.Now(),
	}
	access.Error = event.Err.Error()
	e.emit(ctx, access, event.Operation, encoded)
	return struct{}{}, nil
}

// emitCompleted emits one operation-completed carrier with sidecars.
func (e *Extension) emitCompleted(ctx context.Context, kind, name string, lifecycle toolhooks.Lifecycle, sidecars ...protobuf.Message) {
	completed := &operationpb.Completed{Kind: kind, Name: name}
	if !lifecycle.StartedAt.IsZero() {
		completed.StartedAt = timestamppb.New(lifecycle.StartedAt)
	}
	if lifecycle.Err != nil {
		completed.Failure = failure(lifecycle.Err)
	}
	e.emit(ctx, completed, lifecycle.Operation, sidecars...)
}

// emit publishes one Event_Extension carrier: the payload encoded as the
// extension body, the operation correlation as a typed extension, and every
// sidecar appended as a pre-built Any — never wrapped again, because Any-in-
// Any hides the real type URL from the control plane's exact-URL match.
func (e *Extension) emit(ctx context.Context, payload protobuf.Message, correlation *operationpb.Ref, sidecars ...protobuf.Message) {
	encoded, err := anypb.New(payload)
	if err != nil {
		e.logger.Warnf("evidence encode: %v", err)
		return
	}
	invocation := operation.InvocationFromContext(ctx)
	event := &aop.Event{
		SessionId: invocation.SessionID, TurnId: invocation.TurnID, Emitter: invocation.Emitter,
		Payload: &aop.Event_Extension{Extension: encoded},
	}
	if correlation != nil {
		if err := aop.SetTypedExtension(event, correlation); err != nil {
			e.logger.Warnf("evidence correlation: %v", err)
			return
		}
	}
	for _, sidecar := range sidecars {
		if sidecar == nil {
			continue
		}
		if anyMsg, ok := sidecar.(*anypb.Any); ok {
			event.Extensions = append(event.Extensions, anyMsg)
			continue
		}
		if err := aop.SetTypedExtension(event, sidecar); err != nil {
			e.logger.Warnf("evidence sidecar: %v", err)
			return
		}
	}
	e.events.Publish(event)
}

func (e *Extension) snapshotError(ctx context.Context, correlation *operationpb.Ref, directory string, err error) {
	e.logger.Importantf("evidence: snapshot %s failed: %v", directory, err)
	failure := &operationpb.Completed{Failure: &operationpb.Failure{Message: fmt.Sprintf("evidence snapshot %s failed: %v", directory, err)}}
	e.emit(ctx, failure, correlation)
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

func defaultFileOptions() FileOptions {
	return FileOptions{Enabled: true}
}
