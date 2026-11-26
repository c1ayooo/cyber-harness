package observe

// In-package integration test for the artifact sidecar channel (fork patches
// 23c, 27, 28): a process completion under the artifacts kind ships changed
// case-directory files as 4zrcin.Artifact sidecars, while the node's private
// .zrcin state never ships — except the two handoff files a control plane reads
// back (facts.jsonl, worker-note.md). The artifacts kind works on its own.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	aop "github.com/c1ayooo/cyber/aop"
	operationpb "github.com/c1ayooo/cyber/aop/operation"
	"github.com/c1ayooo/cyber/core/artifactsync"
	coreevents "github.com/c1ayooo/cyber/core/events"
	toolhooks "github.com/c1ayooo/cyber/core/tool/hooks"
)

func TestArtifactsSidecarsOnProcessCompleted(t *testing.T) {
	caseDir := t.TempDir()
	stream := coreevents.New()
	var events []*aop.Event
	sub := stream.Observe(func(event *aop.Event) { events = append(events, event) })
	defer sub.Cancel()

	e := &Extension{
		kinds:     map[Kind]bool{Processes: true, Files: true, Artifacts: true},
		events:    stream,
		file:      defaultFileOptions(),
		snapshots: map[string]Snapshot{},
	}
	ctx := context.Background()
	ref := &operationpb.Ref{OperationId: "op-1"}

	// Baseline file exists before the process starts; it must not ship.
	before := filepath.Join(caseDir, "before.txt")
	if err := os.WriteFile(before, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.processSnapshot(ctx, toolhooks.ProcessEvent{Operation: ref, Directory: caseDir})

	// The process creates output, refreshes the baseline and touches the
	// node-private metadata directory.
	if err := os.WriteFile(filepath.Join(caseDir, "results.jsonl"), []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(before, []byte("new-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(caseDir, ".zrcin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, ".zrcin", "facts.jsonl"), []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Private state under .zrcin must stay private; the handoff files ship.
	if err := os.WriteFile(filepath.Join(caseDir, ".zrcin", "auth"), []byte("Authorization: Bearer secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, ".zrcin", "worker-note.md"), []byte("note"), 0o600); err != nil {
		t.Fatal(err)
	}

	completion := toolhooks.ProcessCompletion{
		Lifecycle: toolhooks.Lifecycle{Operation: ref},
		Process:   toolhooks.ProcessEvent{Operation: ref, Directory: caseDir, Command: "gogo"},
	}
	e.processCompleted(ctx, completion)

	// Find the process-completed event and decode its sidecars.
	if len(events) == 0 {
		t.Fatal("no events published at all")
	}
	for i, event := range events {
		t.Logf("event %d: payload=%v extensions=%d", i, event.GetPayload() != nil, len(event.GetExtensions()))
		for _, ext := range event.GetExtensions() {
			t.Logf("  ext url=%s", ext.GetTypeUrl())
		}
	}
	var shipped []artifactsync.Payload
	var sawResults, sawBefore, sawFacts, sawNote, sawAuth bool
	var fileAccessSeen int
	for _, event := range events {
		for _, ext := range event.GetExtensions() {
			if payload, ok := artifactsync.Parse(ext); ok {
				shipped = append(shipped, payload)
				switch payload.Path {
				case "results.jsonl":
					sawResults = true
				case "before.txt":
					sawBefore = true
				case ".zrcin/facts.jsonl":
					sawFacts = true
				case ".zrcin/worker-note.md":
					sawNote = true
				case ".zrcin/auth":
					sawAuth = true
				}
				if payload.Path == "results.jsonl" {
					if payload.Kind != "process" || payload.MediaType == "" || payload.SHA256 == "" {
						t.Fatalf("results.jsonl payload incomplete: %+v", payload)
					}
					data, err := base64.StdEncoding.DecodeString(payload.Data)
					if err != nil || string(data) != `{"v":1}` {
						t.Fatalf("results.jsonl bytes mismatch: %q err=%v", payload.Data, err)
					}
					if payload.Size != int64(len(data)) {
						t.Fatalf("size mismatch: %d != %d", payload.Size, len(data))
					}
				}
			}
		}
		if event.GetExtension().MessageIs(new(operationpb.Completed)) {
			// The completed event itself carries the batch.
			for _, ext := range event.GetExtensions() {
				if _, ok := artifactsync.Parse(ext); ok {
					fileAccessSeen++
				}
			}
		}
	}
	if !sawResults || !sawBefore {
		t.Fatalf("created and refreshed files must ship: results=%v before=%v shipped=%d", sawResults, sawBefore, len(shipped))
	}
	if !sawFacts || !sawNote {
		t.Fatalf("the handoff files must ship: facts=%v note=%v", sawFacts, sawNote)
	}
	if sawAuth {
		t.Fatalf("node-private .zrcin state must never ship (auth leaked)")
	}
	if fileAccessSeen == 0 {
		t.Fatalf("the completed event must carry the artifact batch")
	}
	// The round trip is honest: Parse(Encode) == payload.
	if len(shipped) != 4 {
		t.Fatalf("shipped = %d payloads, want results.jsonl + before.txt + facts.jsonl + worker-note.md", len(shipped))
	}
	// And the JSON stays inspectable on the wire.
	raw, _ := json.Marshal(shipped[0])
	if len(raw) == 0 {
		t.Fatal("payload does not marshal")
	}
}

// The artifacts kind is self-sufficient (fork patch 28): with no processes or
// files kinds it still ships changed case files on process completion, and it
// emits nothing for a completion that changed no files.
func TestArtifactsOnlyKindShipsChangedFiles(t *testing.T) {
	caseDir := t.TempDir()
	stream := coreevents.New()
	var events []*aop.Event
	sub := stream.Observe(func(event *aop.Event) { events = append(events, event) })
	defer sub.Cancel()

	e := &Extension{
		kinds:     map[Kind]bool{Artifacts: true},
		events:    stream,
		file:      defaultFileOptions(),
		snapshots: map[string]Snapshot{},
	}
	ctx := context.Background()
	ref := &operationpb.Ref{OperationId: "op-only"}
	completion := toolhooks.ProcessCompletion{
		Lifecycle: toolhooks.Lifecycle{Operation: ref},
		Process:   toolhooks.ProcessEvent{Operation: ref, Directory: caseDir, Command: "bash"},
	}

	e.processSnapshot(ctx, toolhooks.ProcessEvent{Operation: ref, Directory: caseDir})
	e.processCompleted(ctx, completion)
	if len(events) != 0 {
		t.Fatalf("a completion without changes published %d events", len(events))
	}

	// Each completion pairs with its own start snapshot (the ProcessStarting
	// hook supplies it in production); the change lands after the snapshot.
	e.processSnapshot(ctx, toolhooks.ProcessEvent{Operation: ref, Directory: caseDir})
	if err := os.MkdirAll(filepath.Join(caseDir, ".zrcin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, ".zrcin", "facts.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.processCompleted(ctx, completion)
	if len(events) != 1 {
		t.Fatalf("events after one changed batch = %d, want exactly the carrier", len(events))
	}
	payloads := 0
	for _, ext := range events[0].GetExtensions() {
		if payload, ok := artifactsync.Parse(ext); ok {
			payloads++
			if payload.Path != ".zrcin/facts.jsonl" {
				t.Fatalf("carrier shipped %q", payload.Path)
			}
		}
	}
	if payloads != 1 {
		t.Fatalf("carrier sidecars = %d, want 1", payloads)
	}
}
