// Package artifactsync carries run evidence from the node's case directory
// back to the control plane as 4zrcin.Artifact sidecars (fork patch 23c,
// 4zrcin docs/rules.md). Remote scan nodes share no filesystem with the hub: the evidence
// bytes travel inside the Envelope stream instead, and the control plane lands
// them in the central case directory. Old hubs ignore the unknown sidecar and
// old nodes never send it, so the two sides can upgrade independently.
//
// The payload is JSON inside a hand-built anypb.Any — the fork's extension
// convention (every 4zrcin.* sidecar is JSON-in-Any, never a generated proto),
// which keeps the wire shape reviewable and the codec three lines long on both
// ends.
package artifactsync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// ExtensionURL is the type URL of the Artifact sidecar in an aop.Event's
// Extensions list. The control plane matches on the exact URL and keeps every
// other sidecar untouched.
const ExtensionURL = "type.googleapis.com/4zrcin.Artifact"

// Limits bound one evidence batch. They exist because the bytes ride the same
// bidirectional stream as the session protocol: an unbounded run output (a
// runaway log, a dd image) must not starve it. One file is capped at 8 MiB,
// a batch at 16 files / 64 MiB; over-limit files are skipped, never truncated.
const (
	MaxFileBytes     = 8 << 20
	MaxFilesPerBatch = 16
	MaxBatchBytes    = 64 << 20
)

// Payload is the JSON body of one Artifact sidecar. Path is relative to the
// case directory so the control plane can place the file without knowing the
// node's layout; Data is base64 of the file content.
type Payload struct {
	Path      string `json:"path"`
	Kind      string `json:"kind,omitempty"` // process | file — what produced it
	MediaType string `json:"media_type,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Data      string `json:"data,omitempty"`
}

// Encode renders one payload as the sidecar anypb.Any.
func Encode(p Payload) (*anypb.Any, error) {
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &anypb.Any{TypeUrl: ExtensionURL, Value: encoded}, nil
}

// Parse decodes one extension as an Artifact sidecar; ok is false for any
// other type URL or an undecodable body — callers keep the event untouched.
func Parse(ext *anypb.Any) (Payload, bool) {
	if ext == nil || ext.GetTypeUrl() != ExtensionURL {
		return Payload{}, false
	}
	var p Payload
	if err := json.Unmarshal(ext.GetValue(), &p); err != nil {
		return Payload{}, false
	}
	return p, true
}

// Change is one file change the caller wants shipped. RelPath is relative to
// the case directory; Deleted changes are never collected (there is nothing to
// ship), they exist so callers can pass a diff verbatim.
type Change struct {
	RelPath string
	AbsPath string
	Deleted bool
}

// Collect reads the changed files under limits and renders their sidecars.
// Reading is best-effort: a file that vanished between the snapshot and the
// read is skipped, because the FileAccess observation already recorded the
// metadata — the sidecar is only for bytes.
func Collect(kind string, changes []Change, limits Limits) []*anypb.Any {
	if limits.MaxFileBytes <= 0 {
		limits = Limits{MaxFileBytes: MaxFileBytes, MaxFiles: MaxFilesPerBatch, MaxTotalBytes: MaxBatchBytes}
	}
	var out []*anypb.Any
	var total int64
	for _, change := range changes {
		if change.Deleted || change.RelPath == "" || len(out) >= limits.MaxFiles || total >= limits.MaxTotalBytes {
			break
		}
		if skipsArtifact(change.RelPath) {
			continue
		}
		payload, err := buildPayload(kind, change.RelPath, change.AbsPath, limits.MaxFileBytes)
		if err != nil {
			continue
		}
		total += payload.Size
		if encoded, err := Encode(payload); err == nil {
			out = append(out, encoded)
		}
	}
	return out
}

// FromData renders one sidecar from content the caller already holds (a file
// hook that carried the bytes in-band), with the same hash and media-type
// treatment as Collect. Empty content and over-limit sizes are errors.
func FromData(kind, relPath string, data []byte, maxBytes int) (*anypb.Any, error) {
	if maxBytes <= 0 {
		maxBytes = MaxFileBytes
	}
	if len(data) == 0 || len(data) > maxBytes {
		return nil, fmt.Errorf("artifactsync: %s: empty or over %d bytes", relPath, maxBytes)
	}
	sum := sha256.Sum256(data)
	encoded, err := Encode(Payload{
		Path:      filepath.ToSlash(relPath),
		Kind:      kind,
		MediaType: mediaType(relPath),
		Size:      int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
		Data:      base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// Limits bounds one Collect batch; zero fields fall back to the constants.
type Limits struct {
	MaxFileBytes  int
	MaxFiles      int
	MaxTotalBytes int64
}

// skipsArtifact excludes the node's own metadata from evidence: .zrcin holds
// the node's private state, not run output. Default-deny: only the two handoff
// files a control plane reads back may ship (fork patch 27) — everything else
// under .zrcin (auth, identity.json, aop-session.json, offsets, future files)
// stays excluded, so a new private file cannot leak by accident.
func skipsArtifact(relPath string) bool {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	last := -1
	for i, part := range parts {
		if part == ".zrcin" {
			last = i
		}
	}
	if last < 0 {
		return false
	}
	rest := parts[last+1:]
	if len(rest) != 1 {
		return true
	}
	switch rest[0] {
	case "facts.jsonl", "worker-note.md":
		return false
	}
	return true
}

func buildPayload(kind, relPath, absPath string, maxBytes int) (Payload, error) {
	info, err := os.Stat(absPath)
	if err != nil || !info.Mode().IsRegular() {
		return Payload{}, fmt.Errorf("artifactsync: %s: %w", relPath, err)
	}
	if info.Size() > int64(maxBytes) {
		return Payload{}, fmt.Errorf("artifactsync: %s exceeds %d bytes", relPath, maxBytes)
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Payload{}, err
	}
	sum := sha256.Sum256(data)
	return Payload{
		Path:      filepath.ToSlash(relPath),
		Kind:      kind,
		MediaType: mediaType(absPath),
		Size:      int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
		Data:      base64.StdEncoding.EncodeToString(data),
	}, nil
}

func mediaType(path string) string {
	if t := mime.TypeByExtension(filepath.Ext(path)); t != "" {
		return t
	}
	return "application/octet-stream"
}
