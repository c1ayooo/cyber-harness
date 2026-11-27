package payloads

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/anypb"
)

// MaxArtifactBytes is the wire cap for one evidence file — the engine's
// artifactsync limit, now the single limit both sides compile.
const MaxArtifactBytes = 8 << 20

// Artifact is one evidence sidecar: a changed case-directory file the node
// ships to the control plane's case directory.
type Artifact struct {
	Path      string `json:"path"`
	Kind      string `json:"kind,omitempty"` // process | file — what produced it
	MediaType string `json:"media_type,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	// Data is the file bytes. encoding/json renders []byte as base64 on the
	// wire, which is exactly the shape both sides already exchanged.
	Data []byte `json:"data,omitempty"`
}

// Valid reports whether the sidecar carries landable bytes with a stable
// identity. A path-less or empty artifact is dropped, never guessed into the
// case directory.
func (a Artifact) Valid() bool {
	return a.Path != "" && len(a.Data) > 0 && len(a.Data) <= MaxArtifactBytes
}

// ArtifactExtension encodes the evidence sidecar.
func ArtifactExtension(a Artifact) *anypb.Any {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil
	}
	return &anypb.Any{TypeUrl: ArtifactExtensionURL, Value: raw}
}

// ParseArtifact decodes one evidence sidecar. ok is false for anything that
// is not a landable artifact of this namespace; the caller keeps such events
// untouched instead of guessing.
func ParseArtifact(ext *anypb.Any) (Artifact, bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), ExtensionURLs("Artifact")) {
		return Artifact{}, false
	}
	var a Artifact
	if err := json.Unmarshal(ext.GetValue(), &a); err != nil {
		return Artifact{}, false
	}
	if !a.Valid() {
		return Artifact{}, false
	}
	return a, true
}
