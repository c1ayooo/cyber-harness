package payloads

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
)

// Case-seed limits mirror the evidence sidecar's (one 8 MiB file, a 64 MiB
// request): a control plane that believes it delivered the inputs must not
// silently ship more than the node accepts.
const (
	MaxSeedFileBytes = 8 << 20
	MaxSeedFiles     = 16
	MaxSeedBytes     = 64 << 20
)

// CaseSeedFile is one file the control plane materializes in the turn's
// workspace before the turn runs.
type CaseSeedFile struct {
	Path string
	Mode uint32
	Data []byte
}

// caseSeedWireFile is the wire form: base64 data, permission-bit modes.
type caseSeedWireFile struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
	Data string `json:"data"`
}

type caseSeedPayload struct {
	Files []caseSeedWireFile `json:"files"`
}

// CaseSeedExtension encodes the seed files. A file beyond the limits is an
// error: the control plane must learn its inputs cannot land, not discover it
// from the node's refusal.
func CaseSeedExtension(files []CaseSeedFile) (*anypb.Any, error) {
	if len(files) == 0 {
		return nil, nil
	}
	if len(files) > MaxSeedFiles {
		return nil, fmt.Errorf("case seed: %d files exceed the %d-file limit", len(files), MaxSeedFiles)
	}
	payload := caseSeedPayload{Files: make([]caseSeedWireFile, 0, len(files))}
	total := 0
	for _, file := range files {
		if len(file.Data) > MaxSeedFileBytes {
			return nil, fmt.Errorf("case seed: %s is %d bytes, over the %d-byte file limit", file.Path, len(file.Data), MaxSeedFileBytes)
		}
		total += len(file.Data)
		if total > MaxSeedBytes {
			return nil, fmt.Errorf("case seed: batch exceeds the %d-byte request limit", MaxSeedBytes)
		}
		payload.Files = append(payload.Files, caseSeedWireFile{
			Path: file.Path, Mode: file.Mode, Data: base64.StdEncoding.EncodeToString(file.Data),
		})
	}
	return extension(CaseSeedExtensionURL, payload), nil
}

// ParseCaseSeed decodes the seed files. An absent extension is (nil, nil); a
// malformed payload is an ERROR — a control plane that believes it delivered
// the inputs must learn that it did not (the caller fails the turn), instead
// of the model reading stale or missing context.
func ParseCaseSeed(ext *anypb.Any) ([]CaseSeedFile, error) {
	if ext == nil || !matches(ext.GetTypeUrl(), CaseSeedURLs) {
		return nil, nil
	}
	var payload caseSeedPayload
	if err := json.Unmarshal(ext.GetValue(), &payload); err != nil {
		return nil, fmt.Errorf("case seed payload: %w", err)
	}
	files := make([]CaseSeedFile, 0, len(payload.Files))
	for i, wire := range payload.Files {
		data, err := base64.StdEncoding.DecodeString(wire.Data)
		if err != nil {
			return nil, fmt.Errorf("case seed file %d data: %w", i, err)
		}
		files = append(files, CaseSeedFile{Path: wire.Path, Mode: wire.Mode, Data: data})
	}
	return files, nil
}
