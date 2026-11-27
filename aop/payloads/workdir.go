package payloads

import (
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// WorkDirPayload is one session's workspace. SingleTask records the control
// plane's turn-admission contract (only a tracked RunTurn may start model
// execution).
type WorkDirPayload struct {
	WorkDir    string `json:"work_dir"`
	SingleTask bool   `json:"single_task,omitempty"`
}

// WorkDirExtension encodes one session's workspace. Empty returns nil, which
// keeps the upstream behavior (agent process directory) for callers without a
// workspace.
func WorkDirExtension(dir string) *anypb.Any {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	return extension(WorkDirExtensionURL, WorkDirPayload{WorkDir: dir, SingleTask: true})
}

// ParseWorkDir decodes the workspace from an open-session extension. ok is
// false for absent or malformed payloads (empty keeps the agent's own
// directory).
func ParseWorkDir(ext *anypb.Any) (payload WorkDirPayload, ok bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), WorkDirURLs) {
		return WorkDirPayload{}, false
	}
	if err := json.Unmarshal(ext.GetValue(), &payload); err != nil {
		return WorkDirPayload{}, false
	}
	return payload, true
}
