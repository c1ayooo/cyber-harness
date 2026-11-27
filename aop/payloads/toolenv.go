package payloads

import (
	"encoding/json"
	"sort"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// ToolEnvPayload is the per-turn tool environment as KEY=VALUE pairs.
type ToolEnvPayload struct {
	Env map[string]string `json:"env"`
}

// ToolEnvExtension encodes the environment map. Empty returns nil.
func ToolEnvExtension(env map[string]string) *anypb.Any {
	if len(env) == 0 {
		return nil
	}
	return extension(ToolEnvExtensionURL, ToolEnvPayload{Env: env})
}

// ParseToolEnv decodes the tool environment as sorted KEY=VALUE pairs. ok is
// false when the extension is absent or malformed.
func ParseToolEnv(ext *anypb.Any) ([]string, bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), ToolEnvURLs) {
		return nil, false
	}
	var payload ToolEnvPayload
	if err := json.Unmarshal(ext.GetValue(), &payload); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(payload.Env))
	for _, key := range sortedKeys(payload.Env) {
		out = append(out, key+"="+payload.Env[key])
	}
	return out, true
}

func sortedKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
