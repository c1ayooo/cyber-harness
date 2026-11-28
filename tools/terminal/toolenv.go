package terminal

import "strings"

// mergeToolEnv layers the per-turn tool environment beneath explicit
// per-invocation overrides: a caller that sets BashExecOptions.Env on purpose
// still wins, so a control plane cannot silently shadow a value the caller
// chose. It returns nil when there is nothing to add, keeping runEnv's map
// allocation unchanged for every call without a tool environment.
func mergeToolEnv(turnEnv []string, overrides map[string]string) map[string]string {
	if len(turnEnv) == 0 {
		return overrides
	}
	merged := make(map[string]string, len(turnEnv)+len(overrides))
	for _, item := range turnEnv {
		if key, value, ok := strings.Cut(item, "="); ok && key != "" {
			merged[key] = value
		}
	}
	for key, value := range overrides {
		merged[key] = value
	}
	return merged
}
