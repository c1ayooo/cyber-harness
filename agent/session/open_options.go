package session

import "github.com/chainreactors/cyber/agent"

// applyOpenOptions lands what the fork adds to the agent config a session is
// opened with.
//
// The model-facing conversation id is the logical session id: a rotation
// (/clear, /compact, resume) opens its continuation under a new physical id,
// and the model conversation survives that change (model_session_test.go).
//
// A workspace the control plane named for this session replaces the config's;
// without one the session keeps the agent's working directory.
func applyOpenOptions(config *agent.Config, options SessionOptions, logicalID string) {
	config.ModelSessionID = logicalID
	if options.WorkDir != "" {
		config.WorkDir = options.WorkDir
	}
}
