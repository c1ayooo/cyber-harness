package session

import "github.com/chainreactors/cyber/aop/payloads"

// The canonical (oldest) URL of each fork payload, so the extension tests keep
// pinning the pre-rename namespace while the parser accepts both generations.
// The URL lists live in the payload contract package.
func forkRunGoalExtensionURL() string { return payloads.RunGoalURLs[0] }
func forkWorkDirExtensionURL() string { return payloads.WorkDirURLs[0] }
func forkToolEnvExtensionURL() string { return payloads.ToolEnvURLs[0] }
