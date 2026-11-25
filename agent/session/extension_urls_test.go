package session

// The canonical (oldest) URL of each fork payload, so the extension tests keep
// pinning the pre-rename namespace while the parser accepts both generations.
func forkRunGoalExtensionURL() string { return runGoalExtensionURLs[0] }
func forkWorkDirExtensionURL() string { return forkWorkDirExtensionURLs[0] }
func forkToolEnvExtensionURL() string { return toolEnvExtensionURLs[0] }
