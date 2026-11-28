package agent

// WorkDir returns the workspace tools resolve relative paths in, or "" when the
// session never received one (it then falls back to the agent process directory).
func (a *Agent) WorkDir() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Cfg.WorkDir
}

// SetWorkDir binds a session's workspace after creation. A resumed turn is the
// reason this exists: the turn never re-opens the session, so a session that the
// host re-created after a restart has no workspace unless the turn supplies one.
// It only fills an empty workspace — the caller refuses a conflicting one, so a
// live session is never silently moved to another directory.
func (a *Agent) SetWorkDir(dir string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Cfg.WorkDir = dir
}
