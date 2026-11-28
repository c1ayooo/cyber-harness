package operation

import "context"

type toolEnvKey struct{}

// ContextWithToolEnv attaches the environment a control plane wants every tool
// subprocess of this turn to inherit, as an explicit list of KEY=VALUE. It is a
// separate context value rather than an Invocation field because tool
// boundaries rebuild Invocation for their own correlation and must not drop the
// environment on the way. Empty is a no-op: a turn without it inherits nothing
// extra, so a previous turn's values can never bleed into this one.
func ContextWithToolEnv(ctx context.Context, env []string) context.Context {
	if ctx == nil || len(env) == 0 {
		return ctx
	}
	return context.WithValue(ctx, toolEnvKey{}, env)
}

// ToolEnvFromContext returns the per-turn tool environment, or nil.
func ToolEnvFromContext(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	env, _ := ctx.Value(toolEnvKey{}).([]string)
	return env
}
