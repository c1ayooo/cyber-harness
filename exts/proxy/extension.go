// Package proxy adapts proxy resources to the Profile extension lifecycle.
package proxy

import (
	"context"
	"github.com/chainreactors/cyber/core/egress"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	coretool "github.com/chainreactors/cyber/core/tool"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	cfg "github.com/chainreactors/cyber/pkg/config"
	proxytool "github.com/chainreactors/cyber/tools/proxy"
)

// Config is what the profile chooses. Everything the extension borrows comes
// from the capability registry instead.
type Config struct {
	WorkDir string
	// Proxy is the upstream the host was started with. It is also the fallback
	// the proxy commands report when no hub route applies.
	Proxy string
	// ControlPlaneHost is the control plane's host (the agent server URL's
	// host). Requests naming it — the executor's own bookkeeping — forward
	// unjudged and uncaptured (fork patch 36). Empty exempts nothing.
	ControlPlaneHost string
	Capture          bool
	Storage          cfg.TrafficOptions
}

// Extension owns one proxy Resource and publishes it as the Endpoint
// capability. Consumers receive the interface, whose implementations have no
// lifecycle methods; the extension graph alone starts and closes the resource.
type Extension struct {
	config   Config
	resource *proxytool.Resource
}

func New(config Config) *Extension { return &Extension{config: config} }

func (e *Extension) Load(scope *extension.Scope) error {
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	executor, err := extension.Use[coretool.CommandExecutor](scope)
	if err != nil {
		return err
	}
	resource, err := proxytool.NewHub(e.config.WorkDir, e.config.Proxy, e.config.Capture, registry, e.config.Storage)
	if err != nil {
		return err
	}
	resource.Hub.SetControlPlaneHost(e.config.ControlPlaneHost)
	e.resource = resource
	hub := resource.Hub
	// The scope judge is the guardrail runtime when one is installed (it loads
	// ahead of this extension). An embedder without guardrail keeps a judgeless
	// hub: the proxy stays a pure capture/routing relay.
	if runtime, judgeErr := extension.Use[*guardrailext.Runtime](scope); judgeErr == nil {
		hub.SetScopeJudge(runtime)
	}

	binding, err := proxytool.TrafficNamespace(hub)
	if err != nil {
		return err
	}
	if err := extension.Add(scope, binding); err != nil {
		return err
	}
	// The proxy commands read the hub's own state, so they belong to the hub's
	// owner rather than to whichever extension happened to hold a reference.
	if err := extension.Add(scope, proxytool.NewCommands(func(ctx context.Context, argv []string, parent *coretool.Execution) (any, error) {
		return coretool.RunCommand(ctx, executor, argv, parent)
	}, hub, e.config.Proxy)...); err != nil {
		return err
	}
	if err := extension.Provide[egress.Endpoint](scope, hub); err != nil {
		return err
	}
	return e.resource.Start(scope.Init())
}

func (e *Extension) Close(ctx context.Context) error {
	if e == nil || e.resource == nil {
		return nil
	}
	return e.resource.Close(ctx)
}

var _ extension.Extension = (*Extension)(nil)
