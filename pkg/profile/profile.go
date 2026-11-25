// Package profile defines the lifecycle boundary shared by Cyber hosts.
// Composition belongs to the concrete distribution that implements Profile
// and owns its extension.Set.
package profile

import (
	"context"

	"github.com/c1ayooo/cyber/agent/provider"
	agentsession "github.com/c1ayooo/cyber/agent/session"
	"github.com/c1ayooo/cyber/aop"
	toolpb "github.com/c1ayooo/cyber/aop/tool"
	"github.com/c1ayooo/cyber/core/eventbus"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/proc"
	"github.com/c1ayooo/cyber/core/telemetry"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	consoleapi "github.com/c1ayooo/cyber/pkg/console/api"
)

// Profile is the complete runtime surface published by a composition root.
// Load must publish nothing until the whole graph is active.
type Profile interface {
	Load(context.Context) error
	Close(context.Context) error
	Active() bool
	Providers() (*provider.State, error)
	Events() (*events.Stream, error)
	Progress() (*eventbus.Bus[*toolpb.Progress], error)
	Processes() (*proc.Manager, error)
	Runtime() (*agentsession.Runtime, error)
	RegisterNamespaces(*aop.NamespaceMux) error
	AgentStatus() *aop.AgentStatus
	// ConsoleBindings publishes optional presentation contributions.
	ConsoleBindings() *consoleapi.Bindings
}

// Request contains host-selected inputs. Extension selection and resource
// construction remain decisions of the concrete distribution constructor.
type Request struct {
	Option       *cfg.Option
	ProviderMode provider.StartupMode
	Session      *agentsession.Config
	Logger       telemetry.Logger
}
