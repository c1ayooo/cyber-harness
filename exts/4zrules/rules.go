// Package rules is the rule hot-reload brick (4zrcin docs/rules.md). It watches a
// directory of instance rules and adds what changed to the scanner's live
// engines, so a node picks up new fingerprints and POCs on the next tool call
// instead of on the next start.
//
// The engines are mutated in place and carry no lock of their own, so a
// change is applied only while no scan is in flight: tool.started records a
// scan call by id and tool.completed releases it. The executor pairs the two
// (Completed is emitted from a defer that covers every exit), so the count
// cannot leak, and a call the fence denied never counts because it never
// started. What the sdk cannot apply in place is reported, never guessed:
// AddPocs appends, so a rewritten POC and a removed file take effect after a
// node restart and the state file says so.
package rules

import (
	"context"
	"sync"
	"time"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/resource"
	"github.com/chainreactors/cyber/core/telemetry"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	rulesconfig "github.com/chainreactors/cyber/exts/4zrules/config"
	cfg "github.com/chainreactors/cyber/pkg/config"
	"github.com/chainreactors/cyber/tools/scan/engine"
)

const (
	// source names the brick's hook subscriptions.
	source = "4zrules"
	// checkInterval is how often an idle node looks for a change, so a rule
	// saved while nothing runs is applied without waiting for the next call.
	checkInterval = time.Second
)

// scanTools are the tools that read the live engines. A call of one of them
// keeps the engines busy for as long as it runs.
var scanTools = map[string]bool{"gogo": true, "neutron": true, "spray": true, "scan": true}

// Extension is the rule hot-reload brick.
type Extension struct {
	config rulesconfig.Config

	mu       sync.Mutex
	logger   telemetry.Logger
	set      *engine.Set
	subs     []*hooks.Subscription
	inflight map[string]struct{}
	applied  map[string]fileRecord
	// signature is the directory state the records describe. known is false
	// until the first apply, so an empty library is reported at load instead
	// of looking unchanged.
	signature string
	known     bool
	// builtin counts what the node started with, before any instance rule.
	builtin Counts
	pending bool
	errText string
	updated time.Time
	stop    chan struct{}
	done    chan struct{}
}

var _ extension.Extension = (*Extension)(nil)

// New builds the brick without loading it. An empty directory leaves it inert.
func New(config rulesconfig.Config) *Extension {
	return &Extension{
		config:   config,
		inflight: make(map[string]struct{}),
		applied:  make(map[string]fileRecord),
	}
}

// Declare registers the rule directory section.
func Declare(resources *resource.Registry) error {
	_, err := resource.Add[cfg.Section](resources, rulesconfig.Section())
	return err
}

// Load borrows the live engine set and starts watching. Without a directory
// the brick is inert: it borrows nothing and subscribes to nothing, so a node
// that was not given a directory is exactly as it was.
func (e *Extension) Load(scope *extension.Scope) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.config.Dir == "" {
		return nil
	}
	if err := scope.Init().Err(); err != nil {
		return err
	}
	logger, err := extension.Use[telemetry.Logger](scope)
	if err != nil {
		return err
	}
	set, err := extension.Use[*engine.Set](scope)
	if err != nil {
		return err
	}
	registry, err := extension.Use[*hooks.Registry](scope)
	if err != nil {
		return err
	}
	e.logger, e.set = logger, set
	if e.ready() {
		e.builtin = Counts{Fingers: set.Fingers.Count(), Pocs: len(set.Neutron.Get())}
		e.writeBuiltins()
	}
	// Nothing can be in flight while the extensions load, so the directory is
	// applied here and a restarted node starts from what is on disk.
	e.refreshLocked(scope.Init())
	e.subs = append(e.subs,
		toolhooks.Started.On(registry, source, e.scanStarted),
		toolhooks.Completed.On(registry, source, e.scanCompleted),
	)
	e.stop, e.done = make(chan struct{}), make(chan struct{})
	go e.watch(scope.Lifetime(), e.stop, e.done)
	return nil
}

// scanStarted runs before a scan call reads the engines. The change is
// applied first and the call is recorded after it: the call that is about to
// run must see the change, and must not run while a later one is applied.
func (e *Extension) scanStarted(ctx context.Context, event toolhooks.CallEvent) (struct{}, error) {
	if !busy(event.Call) {
		return struct{}{}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshLocked(ctx)
	e.inflight[event.Call.Id] = struct{}{}
	return struct{}{}, nil
}

// scanCompleted runs after a scan call has left the engines. What waited for
// this call is applied as soon as it has gone.
func (e *Extension) scanCompleted(ctx context.Context, event toolhooks.Completion) (struct{}, error) {
	if !busy(event.Call) {
		return struct{}{}, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.inflight, event.Call.Id)
	e.refreshLocked(ctx)
	return struct{}{}, nil
}

// busy reports whether a call is one of the tools that read the engines.
func busy(call *aop.ToolCall) bool {
	return call != nil && scanTools[call.Name]
}

// watch looks for a change while the node is idle.
func (e *Extension) watch(lifetime context.Context, stop, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			e.mu.Lock()
			e.refreshLocked(context.Background())
			e.mu.Unlock()
		}
	}
}

// Close releases the hook subscriptions and stops watching.
func (e *Extension) Close(ctx context.Context) error {
	e.mu.Lock()
	for _, sub := range e.subs {
		_ = sub.Close(context.WithoutCancel(ctx))
	}
	e.subs = nil
	var done chan struct{}
	if e.stop != nil {
		close(e.stop)
		e.stop = nil
		done = e.done
	}
	e.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
