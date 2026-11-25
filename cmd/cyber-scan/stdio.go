package main

import (
	"context"
	"fmt"
	"io"

	"github.com/c1ayooo/cyber/agent"
	agentsession "github.com/c1ayooo/cyber/agent/session"
	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/telemetry"
	taskcli "github.com/c1ayooo/cyber/pkg/cli/task"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	"github.com/c1ayooo/cyber/pkg/host"
	"github.com/c1ayooo/cyber/pkg/profile"
)

// RunStdio assembles a Profile around the transport-only host.
func runStdio(ctx context.Context, newProfile func(profile.Request) (profile.Profile, error), option *cfg.Option, logger telemetry.Logger, input io.Reader, output io.Writer, outputTask *taskcli.Output) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p, rt, err := loadAgentProfile(ctx, newProfile, option, logger, &agentsession.Config{Loop: agent.StandardLoop{}})
	if err != nil {
		return err
	}
	outputTask.Observe(rt)
	mux := aop.NewNamespaceMux(ctx)
	if err := p.RegisterNamespaces(mux); err != nil {
		_ = mux.Close(context.Background())
		_ = p.Close(context.Background())
		return err
	}
	h := host.New(mux)
	stream := host.NewStdio(input, output)
	unsubscribe := rt.Observe(func(event *aop.Event) {
		_ = h.Send(aop.Reply("", &aop.ProtocolMessage{Message: &aop.ProtocolMessage_Event{Event: event}}), stream.Send)
	})
	// One owner closes in dependency order and checks failures from the last
	// session-ended events as well as ordinary replies.
	defer func() {
		_ = p.Close(context.Background())
		unsubscribe.Cancel()
		h.Close()
		if err := h.Err(); err != nil {
			runErr = fmt.Errorf("write stdio protocol: %w", err)
		}
	}()
	err = h.Serve(stream)
	if err != nil {
		cancel()
	}
	// EOF drains admitted work. Keep events subscribed through session closure,
	// then release this connection's listener before checking all write errors.
	rt.WaitOperations()
	if err != nil {
		return fmt.Errorf("stdio protocol: %w", err)
	}
	return nil
}
