package session

import (
	"context"
	"testing"
	"time"

	"github.com/chainreactors/cyber/agent"
	"github.com/chainreactors/cyber/agent/inbox"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestAOPManagedMailboxWaitsForExplicitTurnAndPreservesPolicyOnRotation(t *testing.T) {
	provider := &runtimeSemanticProvider{}
	rt := newBareRuntime(t, nil, provider)
	// The managed policy rides the open request: a registered open decorator
	// (seam G1) lands it in the options, and the runtime must carry it across
	// rotation. The WorkDir payload's own decoding is 4zsession's (its tests).
	rt.config.OpenSessionDecorators = []OpenSessionDecorator{managedOpenDecorator}
	response := rt.OpenAOPSession(&aop.OpenSessionRequest{SessionId: "managed", Extensions: []*anypb.Any{{TypeUrl: payloads.WorkDirExtensionURL, Value: []byte(`{"single_task":true}`)}}})
	if response.GetAccepted() == nil {
		t.Fatalf("open: %v", response.GetRejected())
	}
	s, err := rt.EnsureSession(SessionOptions{ID: "managed"})
	if err != nil {
		t.Fatal(err)
	}
	assertIdle := func() {
		t.Helper()
		before := provider.callCount()
		if err := s.Deliver(t.Context(), inbox.NewSystemMessage("peer update")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
		if provider.callCount() != before {
			t.Fatal("idle mailbox created an unowned model turn")
		}
		if s.state.inbox.Len() == 0 {
			t.Fatal("idle message was dropped")
		}
	}
	assertIdle()
	run, err := s.Run(t.Context(), RunInput{Message: agent.TextInput("tracked turn")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Wait(); err != nil {
		t.Fatal(err)
	}
	if provider.callCount() != 1 {
		t.Fatalf("explicit turn calls = %d", provider.callCount())
	}
	assertIdle()
	if _, err := s.rotate(context.Background(), SessionCloseCleared, s.ID(), nil); err != nil {
		t.Fatal(err)
	}
	assertIdle()
	run, err = s.Run(t.Context(), RunInput{Message: agent.TextInput("next tracked turn")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Wait(); err != nil {
		t.Fatal(err)
	}
	if provider.callCount() != 2 {
		t.Fatal("managed session could not continue explicitly")
	}
}

// managedOpenDecorator stands in for the 4zsession decorator this package
// cannot import (the block imports agent/session): the WorkDir extension's
// single_task flag selects the managed mailbox.
func managedOpenDecorator(req *aop.OpenSessionRequest, options *SessionOptions) error {
	if value, ok := payloads.ParseWorkDir(payloads.ExtensionWithURL(req.GetExtensions(), payloads.WorkDirURLs)); ok {
		options.SingleTask = value.SingleTask
	}
	return nil
}

func TestManagedActiveSessionStillAdmitsPeerMail(t *testing.T) {
	rt := newBareRuntime(t, nil, &runtimeSemanticProvider{})
	entered, release := make(chan struct{}), make(chan struct{})
	cfg := rt.agentConfig.WithLoop(taskLoop(func(ctx context.Context, cfg agent.Config) (*agent.Result, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &agent.Result{}, nil
	}))
	s, err := rt.OpenSession(t.Context(), SessionOptions{ID: "active", Config: &cfg, SingleTask: true})
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Run(t.Context(), RunInput{Message: agent.TextInput("work")})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := s.Deliver(t.Context(), inbox.NewSystemMessage("new peer observation")); err != nil {
		t.Fatal(err)
	}
	if s.state.inbox.Len() == 0 {
		t.Fatal("active peer mail was not admitted")
	}
	close(release)
	if _, err := run.Wait(); err != nil {
		t.Fatal(err)
	}
}
