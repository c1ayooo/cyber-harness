package zsession

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

	agentsession "github.com/chainreactors/cyber/agent/session"
	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
)

// A resumed turn never re-opens its session: after a host restart the session is
// re-created and has no workspace, so the turn itself must be able to supply it.
func TestTurnWorkDirDecodesTheTianwuExtension(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"work_dir": `C:\data\projects\p\cases\in_1`})
	if err != nil {
		t.Fatal(err)
	}
	req := &aop.RunTurnRequest{Extensions: []*anypb.Any{{TypeUrl: payloads.WorkDirURLs[0], Value: raw}}}
	if got := turnWorkDir(req); got != `C:\data\projects\p\cases\in_1` {
		t.Fatalf("turnWorkDir = %q", got)
	}
	if turnWorkDir(&aop.RunTurnRequest{}) != "" {
		t.Fatal("a request without the extension must not name a workspace")
	}
}

// The session's workspace rides the open request (seam G1): the decorator
// lands the payload's directory and scheduling flag in the options, under
// either fork namespace, and leaves the options alone when the request names
// nothing.
func TestOpenWorkDirDecoratorLandsWorkspaceAndFlag(t *testing.T) {
	open := func(url string, payload []byte) *aop.OpenSessionRequest {
		return &aop.OpenSessionRequest{Extensions: []*anypb.Any{{TypeUrl: url, Value: payload}}}
	}
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		options := agentsession.SessionOptions{}
		err := openWorkDirDecorator(open("type.googleapis.com/"+namespace+".WorkDir",
			mustJSON(t, payloads.WorkDirPayload{WorkDir: " /tmp/case-1 ", SingleTask: true})), &options)
		if err != nil || options.WorkDir != "/tmp/case-1" || !options.SingleTask {
			t.Fatalf("%s: err=%v options=%+v", namespace, err, options)
		}
	}
	// A bare flag still selects the managed mailbox; a bare directory still
	// moves the workspace.
	options := agentsession.SessionOptions{}
	if err := openWorkDirDecorator(open(payloads.WorkDirURLs[0], []byte(`{"single_task":true}`)), &options); err != nil || options.WorkDir != "" || !options.SingleTask {
		t.Fatalf("bare flag: err=%v options=%+v", err, options)
	}
	options = agentsession.SessionOptions{}
	if err := openWorkDirDecorator(open(payloads.WorkDirURLs[0], []byte(`{"work_dir":"/tmp/case-2"}`)), &options); err != nil || options.WorkDir != "/tmp/case-2" || options.SingleTask {
		t.Fatalf("bare directory: err=%v options=%+v", err, options)
	}
	// Nothing attached, or an empty payload: an earlier decorator's options
	// stay as they are.
	for _, req := range []*aop.OpenSessionRequest{nil, {}, open(payloads.WorkDirURLs[0], []byte(`{"work_dir":"  "}`))} {
		options := agentsession.SessionOptions{ID: "kept", WorkDir: "/tmp/earlier", SingleTask: true}
		if err := openWorkDirDecorator(req, &options); err != nil || options.ID != "kept" || options.WorkDir != "/tmp/earlier" || !options.SingleTask {
			t.Fatalf("req=%v: err=%v options=%+v", req, err, options)
		}
	}
}

// Decorate registers both decorator kinds and keeps whatever the composition
// appended first ahead of them.
func TestDecorateAppendsBothDecoratorKinds(t *testing.T) {
	firstRan := false
	first := func(*aop.RunTurnRequest, *agentsession.RunInput) error { firstRan = true; return nil }
	config := agentsession.Config{TurnDecorators: []agentsession.RunTurnDecorator{first}}
	Decorate(&config)
	if len(config.TurnDecorators) != 1+len(TurnDecorators()) {
		t.Fatalf("turn decorators = %d, want %d", len(config.TurnDecorators), 1+len(TurnDecorators()))
	}
	_ = config.TurnDecorators[0](nil, &agentsession.RunInput{})
	if !firstRan {
		t.Fatalf("the decorator the composition appended first no longer runs first")
	}
	if len(config.OpenSessionDecorators) != 1 || config.OpenSessionDecorators[0] == nil {
		t.Fatalf("open decorators = %d", len(config.OpenSessionDecorators))
	}
}
