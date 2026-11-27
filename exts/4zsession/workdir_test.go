package zsession

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"

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
