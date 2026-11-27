package zsession

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestTurnCaseSeedDecodesBothNamespaces(t *testing.T) {
	for _, url := range payloads.CaseSeedURLs {
		req := seedRequest(t, url, []payloads.CaseSeedFile{{Path: ".zrcin/context.json", Mode: 0o640, Data: []byte("{}")}})
		files, err := turnCaseSeed(req)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		if len(files) != 1 || files[0].Path != ".zrcin/context.json" || string(files[0].Data) != "{}" || files[0].Mode != 0o640 {
			t.Fatalf("%s decoded %+v", url, files)
		}
	}
	if files, err := turnCaseSeed(&aop.RunTurnRequest{}); err != nil || len(files) != 0 {
		t.Fatalf("a request without the extension = %v %v", files, err)
	}
	// A malformed payload must fail the turn, not silently drop the inputs.
	bad := &aop.RunTurnRequest{Extensions: []*anypb.Any{{TypeUrl: payloads.CaseSeedURLs[1], Value: []byte("{nope")}}}
	if _, err := turnCaseSeed(bad); err == nil {
		t.Fatal("a malformed seed decoded")
	}
}

func seedRequest(t *testing.T, url string, files []payloads.CaseSeedFile) *aop.RunTurnRequest {
	t.Helper()
	type wireFile struct {
		Path string `json:"path"`
		Mode uint32 `json:"mode"`
		Data string `json:"data"`
	}
	wire := make([]wireFile, 0, len(files))
	for _, f := range files {
		wire = append(wire, wireFile{Path: f.Path, Mode: f.Mode, Data: base64.StdEncoding.EncodeToString(f.Data)})
	}
	raw, err := json.Marshal(map[string]any{"files": wire})
	if err != nil {
		t.Fatal(err)
	}
	return &aop.RunTurnRequest{Extensions: []*anypb.Any{{TypeUrl: url, Value: raw}}}
}
