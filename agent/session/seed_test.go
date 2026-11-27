package session

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainreactors/cyber/agent"
	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
	"google.golang.org/protobuf/types/known/anypb"
)

func seedRequest(t *testing.T, url string, files []CaseSeedFile) *aop.RunTurnRequest {
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

func TestTurnCaseSeedDecodesBothNamespaces(t *testing.T) {
	for _, url := range payloads.CaseSeedURLs {
		req := seedRequest(t, url, []CaseSeedFile{{Path: ".zrcin/context.json", Mode: 0o640, Data: []byte("{}")}})
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

func TestApplyCaseSeedWritesUnderWorkspace(t *testing.T) {
	dir := t.TempDir()
	ag := agent.NewAgent(agent.Config{})
	ag.SetWorkDir(dir)
	err := applyCaseSeed(ag, []CaseSeedFile{
		{Path: ".zrcin/context.json", Mode: 0o640, Data: []byte(`{"pages":2}`)},
		{Path: "cases/in_1/brief.md", Data: []byte("brief")},
	})
	if err != nil {
		t.Fatalf("applyCaseSeed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".zrcin", "context.json"))
	if err != nil || string(raw) != `{"pages":2}` {
		t.Fatalf("seed content = %q %v", raw, err)
	}
	info, _ := os.Stat(filepath.Join(dir, ".zrcin", "context.json"))
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("seed mode = %o, want 640", info.Mode().Perm())
	}
	// A file without a mode defaults to 0600: seeds carry credentials
	// sometimes (.zrcin/auth), so the default must be private.
	info, _ = os.Stat(filepath.Join(dir, "cases", "in_1", "brief.md"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("default seed mode = %o, want 600", info.Mode().Perm())
	}
}

func TestApplyCaseSeedRefusesEscapes(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	ag := agent.NewAgent(agent.Config{})
	ag.SetWorkDir(dir)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	for _, path := range []string{"/etc/passwd", "../x", "a/../../x", "link/x"} {
		if err := applyCaseSeed(ag, []CaseSeedFile{{Path: path, Data: []byte("x")}}); err == nil {
			t.Fatalf("seed path %q was accepted", path)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("a seed escaped through the symlink: %d files", len(entries))
	}
}

func TestApplyCaseSeedLimits(t *testing.T) {
	ag := agent.NewAgent(agent.Config{})
	ag.SetWorkDir(t.TempDir())
	tooMany := make([]CaseSeedFile, SeedFilesLimit+1)
	for i := range tooMany {
		tooMany[i] = CaseSeedFile{Path: "f" + string(rune('a'+i)), Data: []byte("x")}
	}
	if err := applyCaseSeed(ag, tooMany); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("file count limit = %v", err)
	}
	big := []CaseSeedFile{{Path: "big", Data: make([]byte, SeedFileLimit+1)}}
	if err := applyCaseSeed(ag, big); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("file size limit = %v", err)
	}
}

func TestApplyCaseSeedNeedsWorkspace(t *testing.T) {
	ag := agent.NewAgent(agent.Config{})
	if err := applyCaseSeed(ag, []CaseSeedFile{{Path: "f", Data: []byte("x")}}); err == nil {
		t.Fatal("a seed without a workspace was accepted")
	}
	if err := applyCaseSeed(ag, nil); err != nil {
		t.Fatalf("an empty seed must be a no-op: %v", err)
	}
}
