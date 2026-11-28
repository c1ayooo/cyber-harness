package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/cyber/tools/resources"
	"github.com/chainreactors/neutron/templates"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
)

// 4zrcin docs/rules.md step 1. A running Set picks up rules that are added in
// place, so the rule hot-reload brick never rebuilds a node. Each test pins
// one sdk behaviour the brick relies on: when the sdk changes one of them the
// matching assertion turns red here before the brick can miss silently.

const (
	hotMarker     = "hot-proof-marker-7f3a9c"
	hotFingerName = "hot-proof-finger"
	hotPocID      = "hot-proof-poc"
	hotFingerYAML = "- name: " + hotFingerName + "\n  rule:\n    - regexps:\n        body:\n          - " + hotMarker + "\n"
	// A template with a request block: compileTemplates silently drops the
	// ones it cannot compile, so a bare id and info never reaches the engine.
	hotPocYAML = "id: " + hotPocID + "\ninfo:\n  name: hot proof poc\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"
)

func hotSet(t *testing.T) *Set {
	t.Helper()
	set, err := InitWithOptions(context.Background(), resources.Options{}, nil)
	if err != nil {
		t.Fatalf("InitWithOptions: %v", err)
	}
	t.Cleanup(set.Close)
	return set
}

func hotRuleFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rule.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func hotServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>" + hotMarker + "</body></html>"))
	}))
	t.Cleanup(server.Close)
	return server
}

func hasFramework(fws sdktypes.Frameworks, name string) bool {
	_, ok := fws[name]
	return ok
}

// A POC added to the running neutron engine is in engine.Get(), which is
// where the next neutron call reads its template set from, and the rebuilt
// index knows it, which is what --finger and the cyberhub search read.
func TestHotAddPocJoinsTheNextSelection(t *testing.T) {
	set := hotSet(t)
	before := len(set.Neutron.Get())
	if err := set.Neutron.AddPocsFile(hotRuleFile(t, hotPocYAML)); err != nil {
		t.Fatalf("AddPocsFile: %v", err)
	}
	after := set.Neutron.Get()
	if len(after) != before+1 {
		t.Fatalf("templates after add = %d, want %d", len(after), before+1)
	}
	var loaded *templates.Template
	for _, tpl := range after {
		if tpl != nil && tpl.Id == hotPocID {
			loaded = tpl
		}
	}
	if loaded == nil {
		t.Fatalf("%s is not in engine.Get(); the next neutron call cannot select it", hotPocID)
	}
	set.Index.BuildWithFingers(set.Fingers.Fingers(), set.Fingers.Aliases(), after)
	if set.Index.Template(hotPocID) == nil {
		t.Fatalf("the index does not know %s after the in-place rebuild", hotPocID)
	}
}

// A fingerprint added to the running fingers engine matches after Reload,
// through the HTTP matching path the tools use.
func TestHotAddFingerMatchesAfterReload(t *testing.T) {
	set := hotSet(t)
	before := set.Fingers.Count()
	if err := set.Fingers.AddFingersFile(hotRuleFile(t, hotFingerYAML)); err != nil {
		t.Fatalf("AddFingersFile: %v", err)
	}
	if err := set.Fingers.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := set.Fingers.Count(); got != before+1 {
		t.Fatalf("finger count after add and reload = %d, want %d", got, before+1)
	}
	server := hotServer(t)
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	fws, err := set.Fingers.MatchHTTP(resp)
	if err != nil || !hasFramework(fws, hotFingerName) {
		t.Fatalf("MatchHTTP after reload = %v, %v; want %s", fws, err, hotFingerName)
	}
}

// Adding a same-name fingerprint and reloading leaves one finger, the new
// one: Append does not dedupe, the reload does.
func TestHotRewriteFingerReplacesInPlace(t *testing.T) {
	set := hotSet(t)
	if err := set.Fingers.AddFingersFile(hotRuleFile(t, hotFingerYAML)); err != nil {
		t.Fatalf("AddFingersFile: %v", err)
	}
	if err := set.Fingers.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	count := set.Fingers.Count()
	server := hotServer(t)
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.Fingers.MatchHTTP(resp)
	_ = resp.Body.Close()
	if err != nil || !hasFramework(first, hotFingerName) {
		t.Fatalf("the first version does not match: %v, %v", first, err)
	}
	other := strings.ReplaceAll(hotFingerYAML, hotMarker, "hot-proof-marker-4d2e81")
	if err := set.Fingers.AddFingersFile(hotRuleFile(t, other)); err != nil {
		t.Fatalf("AddFingersFile: %v", err)
	}
	if err := set.Fingers.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := set.Fingers.Count(); got != count {
		t.Fatalf("finger count after a same-name rewrite = %d, want %d", got, count)
	}
	resp, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.Fingers.MatchHTTP(resp)
	_ = resp.Body.Close()
	if err != nil || hasFramework(second, hotFingerName) {
		t.Fatalf("the old rule still matches after the rewrite: %v, %v", second, err)
	}
}

// AddPocs appends; it does not replace. A rewritten POC therefore leaves the
// loaded version first in engine.Get(), which is why a rewrite removes the old
// ids before it adds the new text.
func TestHotRewritePocAppendsInsteadOfReplacing(t *testing.T) {
	set := hotSet(t)
	if err := set.Neutron.AddPocsFile(hotRuleFile(t, hotPocYAML)); err != nil {
		t.Fatalf("AddPocsFile: %v", err)
	}
	if err := set.Neutron.AddPocsFile(hotRuleFile(t, strings.ReplaceAll(hotPocYAML, "hot proof poc", "second version"))); err != nil {
		t.Fatalf("AddPocsFile: %v", err)
	}
	var names []string
	for _, tpl := range set.Neutron.Get() {
		if tpl != nil && tpl.Id == hotPocID {
			names = append(names, tpl.Info.Name)
		}
	}
	if len(names) != 2 || names[0] != "hot proof poc" {
		t.Fatalf("templates with id %s after a rewrite = %q; want the first version first and the second appended", hotPocID, names)
	}
}

// gogo holds the fingers engine and reads its current implementation when it
// runs, so a scan started after the reload reports the new fingerprint.
func TestHotFingerIsReportedByTheNextGogoScan(t *testing.T) {
	set := hotSet(t)
	if set.Gogo == nil {
		t.Fatal("the gogo engine is not available")
	}
	server := hotServer(t)
	if err := set.Fingers.AddFingersFile(hotRuleFile(t, hotFingerYAML)); err != nil {
		t.Fatalf("AddFingersFile: %v", err)
	}
	if err := set.Fingers.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// A gogo task is a host plus its ports; the target alone is rejected.
	results, err := GogoScanStream(ctx, set.Gogo, GogoOptions{Target: host, Ports: port, Threads: 1, Timeout: 10})
	if err != nil {
		t.Fatalf("GogoScanStream: %v", err)
	}
	found := false
	for result := range results {
		if result != nil && hasFramework(result.Frameworks, hotFingerName) {
			found = true
		}
	}
	if !found {
		t.Fatal("the gogo scan after the reload did not report hot-proof-finger")
	}
}

// RemovePocs takes a template out of the running set without compiling
// anything, which is what a rewrite and a removal ride on.
func TestHotRemovePocsTakesATemplateOutOfTheNextSelection(t *testing.T) {
	set := hotSet(t)
	if err := set.Neutron.AddPocsFile(hotRuleFile(t, hotPocYAML)); err != nil {
		t.Fatalf("AddPocsFile: %v", err)
	}
	if err := set.Neutron.RemovePocs(hotPocID); err != nil {
		t.Fatalf("RemovePocs: %v", err)
	}
	for _, tpl := range set.Neutron.Get() {
		if tpl != nil && tpl.Id == hotPocID {
			t.Fatalf("%s is still in engine.Get() after RemovePocs", hotPocID)
		}
	}
}
