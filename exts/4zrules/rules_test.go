package rules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/telemetry"
	coretool "github.com/chainreactors/cyber/core/tool"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	rulesconfig "github.com/chainreactors/cyber/exts/4zrules/config"
	scannerext "github.com/chainreactors/cyber/exts/scanner"
	"github.com/chainreactors/cyber/pkg/testutil/hosttest"
	engineresources "github.com/chainreactors/cyber/tools/resources"
	"github.com/chainreactors/cyber/tools/scan/engine"
	"github.com/chainreactors/sdk/pkg/association"
	sdktypes "github.com/chainreactors/sdk/pkg/types"
	"gopkg.in/yaml.v3"
)

// pocNamed is the smallest POC the node compiles: one of only an id and an
// info block is dropped.
func pocNamed(id, name string) string {
	return "id: " + id + "\ninfo:\n  name: " + name + "\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"
}

func fingerNamed(name, marker string) string {
	return "- name: " + name + "\n  rule:\n    - regexps:\n        body:\n          - " + marker + "\n"
}

var secondPOC = pocNamed("brick-poc-two", "brick poc two")

// load runs the brick in an extension set with whatever the test provides.
func load(t *testing.T, provided ...extension.Extension) {
	t.Helper()
	set, err := extension.New(provided...)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close(context.Background()) })
}

// engines builds the set a loaded scanner provides: the SDK engines over the
// embedded rules, without the tools around them.
func engines(t *testing.T) *engine.Set {
	t.Helper()
	resources, err := engineresources.Init(context.Background(), engineresources.Options{})
	if err != nil {
		t.Fatal(err)
	}
	set := &engine.Set{
		Fingers: resources.Fingers, Neutron: resources.Neutron, Resources: resources,
		Index: association.NewIndex(),
	}
	set.Index.BuildWithFingers(set.Fingers.Fingers(), set.Fingers.Aliases(), set.Neutron.Get())
	return set
}

// started loads the brick over live engines and returns the hook registry it
// subscribed to.
func started(t *testing.T, dir string) (*engine.Set, *Extension, *hooks.Registry) {
	t.Helper()
	set := engines(t)
	brick := New(rulesconfig.Config{Dir: dir})
	registry := hooks.New()
	load(t,
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		extension.Provided[*engine.Set](set),
		extension.Provided[*hooks.Registry](registry),
		brick,
	)
	return set, brick, registry
}

// write puts a rule file in the directory.
func write(t *testing.T, dir, rel, body string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rewrite replaces a file and moves its modification time forward, as the
// console's writer does.
func rewrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := write(t, dir, rel, body)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// check is what the ticker does, run on demand.
func check(brick *Extension) {
	brick.mu.Lock()
	defer brick.mu.Unlock()
	brick.refreshLocked(context.Background())
}

func readState(t *testing.T, dir string) State {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, NodeDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func file(t *testing.T, state State, path string) FileState {
	t.Helper()
	for _, record := range state.Files {
		if record.Path == path {
			return record
		}
	}
	t.Fatalf("state has no record for %s: %+v", path, state.Files)
	return FileState{}
}

func templatesWithID(set *engine.Set, id string) []*sdktypes.Template {
	var out []*sdktypes.Template
	for _, tpl := range set.Neutron.Get() {
		if tpl != nil && tpl.Id == id {
			out = append(out, tpl)
		}
	}
	return out
}

// firstBuiltInPOC names a POC the node started with.
func firstBuiltInPOC(t *testing.T, set *engine.Set) (id, name string) {
	t.Helper()
	var builtins []*sdktypes.Template
	if err := yaml.Unmarshal(set.Resources.GogoConfig("neutron"), &builtins); err != nil {
		t.Fatal(err)
	}
	for _, tpl := range builtins {
		if tpl != nil && tpl.Id != "" && tpl.Info.Name != "" {
			return tpl.Id, tpl.Info.Name
		}
	}
	t.Fatal("the node started without POCs")
	return "", ""
}

// firstBuiltInFinger names a fingerprint the node started with.
func firstBuiltInFinger(t *testing.T, set *engine.Set) string {
	t.Helper()
	var fingers sdktypes.Fingers
	if err := json.Unmarshal(set.Resources.GogoConfig("http"), &fingers); err != nil {
		t.Fatal(err)
	}
	for _, finger := range fingers {
		if finger != nil && finger.Name != "" && squash(finger.Name) == finger.Name {
			return finger.Name
		}
	}
	t.Fatal("the node started without fingerprints")
	return ""
}

func serve(t *testing.T, marker string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>" + marker + "</body></html>"))
	}))
	t.Cleanup(server.Close)
	return server
}

// matches reports whether a match result names the fingerprint. Results are
// keyed by display name — lowercased, and a known product may be spelled with
// a space instead of a hyphen — so names are compared without case or
// separators.
func matches(t *testing.T, set *engine.Set, server *httptest.Server, name string) bool {
	t.Helper()
	resp, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	fws, err := set.Fingers.MatchHTTP(resp)
	if err != nil {
		t.Fatal(err)
	}
	for key := range fws {
		if squash(key) == squash(name) {
			return true
		}
	}
	return false
}

func squash(name string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == ' ' {
			return -1
		}
		return r
	}, name))
}

func held(brick *Extension) int {
	brick.mu.Lock()
	defer brick.mu.Unlock()
	return len(brick.inflight)
}

// A node that was not given a directory loads without the engine set: the
// brick borrows nothing it was not given.
func TestWithoutDirectoryTheBrickIsInert(t *testing.T) {
	load(t,
		extension.Provided[*hooks.Registry](hooks.New()),
		New(rulesconfig.Config{}),
	)
}

// A node without scanner engines still loads and says so, instead of failing
// or pretending the rules were applied.
func TestWithoutEnginesTheBrickReportsIt(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "brick poc"))
	load(t,
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		extension.Provided[*engine.Set](&engine.Set{}),
		extension.Provided[*hooks.Registry](hooks.New()),
		New(rulesconfig.Config{Dir: dir}),
	)
	state := readState(t, dir)
	if state.Available || state.Reason != reasonNoEngines {
		t.Fatalf("state = available %v reason %q; want unavailable with the engine reason", state.Available, state.Reason)
	}
}

// The production path: the scanner's own Load provides the set the brick
// borrows, so the two load together in the order the assembly lists them.
func TestTheScannerProvidesTheEngineSet(t *testing.T) {
	hosttest.Load(t, context.Background(),
		hosttest.Capabilities(),
		coretool.NewCommandRegistry(),
		scannerext.NewExecution(scannerext.Config{}, t.TempDir()),
		New(rulesconfig.Config{Dir: t.TempDir()}),
	)
}

// A scan call holds the engines from tool.started to tool.completed. Other
// tools hold nothing, and a denied call emits Completed without Started, so
// it must release nothing.
func TestScanCallsAreHeldFromStartToCompletion(t *testing.T) {
	registry := hooks.New()
	brick := New(rulesconfig.Config{Dir: t.TempDir()})
	load(t,
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		extension.Provided[*engine.Set](&engine.Set{}),
		extension.Provided[*hooks.Registry](registry),
		brick,
	)
	call := func(id, name string) *aop.ToolCall { return &aop.ToolCall{Id: id, Name: name} }
	hooks.Notify(context.Background(), registry, toolhooks.Started, toolhooks.CallEvent{Call: call("c1", "neutron")})
	hooks.Notify(context.Background(), registry, toolhooks.Started, toolhooks.CallEvent{Call: call("c2", "bash")})
	if got := held(brick); got != 1 {
		t.Fatalf("calls holding the engines = %d, want 1", got)
	}
	hooks.Notify(context.Background(), registry, toolhooks.Completed, toolhooks.Completion{Call: call("c9", "neutron")})
	if got := held(brick); got != 1 {
		t.Fatalf("calls holding the engines after a denied call = %d, want 1", got)
	}
	hooks.Notify(context.Background(), registry, toolhooks.Completed, toolhooks.Completion{Call: call("c1", "neutron")})
	if got := held(brick); got != 0 {
		t.Fatalf("calls holding the engines after completion = %d, want 0", got)
	}
}

// Loading applies what is on disk: both kinds reach the engines, the index
// knows them, a fingerprint without tags gets its category, and the node
// directory holds the state and the rules the node started with.
func TestLoadAppliesTheDirectoryAndWritesTheNodeFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "fingers/custom/brick.yaml", fingerNamed("brick-finger", "marker"))
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "brick poc"))
	set := engines(t)
	builtin := Counts{Fingers: set.Fingers.Count(), Pocs: len(set.Neutron.Get())}
	brick := New(rulesconfig.Config{Dir: dir})
	load(t,
		extension.Provided[telemetry.Logger](telemetry.NopLogger()),
		extension.Provided[*engine.Set](set),
		extension.Provided[*hooks.Registry](hooks.New()),
		brick,
	)
	if got := set.Fingers.Count(); got != builtin.Fingers+1 {
		t.Fatalf("finger count = %d, want %d", got, builtin.Fingers+1)
	}
	if got := templatesWithID(set, "brick-poc"); len(got) != 1 {
		t.Fatalf("the POC is not in the neutron engine: %+v", got)
	}
	if set.Index.Template("brick-poc") == nil {
		t.Fatal("the index does not know the POC")
	}
	for _, finger := range set.Fingers.Fingers() {
		if finger.Name == "brick-finger" && (len(finger.Tags) != 1 || finger.Tags[0] != "custom") {
			t.Fatalf("fingerprint tags = %q, want the category of its directory", finger.Tags)
		}
	}
	state := readState(t, dir)
	if !state.Available || state.Builtin != builtin {
		t.Fatalf("state = available %v builtin %+v; want available with builtin %+v", state.Available, state.Builtin, builtin)
	}
	if got := file(t, state, "fingers/custom/brick.yaml"); got.State != stateApplied || got.Kind != kindFinger {
		t.Fatalf("fingerprint record = %+v", got)
	}
	if got := file(t, state, "pocs/brick.yaml"); got.State != stateApplied || got.Kind != kindPOC || got.Compiled != 1 {
		t.Fatalf("POC record = %+v", got)
	}
	for _, name := range []string{"builtin-fingers-http.json", "builtin-fingers-socket.json", "builtin-pocs.yaml"} {
		info, err := os.Stat(filepath.Join(dir, NodeDir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("node file %s: %v", name, err)
		}
	}
}

// A change is applied before the next scan call reads the engines.
func TestAChangeAppliesBeforeTheNextScanCallReadsTheEngines(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/first.yaml", pocNamed("brick-poc", "brick poc"))
	set, _, registry := started(t, dir)
	before := len(set.Neutron.Get())
	rewrite(t, dir, "pocs/second.yaml", secondPOC)
	call := &aop.ToolCall{Id: "c1", Name: "neutron"}
	hooks.Notify(context.Background(), registry, toolhooks.Started, toolhooks.CallEvent{Call: call})
	if got := len(set.Neutron.Get()); got != before+1 {
		t.Fatalf("templates when the call started = %d, want %d", got, before+1)
	}
	if len(templatesWithID(set, "brick-poc-two")) != 1 || set.Index.Template("brick-poc-two") == nil {
		t.Fatal("the new POC is neither in the engine nor in the index")
	}
	hooks.Notify(context.Background(), registry, toolhooks.Completed, toolhooks.Completion{Call: call})
}

// A change saved while a scan runs waits for it and is applied when it ends.
func TestAChangeWaitsWhileAScanRuns(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/first.yaml", pocNamed("brick-poc", "brick poc"))
	set, brick, registry := started(t, dir)
	before := len(set.Neutron.Get())
	call := &aop.ToolCall{Id: "c1", Name: "gogo"}
	hooks.Notify(context.Background(), registry, toolhooks.Started, toolhooks.CallEvent{Call: call})
	rewrite(t, dir, "pocs/second.yaml", secondPOC)
	check(brick)
	if state := readState(t, dir); !state.Pending {
		t.Fatal("a change during a scan is not reported as pending")
	}
	if got := len(set.Neutron.Get()); got != before {
		t.Fatalf("templates changed while a scan was running: %d, want %d", got, before)
	}
	hooks.Notify(context.Background(), registry, toolhooks.Completed, toolhooks.Completion{Call: call})
	if got := len(set.Neutron.Get()); got != before+1 {
		t.Fatalf("templates after the scan ended = %d, want %d", got, before+1)
	}
	if state := readState(t, dir); state.Pending || file(t, state, "pocs/second.yaml").State != stateApplied {
		t.Fatalf("state after the scan ended = pending %v, second file %+v", state.Pending, file(t, state, "pocs/second.yaml"))
	}
}

// An idle node applies within the check interval, without waiting for a call.
func TestAnIdleNodeAppliesWithinTheCheckInterval(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/first.yaml", pocNamed("brick-poc", "brick poc"))
	set, brick, _ := started(t, dir)
	before := len(set.Neutron.Get())
	rewrite(t, dir, "pocs/second.yaml", secondPOC)
	// The record does not exist until the ticker applies the file, so the
	// poll reads the state instead of asking for the record by name.
	deadline := time.Now().Add(5 * time.Second)
	for {
		state := readState(t, dir)
		applied := false
		for _, record := range state.Files {
			if record.Path == "pocs/second.yaml" && record.State == stateApplied {
				applied = true
			}
		}
		if applied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the idle node did not apply the change within the check interval; state = %+v", state.Files)
		}
		time.Sleep(50 * time.Millisecond)
	}
	brick.mu.Lock()
	got := len(set.Neutron.Get())
	brick.mu.Unlock()
	if got != before+1 {
		t.Fatalf("templates = %d, want %d", got, before+1)
	}
}

// A file the engines reject is reported with the reason and leaves the
// engines alone; once its content is right it is applied.
func TestABadFileIsReportedAndThenAppliedOnceFixed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/bad.yaml", "this is not a template\n")
	set, brick, _ := started(t, dir)
	before := len(set.Neutron.Get())
	got := file(t, readState(t, dir), "pocs/bad.yaml")
	if got.State != stateFailed || got.Reason == "" {
		t.Fatalf("record for the bad file = %+v; want failed with a reason", got)
	}
	if len(set.Neutron.Get()) != before {
		t.Fatalf("the bad file changed the engines: %d templates, want %d", len(set.Neutron.Get()), before)
	}
	rewrite(t, dir, "pocs/bad.yaml", pocNamed("brick-poc", "brick poc"))
	check(brick)
	if len(templatesWithID(set, "brick-poc")) != 1 || file(t, readState(t, dir), "pocs/bad.yaml").State != stateApplied {
		t.Fatal("the fixed file was not applied")
	}
}

// A rewritten POC replaces the loaded one: one template with the id, carrying
// the new text, and no restart.
func TestARewrittenPocIsReplacedInPlace(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "first version"))
	set, brick, _ := started(t, dir)
	before := len(set.Neutron.Get())
	rewrite(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "second version"))
	check(brick)
	got := templatesWithID(set, "brick-poc")
	if len(got) != 1 || got[0].Info.Name != "second version" {
		t.Fatalf("templates with the id after the rewrite = %+v", got)
	}
	if got := len(set.Neutron.Get()); got != before {
		t.Fatalf("template count after the rewrite = %d, want %d", got, before)
	}
	if got := file(t, readState(t, dir), "pocs/brick.yaml"); got.State != stateApplied {
		t.Fatalf("record after the rewrite = %+v", got)
	}
}

// A removed file leaves the engines, and putting it back loads it again.
func TestARemovedFileLeavesTheEngines(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "brick poc"))
	write(t, dir, "fingers/custom/brick.yaml", fingerNamed("brick-finger", "marker"))
	set, brick, _ := started(t, dir)
	pocs, fingers := len(set.Neutron.Get()), set.Fingers.Count()
	for _, rel := range []string{"pocs/brick.yaml", "fingers/custom/brick.yaml"} {
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
	}
	check(brick)
	if len(templatesWithID(set, "brick-poc")) != 0 || set.Index.Template("brick-poc") != nil {
		t.Fatal("the removed POC is still in the engine or the index")
	}
	if got := set.Fingers.Count(); got != fingers-1 {
		t.Fatalf("finger count after the removal = %d, want %d", got, fingers-1)
	}
	if state := readState(t, dir); len(state.Files) != 0 {
		t.Fatalf("the removed files are still reported: %+v", state.Files)
	}
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "brick poc"))
	check(brick)
	if got := len(set.Neutron.Get()); got != pocs {
		t.Fatalf("template count after the file came back = %d, want %d", got, pocs)
	}
}

// An instance POC with a built-in id takes the built-in's place, without a
// second template, and the built-in comes back when the file goes.
func TestAnInstancePocCoversABuiltInAndTheBuiltInComesBack(t *testing.T) {
	dir := t.TempDir()
	set, brick, _ := started(t, dir)
	id, name := firstBuiltInPOC(t, set)
	before := len(set.Neutron.Get())
	write(t, dir, "pocs/cover.yaml", pocNamed(id, "instance copy"))
	check(brick)
	got := templatesWithID(set, id)
	if len(got) != 1 || got[0].Info.Name != "instance copy" {
		t.Fatalf("templates with the id while covered = %+v", got)
	}
	if got := len(set.Neutron.Get()); got != before {
		t.Fatalf("covering added a template: %d, want %d", got, before)
	}
	if err := os.Remove(filepath.Join(dir, "pocs", "cover.yaml")); err != nil {
		t.Fatal(err)
	}
	check(brick)
	got = templatesWithID(set, id)
	if len(got) != 1 || got[0].Info.Name != name {
		t.Fatalf("templates with the id after the cover was removed = %+v; want the built-in %q back", got, name)
	}
	if got := len(set.Neutron.Get()); got != before {
		t.Fatalf("template count after the cover was removed = %d, want %d", got, before)
	}
}

// An instance fingerprint with a built-in name takes the built-in's place,
// and the built-in comes back when the file goes.
func TestAnInstanceFingerprintCoversABuiltInAndTheBuiltInComesBack(t *testing.T) {
	dir := t.TempDir()
	set, brick, _ := started(t, dir)
	name := firstBuiltInFinger(t, set)
	before := set.Fingers.Count()
	server := serve(t, "instance-marker-7c3e")
	write(t, dir, "fingers/custom/cover.yaml", fingerNamed(name, "instance-marker-7c3e"))
	check(brick)
	if !matches(t, set, server, name) {
		t.Fatal("the instance fingerprint does not match while it covers the built-in")
	}
	if got := set.Fingers.Count(); got != before {
		t.Fatalf("covering changed the finger count: %d, want %d", got, before)
	}
	if err := os.Remove(filepath.Join(dir, "fingers", "custom", "cover.yaml")); err != nil {
		t.Fatal(err)
	}
	check(brick)
	if got := set.Fingers.Count(); got != before {
		t.Fatalf("finger count after the cover was removed = %d, want %d", got, before)
	}
	covered := false
	for _, finger := range set.Fingers.Fingers() {
		if finger.Name == name {
			covered = true
		}
	}
	if !covered {
		t.Fatalf("the built-in fingerprint %q did not come back", name)
	}
	if matches(t, set, server, name) {
		t.Fatal("the instance fingerprint still matches after its file was removed")
	}
}

// A rewrite the engines refuse is reported with the reason, and the version
// that was running goes on running — for both kinds.
func TestABrokenRewriteKeepsThePreviousVersionRunning(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pocs/brick.yaml", pocNamed("brick-poc", "first version"))
	write(t, dir, "fingers/custom/brick.yaml", fingerNamed("brick-finger", "first-marker"))
	set, brick, _ := started(t, dir)
	server := serve(t, "first-marker")
	if !matches(t, set, server, "brick-finger") {
		t.Fatal("the first fingerprint version does not match")
	}
	rewrite(t, dir, "pocs/brick.yaml", "this is not a template\n")
	rewrite(t, dir, "fingers/custom/brick.yaml", "name: not-a-list\n")
	check(brick)
	got := templatesWithID(set, "brick-poc")
	if len(got) != 1 || got[0].Info.Name != "first version" {
		t.Fatalf("the refused POC rewrite changed the engines: %+v", got)
	}
	if !matches(t, set, server, "brick-finger") {
		t.Fatal("the refused fingerprint rewrite changed the engines")
	}
	for _, path := range []string{"pocs/brick.yaml", "fingers/custom/brick.yaml"} {
		if got := file(t, readState(t, dir), path); got.State != stateFailed || !strings.Contains(got.Reason, keepsPrevious) {
			t.Fatalf("record for the refused rewrite of %s = %+v", path, got)
		}
	}
}

// An empty library is reported at load: the console must not read a node that
// is up as not reporting because nothing was ever written for an empty
// directory.
func TestAnEmptyLibraryIsReportedAtLoad(t *testing.T) {
	dir := t.TempDir()
	started(t, dir)
	state := readState(t, dir)
	if !state.Available || len(state.Files) != 0 || state.Builtin.Fingers == 0 {
		t.Fatalf("state for an empty library = %+v", state)
	}
}

// pocForFinger is a POC bound to a fingerprint by its finger field.
func pocForFinger(id, finger string) string {
	return "id: " + id + "\ninfo:\n  name: " + id + "\n  severity: info\nfinger:\n  - " + finger + "\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers:\n      - type: status\n        status:\n          - 200\n"
}

// A fingerprint and a POC added together are picked by the scan pipeline's own
// selection: the POC's finger field links it to the fingerprint in the index,
// and the pipeline runs it for a target that showed the fingerprint. A POC
// that names no fingerprint is left to a direct neutron call, which is also
// why none of the built-in POCs runs in the pipeline without --broad-poc.
func TestAnAddedFingerprintAndPOCAreSelectedByTheScanPipeline(t *testing.T) {
	dir := t.TempDir()
	set, brick, _ := started(t, dir)
	server := serve(t, "instance-marker-7c3e")
	write(t, dir, "fingers/custom/brick.yaml", fingerNamed("brick-finger", "instance-marker-7c3e"))
	write(t, dir, "pocs/brick.yaml", pocForFinger("brick-poc", "brick-finger"))
	check(brick)
	if !matches(t, set, server, "brick-finger") {
		t.Fatal("the added fingerprint does not match")
	}

	// What the pipeline does once gogo reported the fingerprint on a target.
	opts := engine.NeutronOptions{Target: server.URL, Fingers: []string{"brick-finger"}}
	selected, filtered := engine.SelectNeutronTemplates(set.Neutron, set.Index, opts)
	if !filtered || len(selected) != 1 || selected[0].Id != "brick-poc" {
		t.Fatalf("the pipeline selected %d templates (filtered %v); want only brick-poc", len(selected), filtered)
	}
	results, err := engine.NeutronExecuteStream(context.Background(), set.Neutron, set.Index, opts)
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for result := range results {
		if result != nil && result.Template() != nil && result.Template().Id == "brick-poc" && result.Matched() {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("the added POC matched %d times; want once", hits)
	}

	// A POC that names no fingerprint stays out of the pipeline's selection.
	write(t, dir, "pocs/unbound.yaml", pocNamed("unbound-poc", "unbound poc"))
	check(brick)
	if len(templatesWithID(set, "unbound-poc")) != 1 {
		t.Fatal("the unbound POC is not in the engine")
	}
	selected, _ = engine.SelectNeutronTemplates(set.Neutron, set.Index, opts)
	if len(selected) != 1 {
		t.Fatalf("the pipeline selected %d templates; the unbound POC must stay out", len(selected))
	}
}
