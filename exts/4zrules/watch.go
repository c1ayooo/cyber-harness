package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
	"gopkg.in/yaml.v3"
)

// NodeDir is where the brick writes back, inside the rules directory. The
// console reads it and never writes it.
const NodeDir = ".node"

// brickVersion is the state file's shape.
const brickVersion = 2

// What the node did with one instance file.
const (
	stateApplied = "applied"
	stateFailed  = "failed"
)

// The two kinds of rule file, named by their top-level directory.
const (
	kindFinger = "finger"
	kindPOC    = "poc"
)

const (
	reasonNoEngines = "the node has no scanner engines"
	// keepsPrevious ends the reason of a rewrite the engines refused: what
	// was running goes on running.
	keepsPrevious = "; the node keeps running the previous version"
)

// FileState is one file's record as the console reads it.
type FileState struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Parsed   int    `json:"parsed,omitempty"`
	Compiled int    `json:"compiled,omitempty"`
}

// fileRecord is a file state plus what the brick needs to change it.
type fileRecord struct {
	FileState
	// Digest is the file the record describes; a rewrite is a new digest.
	Digest string
	// Loaded is true while a version of the file is in the engines.
	Loaded bool
	// source is the text of the loaded version, so a refused rewrite can put
	// it back from a fresh parse.
	source string
	// ids and names are what the loaded version holds in the engines, and
	// what taking it out removes.
	ids   []string
	names []string
}

// Counts is how many rules of each kind a node runs.
type Counts struct {
	Fingers int `json:"fingers"`
	Pocs    int `json:"pocs"`
}

// State is what the brick writes back for the console (4zrcin docs/rules.md).
// It reports what the node did: a file counts as applied only once the
// engines accepted it.
type State struct {
	Brick     int         `json:"brick"`
	UpdatedAt time.Time   `json:"updated_at"`
	Available bool        `json:"available"`
	Reason    string      `json:"reason,omitempty"`
	Pending   bool        `json:"pending"`
	Error     string      `json:"error,omitempty"`
	Builtin   Counts      `json:"builtin"`
	Files     []FileState `json:"files"`
}

// parsed is one instance file read into sdk types.
type parsed struct {
	pocs    []*sdktypes.Template
	fingers sdktypes.Fingers
}

// ready reports whether the set carries the engines the brick mutates.
func (e *Extension) ready() bool {
	return e.set != nil && e.set.Resources != nil && e.set.Fingers != nil && e.set.Neutron != nil
}

// refreshLocked applies the directory if it changed and the engines are idle.
func (e *Extension) refreshLocked(ctx context.Context) {
	signature, files, err := signature(e.config.Dir)
	if err != nil {
		if e.errText != err.Error() {
			e.errText = err.Error()
			e.logger.Warnf("rules: read %s: %v", e.config.Dir, err)
			e.writeStateLocked()
		}
		return
	}
	if e.known && signature == e.signature && e.errText == "" {
		return
	}
	e.errText = ""
	if len(e.inflight) > 0 {
		if !e.pending {
			e.pending = true
			e.writeStateLocked()
		}
		return
	}
	e.applyLocked(ctx, signature, files)
}

// applyLocked makes the engines hold what the directory says. Each changed
// file is read before anything is taken out, so a file that does not parse
// costs nothing; what was running goes back in. One file failing does not
// stop the others, and a failed file is not tried again until it changes.
func (e *Extension) applyLocked(ctx context.Context, signature string, files map[string]string) {
	e.signature, e.known, e.pending = signature, true, false
	if !e.ready() {
		e.writeStateLocked()
		return
	}
	reload := false
	var applied []string
	for _, path := range sortedKeys(files) {
		kind := kindOf(path)
		if kind == "" {
			continue
		}
		record, seen := e.applied[path]
		if seen && record.Digest == files[path] {
			continue
		}
		previous := record
		if !seen {
			record = fileRecord{FileState: FileState{Path: path, Kind: kind}}
		}
		record.Digest = files[path]
		record.State, record.Reason, record.Parsed, record.Compiled = "", "", 0, 0

		content, err := os.ReadFile(filepath.Join(e.config.Dir, filepath.FromSlash(path)))
		var read parsed
		if err == nil {
			read, err = parse(path, content)
		}
		e.takeOut(previous, &reload)
		if err == nil {
			err = e.putIn(path, content, &read, &record, &reload)
		}
		if err != nil {
			e.refuse(previous, &record, err, &reload)
		} else {
			applied = append(applied, path)
		}
		e.applied[path] = record
	}
	for path, record := range e.applied {
		if _, exists := files[path]; exists {
			continue
		}
		e.takeOut(record, &reload)
		delete(e.applied, path)
	}
	if reload {
		if err := e.set.Fingers.Reload(ctx); err != nil {
			e.logger.Warnf("rules: reload fingers: %v", err)
			e.failFingers(applied, err)
		}
	}
	if e.set.Index != nil {
		e.set.Index.BuildWithFingers(e.set.Fingers.Fingers(), e.set.Fingers.Aliases(), e.set.Neutron.Get())
	}
	e.writeStateLocked()
}

// parse reads a rule file the way the sdk's file provider does: a POC file is
// a template or a list of them, a fingerprint file is a list.
func parse(path string, data []byte) (parsed, error) {
	switch kindOf(path) {
	case kindPOC:
		var list []*sdktypes.Template
		if err := yaml.Unmarshal(data, &list); err == nil && len(list) > 0 {
			return parsed{pocs: list}, nil
		}
		tpl := &sdktypes.Template{}
		if err := yaml.Unmarshal(data, tpl); err != nil {
			return parsed{}, fmt.Errorf("parse %s: %w", path, err)
		}
		return parsed{pocs: []*sdktypes.Template{tpl}}, nil
	case kindFinger:
		var fingers sdktypes.Fingers
		if err := yaml.Unmarshal(data, &fingers); err != nil {
			return parsed{}, fmt.Errorf("parse %s: %w", path, err)
		}
		return parsed{fingers: fingers}, nil
	}
	return parsed{}, fmt.Errorf("%s is not a rule file", path)
}

// putIn adds one file's rules to the engines. A built-in of the same id or
// name makes way for the instance one and comes back when the file goes.
func (e *Extension) putIn(path string, content []byte, read *parsed, record *fileRecord, reload *bool) error {
	record.source = string(content)
	record.Parsed = len(read.pocs) + len(read.fingers)
	switch {
	case len(read.pocs) > 0:
		record.ids = idsOf(read.pocs)
		if len(record.ids) == 0 {
			return errors.New("no template has an id")
		}
		if err := e.set.Neutron.RemovePocs(record.ids...); err != nil {
			return err
		}
		before := len(e.set.Neutron.Get())
		// compileTemplates drops what it cannot compile without a word; the
		// difference is the only place the operator can see a template vanish.
		if err := e.set.Neutron.AddPocs(read.pocs); err != nil {
			// Nothing was added: put back any built-in that made way.
			if restoreErr := e.restorePOCs(record.ids); restoreErr != nil {
				e.logger.Warnf("rules: restore built-in POCs: %v", restoreErr)
			}
			record.ids = nil
			return err
		}
		record.Compiled = len(e.set.Neutron.Get()) - before
	case len(read.fingers) > 0:
		addCategoryTag(read.fingers, path)
		record.names = namesOf(read.fingers)
		*reload = true
		if err := e.set.Fingers.RemoveFingers(record.names...); err != nil {
			return err
		}
		if err := e.set.Fingers.AddFingers(read.fingers); err != nil {
			// Append may have added some before failing; the reload that
			// follows restores the running set to what the configuration
			// holds. The built-ins that made way go back first.
			if restoreErr := e.restoreFingers(record.names); restoreErr != nil {
				e.logger.Warnf("rules: restore built-in fingerprints: %v", restoreErr)
			}
			record.names = nil
			return err
		}
	default:
		return errors.New("the file holds no rule")
	}
	record.Loaded = true
	record.State = stateApplied
	return nil
}

// takeOut removes what a loaded version holds and puts back the built-ins it
// was covering.
func (e *Extension) takeOut(record fileRecord, reload *bool) {
	if !record.Loaded {
		return
	}
	if record.Kind == kindPOC {
		if err := e.set.Neutron.RemovePocs(record.ids...); err != nil {
			e.logger.Warnf("rules: remove POCs: %v", err)
		}
		if err := e.restorePOCs(record.ids); err != nil {
			e.logger.Warnf("rules: restore built-in POCs: %v", err)
		}
		return
	}
	*reload = true
	if err := e.set.Fingers.RemoveFingers(record.names...); err != nil {
		e.logger.Warnf("rules: remove fingerprints: %v", err)
	}
	if err := e.restoreFingers(record.names); err != nil {
		e.logger.Warnf("rules: restore built-in fingerprints: %v", err)
	}
}

// refuse records a file the engines would not take. When a version of it was
// running, that version goes back in, from a fresh parse of its own text, so
// a broken edit does not take a working rule out of the node.
func (e *Extension) refuse(previous fileRecord, record *fileRecord, cause error, reload *bool) {
	record.State, record.Reason = stateFailed, cause.Error()
	record.Loaded, record.ids, record.names, record.source = false, nil, nil, ""
	if !previous.Loaded {
		return
	}
	back := fileRecord{FileState: FileState{Path: previous.Path, Kind: previous.Kind}, Digest: previous.Digest}
	read, err := parse(previous.Path, []byte(previous.source))
	if err != nil {
		e.logger.Warnf("rules: the previous version of %s no longer parses: %v", previous.Path, err)
		return
	}
	if err := e.putIn(previous.Path, []byte(previous.source), &read, &back, reload); err != nil {
		e.logger.Warnf("rules: the previous version of %s could not be put back: %v", previous.Path, err)
		return
	}
	record.Loaded, record.ids, record.names, record.source = true, back.ids, back.names, previous.source
	record.Parsed, record.Compiled = back.Parsed, back.Compiled
	record.Reason = cause.Error() + keepsPrevious
}

// failFingers marks the fingerprints of one pass failed when the rebuild
// after them failed: the engines then still run what Append added, so the
// operator is told rather than shown a clean applied.
func (e *Extension) failFingers(applied []string, err error) {
	for _, path := range applied {
		record := e.applied[path]
		if record.Kind != kindFinger {
			continue
		}
		record.State, record.Reason = stateFailed, "reload: "+err.Error()
		e.applied[path] = record
	}
}

// restorePOCs puts back the POCs the node started with, for the ids an
// instance file had covered. They are parsed again from the node's own copy
// of them: AddPocs compiles what it is given, and a compiled template must
// not be compiled twice.
func (e *Extension) restorePOCs(ids []string) error {
	wanted := lowerSet(ids)
	if len(wanted) == 0 {
		return nil
	}
	data := e.set.Resources.GogoConfig("neutron")
	if len(data) == 0 {
		return nil
	}
	var builtins []*sdktypes.Template
	if err := yaml.Unmarshal(data, &builtins); err != nil {
		return fmt.Errorf("parse built-in POCs: %w", err)
	}
	var restored []*sdktypes.Template
	for _, tpl := range builtins {
		if tpl == nil {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(tpl.Id))
		if wanted[id] {
			restored = append(restored, tpl)
			delete(wanted, id)
		}
	}
	if len(restored) == 0 {
		return nil
	}
	return e.set.Neutron.AddPocs(restored)
}

// restoreFingers puts back the fingerprints the node started with, for the
// names an instance file had covered, read again from the node's own copy.
func (e *Extension) restoreFingers(names []string) error {
	wanted := nameSet(names)
	if len(wanted) == 0 {
		return nil
	}
	var restored sdktypes.Fingers
	for _, key := range []string{"http", "socket"} {
		data := e.set.Resources.GogoConfig(key)
		if len(data) == 0 {
			continue
		}
		var fingers sdktypes.Fingers
		if err := json.Unmarshal(data, &fingers); err != nil {
			return fmt.Errorf("parse built-in %s fingerprints: %w", key, err)
		}
		for _, finger := range fingers {
			if finger != nil && wanted[finger.Name] {
				restored = append(restored, finger)
				delete(wanted, finger.Name)
			}
		}
	}
	if len(restored) == 0 {
		return nil
	}
	return e.set.Fingers.AddFingers(restored)
}

// addCategoryTag gives a fingerprint without tags the category of its
// directory, the same rule the generator applies to the rules repository.
func addCategoryTag(fingers sdktypes.Fingers, path string) {
	category := ""
	if rest, ok := strings.CutPrefix(path, "fingers/"); ok {
		category, _, _ = strings.Cut(rest, "/")
	}
	for _, finger := range fingers {
		if finger != nil && len(finger.Tags) == 0 && category != "" {
			finger.Tags = []string{category}
		}
	}
}

// idsOf lists the ids of a file's templates the way the engine keys them.
func idsOf(pocs []*sdktypes.Template) []string {
	ids := make([]string, 0, len(pocs))
	for _, tpl := range pocs {
		if tpl == nil {
			continue
		}
		if id := strings.ToLower(strings.TrimSpace(tpl.Id)); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// namesOf lists the names of a file's fingerprints.
func namesOf(fingers sdktypes.Fingers) []string {
	names := make([]string, 0, len(fingers))
	for _, finger := range fingers {
		if finger != nil && finger.Name != "" {
			names = append(names, finger.Name)
		}
	}
	return names
}

func lowerSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			set[value] = true
		}
	}
	return set
}

func nameSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = true
		}
	}
	return set
}

// writeBuiltins copies the rules the node started with into the node
// directory, so the console lists what this node runs rather than what some
// checkout contains.
func (e *Extension) writeBuiltins() {
	for _, dump := range []struct {
		name string
		data []byte
	}{
		{"builtin-fingers-http.json", e.set.Resources.GogoConfig("http")},
		{"builtin-fingers-socket.json", e.set.Resources.GogoConfig("socket")},
		{"builtin-pocs.yaml", e.set.Resources.GogoConfig("neutron")},
	} {
		path := filepath.Join(e.config.Dir, NodeDir, dump.name)
		if err := writeFileAtomic(path, dump.data); err != nil {
			e.logger.Warnf("rules: write %s: %v", path, err)
		}
	}
}

// writeStateLocked reports what the node runs. The file is replaced whole, so
// the console never reads a half-written state.
func (e *Extension) writeStateLocked() {
	e.updated = time.Now().UTC()
	state := State{
		Brick:     brickVersion,
		UpdatedAt: e.updated,
		Available: e.ready(),
		Pending:   e.pending,
		Error:     e.errText,
		Builtin:   e.builtin,
		Files:     make([]FileState, 0, len(e.applied)),
	}
	if !state.Available {
		state.Reason = reasonNoEngines
	}
	for _, path := range sortedKeys(e.applied) {
		state.Files = append(state.Files, e.applied[path].FileState)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		e.logger.Warnf("rules: encode state: %v", err)
		return
	}
	path := filepath.Join(e.config.Dir, NodeDir, "state.json")
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		e.logger.Warnf("rules: write %s: %v", path, err)
	}
}

// signature lists the rule files under fingers/ and pocs/ with their size and
// modification time. The writer moves the modification time forward on every
// rewrite, so a same-size overwrite cannot hide.
func signature(dir string) (string, map[string]string, error) {
	digests := make(map[string]string)
	for _, sub := range []string{"fingers", "pocs"} {
		err := filepath.WalkDir(filepath.Join(dir, sub), func(path string, entry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if entry.IsDir() || !isYAML(entry.Name()) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			digests[rel] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
			return nil
		})
		if err != nil {
			return "", nil, err
		}
	}
	var b strings.Builder
	for _, rel := range sortedKeys(digests) {
		fmt.Fprintf(&b, "%s\x00%s\n", rel, digests[rel])
	}
	return b.String(), digests, nil
}

// kindOf classifies a rule file by its top-level directory. Anything else
// under the directory is not a rule.
func kindOf(path string) string {
	switch {
	case strings.HasPrefix(path, "fingers/"):
		return kindFinger
	case strings.HasPrefix(path, "pocs/"):
		return kindPOC
	}
	return ""
}

func isYAML(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		return true
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// writeFileAtomic replaces a file whole: the reader sees the old content or
// the new one, never a partial write.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
