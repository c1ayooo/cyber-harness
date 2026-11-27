package evidence

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	filepb "github.com/chainreactors/cyber/aop/file"
)

// The snapshot machinery below is owned by 4zevidence (docs/19 E5): it began
// as upstream observe's TakeSnapshot/DiffSnapshots/FileOptions, which this
// package first reused via import. The import direction was wrong — evidence
// only needs the pure functions, not observe's extension — so the functions
// moved here unchanged. observe keeps its own upstream copy; neither package
// imports the other.

const DefaultMaxEntries = 20000

// FileOptions selects which files a snapshot covers.
type FileOptions struct {
	Enabled    bool
	Ignore     []string
	MaxEntries int
}

type snapshotEntry struct {
	modTime int64
	size    int64
}

// Snapshot is the best-effort state of a directory tree: path to mtime and
// size. Unreadable entries are omitted, not errors.
type Snapshot map[string]snapshotEntry

// Change is one path a completion diff turned up.
type Change struct {
	Path string
	Op   filepb.AccessOp
	Size int64
}

var errSnapshotTooLarge = fmt.Errorf("snapshot limit reached")

// TakeSnapshot walks root and records every regular, non-ignored file.
func TakeSnapshot(root string, options FileOptions) (Snapshot, error) {
	if root == "" {
		return nil, fmt.Errorf("file observation: work directory is required")
	}
	maxEntries := options.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	ignore := options.Ignore
	if len(ignore) == 0 {
		ignore = defaultSnapshotIgnore
	}
	result := make(Snapshot)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if path != root && ignored(entry.Name(), ignore) {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || ignored(entry.Name(), ignore) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			// Unreadable entries are intentionally omitted from a best-effort
			// snapshot; callers still receive the remaining tree.
			return nil //nolint:nilerr
		}
		if len(result) >= maxEntries {
			return errSnapshotTooLarge
		}
		result[path] = snapshotEntry{modTime: info.ModTime().UnixNano(), size: info.Size()}
		return nil
	})
	if err == errSnapshotTooLarge {
		return nil, fmt.Errorf("file observation: %s holds more than %d files", root, maxEntries)
	}
	return result, err
}

// defaultSnapshotIgnore is what an empty Ignore list means. It mirrors
// upstream observe's defaults so a snapshot taken here skips the same trees.
var defaultSnapshotIgnore = []string{".git", "node_modules", ".cairn", "__pycache__", ".venv"}

func ignored(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern != "" && strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// DiffSnapshots returns create/write/delete changes between two snapshots,
// sorted by path.
func DiffSnapshots(before, after Snapshot) []Change {
	var changes []Change
	for path, now := range after {
		previous, existed := before[path]
		switch {
		case !existed:
			changes = append(changes, Change{Path: path, Op: filepb.AccessOp_ACCESS_OP_CREATE, Size: now.size})
		case previous != now:
			changes = append(changes, Change{Path: path, Op: filepb.AccessOp_ACCESS_OP_WRITE, Size: now.size})
		}
	}
	for path := range before {
		if _, exists := after[path]; !exists {
			changes = append(changes, Change{Path: path, Op: filepb.AccessOp_ACCESS_OP_DELETE})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes
}
