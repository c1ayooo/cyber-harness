package session

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/cyber/agent"
)

// Turn seed (fork patch 26): a control plane on a machine that does not share
// a filesystem with the node sends the case's input files with the turn. They
// are materialised into the turn's workspace before the model runs, so the
// prompts' paths and the model's file tools see the same tree they always did.
const (
	// SeedFileLimit mirrors artifactsync's per-file cap.
	SeedFileLimit = 8 << 20
	// SeedFilesLimit and SeedTotalLimit mirror the per-batch caps.
	SeedFilesLimit = 16
	SeedTotalLimit = 64 << 20
)

// applyCaseSeed writes the seed files under the agent's workspace. Every
// failure is fatal to the turn: a half-applied seed would let the model read a
// mixture of this case's inputs and another turn's leftovers.
func applyCaseSeed(a *agent.Agent, files []CaseSeedFile) error {
	if len(files) == 0 {
		return nil
	}
	if a == nil {
		return fmt.Errorf("seed without a session")
	}
	workDir := strings.TrimSpace(a.WorkDir())
	if workDir == "" {
		return fmt.Errorf("seed needs a session workspace; this session has none")
	}
	if len(files) > SeedFilesLimit {
		return fmt.Errorf("seed carries %d files, limit is %d", len(files), SeedFilesLimit)
	}
	total := int64(0)
	for _, file := range files {
		if len(file.Data) > SeedFileLimit {
			return fmt.Errorf("seed file %q is %d bytes, limit is %d", file.Path, len(file.Data), SeedFileLimit)
		}
		total += int64(len(file.Data))
	}
	if total > SeedTotalLimit {
		return fmt.Errorf("seed totals %d bytes, limit is %d", total, SeedTotalLimit)
	}
	for _, file := range files {
		dest, err := seedPath(workDir, file.Path)
		if err != nil {
			return err
		}
		if err := writeSeedFile(dest, file); err != nil {
			return err
		}
	}
	return nil
}

// seedPath resolves one seed path under the workspace and refuses anything
// that could escape it: absolute paths, "..", and existing symlinked ancestors
// (a seed must not be able to write through a link the model or an earlier
// process planted).
func seedPath(workDir, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", fmt.Errorf("seed file with an empty path")
	}
	rel = filepath.FromSlash(rel)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("seed path %q is absolute", rel)
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("seed path %q leaves the workspace", rel)
	}
	root, err := filepath.Abs(workDir)
	if err != nil {
		return "", fmt.Errorf("seed workspace: %w", err)
	}
	dest := filepath.Join(root, clean)
	if inside, err := isWithin(root, dest); err != nil || !inside {
		if err == nil {
			err = fmt.Errorf("seed path %q leaves the workspace", rel)
		}
		return "", err
	}
	// No existing ancestor may be a symlink.
	for p := filepath.Dir(dest); ; p = filepath.Dir(p) {
		if info, lerr := os.Lstat(p); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("seed path %q crosses a symlink at %s", rel, p)
		}
		if p == root || filepath.Dir(p) == p {
			break
		}
	}
	return dest, nil
}

// isWithin reports whether child is inside parent (both absolute and clean).
func isWithin(parent, child string) (bool, error) {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false, err
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// writeSeedFile writes one seed file atomically, creating parents as needed.
func writeSeedFile(dest string, file CaseSeedFile) error {
	mode := os.FileMode(file.Mode) & os.ModePerm
	if mode == 0 {
		mode = 0o600
	}
	mode &^= os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("seed dir %s: %w", filepath.Dir(dest), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".seed-*.tmp")
	if err != nil {
		return fmt.Errorf("seed file %s: %w", file.Path, err)
	}
	name := tmp.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err := tmp.Write(file.Data); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("seed file %s: %w", file.Path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("seed file %s: %w", file.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("seed file %s: %w", file.Path, err)
	}
	if err := os.Rename(name, dest); err != nil {
		return fmt.Errorf("seed file %s: %w", file.Path, err)
	}
	return nil
}
