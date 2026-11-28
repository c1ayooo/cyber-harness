package curl

import (
	"os"
	"path/filepath"
)

// createFile resolves an output path the same way every other file argument is
// resolved and creates the missing parent directories on the way.
//
// A POSIX-looking absolute path like /tmp/body.json is not absolute on Windows,
// so resolvePath anchors it under the working directory (the case). Without
// this, the write failed whenever that scratch directory had not been created
// yet — "Failed to create /tmp/f.json: The system cannot find the path
// specified" — and the model lost a whole round to a path we handed it.
func createFile(workDir, path string) (*os.File, error) {
	resolved := resolvePath(workDir, path)
	if dir := filepath.Dir(resolved); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.Create(resolved)
}
