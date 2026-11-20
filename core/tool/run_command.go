package tool

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

// RunCommand invokes one expanded argv. Registered commands take precedence
// over programs in PATH; a rejected registered command never falls through.
func RunCommand(ctx context.Context, registry CommandExecutor, argv []string, parent *Execution) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("empty command")
	}
	if parent == nil {
		return nil, fmt.Errorf("command %s requires an execution", argv[0])
	}
	name := argv[0]
	if registry != nil && !strings.ContainsAny(name, `/\`) && registry.Has(name) {
		return registry.Run(ctx, argv, parent)
	}
	env := mergeCommandEnvironment(os.Environ(), parent.Env)
	resolved := name
	if mapped, ok := posixDrivePath(name); ok {
		resolved = mapped
	}
	path, err := interp.LookPathDir(parent.Dir, expand.ListEnviron(env...), resolved)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Dir = parent.Dir
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = parent.Stdin, parent.Stdout, parent.Stderr
	if err := runExternalCommand(ctx, cmd); err != nil {
		return nil, err
	}
	return nil, nil
}

// posixDrivePath converts an MSYS-style absolute path (/c/Windows/System32/
// curl.exe) into its native form (C:\Windows\System32\curl.exe).
//
// The embedded shell keeps POSIX syntax while external programs are native, so
// a model that types an absolute POSIX path for an executable got
// "executable file not found" even though the file was right there (observed on
// 2026-11-20: CURL=/c/WINDOWS/system32/curl.exe). Only the program name is
// translated — ordinary arguments keep whatever spelling the caller used, so
// this cannot rewrite a URL or a data value.
func posixDrivePath(p string) (string, bool) {
	if runtime.GOOS != "windows" || len(p) < 3 || p[0] != '/' || p[2] != '/' {
		return "", false
	}
	drive := p[1]
	if !(drive >= 'a' && drive <= 'z') && !(drive >= 'A' && drive <= 'Z') {
		return "", false
	}
	rest := strings.ReplaceAll(p[3:], "/", `\`)
	return strings.ToUpper(string(drive)) + `:\` + rest, true
}

func mergeCommandEnvironment(base, overrides []string) []string {
	if len(overrides) == 0 {
		return base
	}
	values := make(map[string]string, len(overrides))
	for _, item := range overrides {
		if key, value, ok := strings.Cut(item, "="); ok {
			values[environmentKey(key)] = value
		}
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if _, replaced := values[environmentKey(key)]; ok && replaced {
			continue
		}
		out = append(out, item)
	}
	return append(out, overrides...)
}

func environmentKey(key string) string {
	if runtime.GOOS == "windows" {
		return strings.ToUpper(key)
	}
	return key
}
