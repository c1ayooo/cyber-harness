package tool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunCommandRegisteredPrecedence(t *testing.T) {
	registry, _ := loadTestRegistry(t, commandBatch(Command{
		Name: "echo", Run: func(_ context.Context, execution *Execution) (any, error) {
			fmt.Fprint(execution.Stdout, "registered:", strings.Join(execution.Args, ","))
			return "details", nil
		},
	}))
	var output bytes.Buffer
	details, err := RunCommand(t.Context(), registry, []string{"echo", "one", "two"}, &Execution{Stdout: &output})
	if err != nil || details != "details" || output.String() != "registered:one,two" {
		t.Fatalf("details=%v output=%q err=%v", details, output.String(), err)
	}
}

func TestRunCommandExternalEnvironmentStreamsAndStatus(t *testing.T) {
	var output bytes.Buffer
	parent := &Execution{
		Dir: t.TempDir(), Env: []string{"RUN_COMMAND_CHILD=1", "RUN_COMMAND_VALUE=override"},
		Stdin: strings.NewReader("input"), Stdout: &output, Stderr: &output,
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = RunCommand(t.Context(), nil, []string{program, "-test.run=^TestRunCommandChild$"}, parent)
	if err != nil || !strings.Contains(output.String(), "override:input:") || !strings.Contains(output.String(), parent.Dir) {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
	parent.Env = append(parent.Env, "RUN_COMMAND_FAIL=7")
	_, err = RunCommand(t.Context(), nil, []string{program, "-test.run=^TestRunCommandChild$"}, parent)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("exit=%v, want status 7", err)
	}
}

func TestRunCommandCancellation(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = RunCommand(ctx, nil, []string{program, "-test.run=^TestRunCommandChild$"}, &Execution{
		Env:    []string{"RUN_COMMAND_CHILD=1", "RUN_COMMAND_SLEEP=1"},
		Stdout: io.Discard, Stderr: io.Discard,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestRunCommandChild(t *testing.T) {
	if os.Getenv("RUN_COMMAND_CHILD") != "1" {
		return
	}
	if os.Getenv("RUN_COMMAND_SLEEP") == "1" {
		time.Sleep(10 * time.Second)
		return
	}
	input, _ := io.ReadAll(os.Stdin)
	dir, _ := os.Getwd()
	fmt.Printf("%s:%s:%s", os.Getenv("RUN_COMMAND_VALUE"), input, dir)
	if os.Getenv("RUN_COMMAND_FAIL") == "7" {
		os.Exit(7)
	}
}

func TestPosixDrivePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/c/Windows/System32/curl.exe", `C:\Windows\System32\curl.exe`, true},
		{"/D/tools/x.exe", `D:\tools\x.exe`, true},
		{"/tmp/f.json", "", false},         // not a drive path
		{"/c", "", false},                  // too short to be a path
		{"/cc/x", "", false},               // second char after the slash must be one letter
		{"C:/Windows/curl.exe", "", false}, // already native
		{"curl", "", false},
	}
	for _, tc := range cases {
		got, ok := posixDrivePath(tc.in)
		if runtime.GOOS != "windows" {
			if ok {
				t.Fatalf("posixDrivePath(%q) converted on %s", tc.in, runtime.GOOS)
			}
			continue
		}
		if ok != tc.ok || got != tc.want {
			t.Errorf("posixDrivePath(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// An MSYS-style absolute path must reach the real program on Windows: the
// shell is POSIX but the binaries are native (2026-11-20: /c/WINDOWS/system32/
// curl.exe failed while C:\WINDOWS\system32\curl.exe worked).
func TestRunCommandAcceptsPosixDrivePath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-letter mapping is a Windows path rule")
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("no SystemRoot")
	}
	native := filepath.Join(root, "System32", "cmd.exe")
	if _, err := os.Stat(native); err != nil {
		t.Skipf("cmd.exe not found: %v", err)
	}
	// C:\Windows\System32\cmd.exe -> /c/Windows/System32/cmd.exe
	drive := strings.ToLower(string(root[0]))
	posix := "/" + drive + strings.ReplaceAll(root[2:], `\`, "/") + "/System32/cmd.exe"

	var output bytes.Buffer
	_, err := RunCommand(t.Context(), nil, []string{posix, "/c", "echo", "mapped"}, &Execution{
		Dir: t.TempDir(), Stdout: &output, Stderr: &output,
	})
	if err != nil {
		t.Fatalf("run %s: %v", posix, err)
	}
	if !strings.Contains(strings.ToLower(output.String()), "mapped") {
		t.Fatalf("output = %q", output.String())
	}
}
