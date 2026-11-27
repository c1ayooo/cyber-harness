package session

// The turn's workspace lands on the agent (the block parses the payload; the
// runtime applies it), so the application rules live beside the agent.

import (
	"testing"

	"github.com/chainreactors/cyber/agent"
)

func TestTurnWorkDirFillsAnEmptyWorkspaceOnly(t *testing.T) {
	ag := agent.NewAgent(agent.Config{})
	if err := applyTurnWorkDir(ag, `C:\data\project\cases\in_1`); err != nil {
		t.Fatal(err)
	}
	if got := ag.WorkDir(); got != `C:\data\project\cases\in_1` {
		t.Fatalf("workspace = %q, want the one the turn supplied", got)
	}

	// The same directory written differently is not a conflict.
	if err := applyTurnWorkDir(ag, `C:/data/project/cases/in_1/`); err != nil {
		t.Fatalf("same workspace reported as a conflict: %v", err)
	}

	// A different directory would move the session's relative paths mid-run.
	if err := applyTurnWorkDir(ag, `C:\data\project\cases\in_2`); err == nil {
		t.Fatal("a turn silently moved the session to another workspace")
	}
	if got := ag.WorkDir(); got != `C:\data\project\cases\in_1` {
		t.Fatalf("workspace changed despite the refusal: %q", got)
	}

	// A turn without a workspace leaves an existing one alone.
	if err := applyTurnWorkDir(ag, ""); err != nil {
		t.Fatal(err)
	}
	if got := ag.WorkDir(); got != `C:\data\project\cases\in_1` {
		t.Fatalf("workspace = %q after an empty turn", got)
	}
}
