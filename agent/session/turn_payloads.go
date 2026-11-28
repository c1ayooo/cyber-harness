package session

import (
	"context"
	"fmt"
	"strings"

	"github.com/chainreactors/cyber/agent"
	inboxpkg "github.com/chainreactors/cyber/agent/inbox"
	"github.com/chainreactors/cyber/core/operation"
)

// prepareTurn lands what a control plane attached to a turn before the agent
// runs on it, in dependency order:
//
//   - the tool environment goes on the run context, so every tool call this
//     turn makes inherits it without mutating the shared BashTool base
//     environment (that would leak one session's token to another on the same
//     host);
//   - the workspace fills a session that has none, and is refused when it
//     disagrees with one the session already has (applyTurnWorkDir);
//   - the seed files are written under that workspace, after it is settled
//     (applyCaseSeed, seed.go);
//   - a continued turn's new input is pushed as a user message. The agent's
//     Continue only drains the inbox; without the push the message is dropped
//     and a session whose last message is assistant rejects the turn with
//     "cannot continue from message role: assistant" (seen on every steer
//     after a canceled run). The push cannot start a second run: the caller
//     (executeRun, via startRun) runs under an inbox that is already active.
//
// Every failure is fatal to the turn: a half-landed payload would let the
// model work on a mixture of this turn's inputs and another turn's leftovers.
func (s *sessionState) prepareTurn(ctx context.Context, input RunInput) (context.Context, error) {
	ctx = operation.ContextWithToolEnv(ctx, input.ToolEnv)
	if err := applyTurnWorkDir(s.agent, input.WorkDir); err != nil {
		return ctx, err
	}
	if err := applyCaseSeed(s.agent, input.Seed); err != nil {
		return ctx, err
	}
	if !input.automatic && input.Continue && input.Message != nil {
		_ = s.inbox.Push(inboxpkg.FromAOPMessage(input.Message, inboxpkg.OriginUser))
	}
	return ctx, nil
}

// applyTurnWorkDir gives a session without a workspace the one its control plane
// still names — the resumed turn after a host restart, where the session was
// re-created and never re-opened. A session that already has a different
// workspace is refused: the tools' relative paths would silently start landing
// somewhere else mid-run.
func applyTurnWorkDir(a *agent.Agent, dir string) error {
	dir = strings.TrimSpace(dir)
	if a == nil || dir == "" {
		return nil
	}
	current := strings.TrimSpace(a.WorkDir())
	if current == "" {
		a.SetWorkDir(dir)
		return nil
	}
	if !sameWorkspace(current, dir) {
		return fmt.Errorf("session already runs in workspace %q; the turn asked for %q", current, dir)
	}
	return nil
}

// sameWorkspace compares two workspace paths the way the host's tools do: case
// and separator differences are not a real change (Windows accepts both).
func sameWorkspace(a, b string) bool {
	normalize := func(p string) string {
		p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
		return strings.TrimRight(p, "/")
	}
	return strings.EqualFold(normalize(a), normalize(b))
}
