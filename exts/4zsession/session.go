// Package zsession is the 4zsession building block (4zrcin docs/19 P1-4):
// the fork payload decorators that enrich a turn's input — the evaluator's
// goal, the case seed files, the tool environment, and the workspace. The
// fence-side payloads (scope rules, global fence, egress proxy) live in the
// 4zfence package; the two building blocks do not import each other.
package zsession

import (
	"strings"

	agentsession "github.com/chainreactors/cyber/agent/session"
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/aop/payloads"
)

// TurnDecorators returns the input-enrichment decorators in their historical
// application order (they run after the fence decorators the composition
// appends first).
func TurnDecorators() []agentsession.RunTurnDecorator {
	return []agentsession.RunTurnDecorator{
		runGoalDecorator,
		caseSeedDecorator,
		toolEnvDecorator,
		workDirDecorator,
	}
}

// Decorate registers the block's request decorators (seam G1) on a session
// runtime config. Decorators already on the config — the fence's, which the
// composition appends first — stay ahead of these.
func Decorate(config *agentsession.Config) {
	config.TurnDecorators = append(config.TurnDecorators, TurnDecorators()...)
	config.OpenSessionDecorators = append(config.OpenSessionDecorators, OpenSessionDecorators()...)
}

// OpenSessionDecorators returns the decorators that resolve an open-session
// request into session options.
func OpenSessionDecorators() []agentsession.OpenSessionDecorator {
	return []agentsession.OpenSessionDecorator{openWorkDirDecorator}
}

// openWorkDirDecorator lands the workspace a control plane attached to the
// open request: the per-run case directory the session's file and shell tools
// resolve against, with the scheduling flag that selects the runtime's
// SingleTask mailbox policy. The AOP schema has no session work dir (a session
// runs in the agent process directory), so a control plane that owns a case
// directory sends it here instead of editing the shared schema. Empty keeps
// the agent's own working directory, which keeps old control planes working;
// options an earlier decorator already set are left alone.
func openWorkDirDecorator(req *aop.OpenSessionRequest, options *agentsession.SessionOptions) error {
	if value := openWorkDir(req); value.WorkDir != "" || value.SingleTask {
		options.WorkDir, options.SingleTask = value.WorkDir, value.SingleTask
	}
	return nil
}

// openWorkDir decodes the WorkDir extension of an open request.
func openWorkDir(req *aop.OpenSessionRequest) payloads.WorkDirPayload {
	if req == nil {
		return payloads.WorkDirPayload{}
	}
	if value, ok := payloads.ParseWorkDir(payloads.ExtensionWithURL(req.GetExtensions(), payloads.WorkDirURLs)); ok {
		value.WorkDir = strings.TrimSpace(value.WorkDir)
		if value.WorkDir != "" || value.SingleTask {
			return value
		}
	}
	return payloads.WorkDirPayload{}
}

// runGoalDecorator separates the evaluator's goal from the executor's turn
// message; its own extension wins over AgentRunOptions.eval_rounds.
func runGoalDecorator(req *aop.RunTurnRequest, input *agentsession.RunInput) error {
	goal, rounds := turnRunGoal(req)
	if rounds == "" {
		rounds = input.EvalRounds
	}
	input.EvalGoal, input.EvalRounds = goal, rounds
	return nil
}

// caseSeedDecorator materializes the turn's case files. A malformed payload
// is an error: the control plane must learn the inputs did not land.
func caseSeedDecorator(req *aop.RunTurnRequest, input *agentsession.RunInput) error {
	seed, err := turnCaseSeed(req)
	if err != nil {
		return err
	}
	input.Seed = seed
	return nil
}

// toolEnvDecorator carries the per-turn tool environment.
func toolEnvDecorator(req *aop.RunTurnRequest, input *agentsession.RunInput) error {
	input.ToolEnv = turnToolEnv(req)
	return nil
}

// workDirDecorator carries the turn's workspace (a resumed turn never
// re-opens its session).
func workDirDecorator(req *aop.RunTurnRequest, input *agentsession.RunInput) error {
	input.WorkDir = turnWorkDir(req)
	return nil
}

func turnRunGoal(req *aop.RunTurnRequest) (goal, rounds string) {
	if req == nil {
		return "", ""
	}
	if payload, ok := payloads.ParseRunGoal(payloads.ExtensionWithURL(req.GetExtensions(), payloads.RunGoalURLs)); ok {
		goal, rounds = strings.TrimSpace(payload.Goal), payloads.EvalRoundsText(payload.EvalRounds)
		if goal != "" || rounds != "" {
			return goal, rounds
		}
	}
	return "", ""
}

// turnWorkDir returns the workspace a control plane attached to this turn. It
// rides the same WorkDir extension the session opening carries: a resumed turn
// never re-opens its session, so a session the host re-created after a restart
// would otherwise keep the agent's process directory as its workspace.
func turnWorkDir(req *aop.RunTurnRequest) string {
	if req == nil {
		return ""
	}
	if payload, ok := payloads.ParseWorkDir(payloads.ExtensionWithURL(req.GetExtensions(), payloads.WorkDirURLs)); ok {
		return strings.TrimSpace(payload.WorkDir)
	}
	return ""
}

// turnCaseSeed decodes the files a control plane sends with this turn. A
// malformed payload is an error: a control plane that believes it delivered
// the inputs must learn that it did not, instead of the model reading stale
// or missing context.
func turnCaseSeed(req *aop.RunTurnRequest) ([]payloads.CaseSeedFile, error) {
	if req == nil {
		return nil, nil
	}
	return payloads.ParseCaseSeed(payloads.ExtensionWithURL(req.GetExtensions(), payloads.CaseSeedURLs))
}

// turnToolEnv returns the per-turn tool environment as KEY=VALUE pairs.
func turnToolEnv(req *aop.RunTurnRequest) []string {
	if req == nil {
		return nil
	}
	if pairs, ok := payloads.ParseToolEnv(payloads.ExtensionWithURL(req.GetExtensions(), payloads.ToolEnvURLs)); ok {
		return pairs
	}
	return nil
}
