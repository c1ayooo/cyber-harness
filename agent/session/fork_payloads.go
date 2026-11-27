package session

// The fork payload decorators, as default turn/open decorators: behavior
// identical to the pre-G1 inline application (fork patches 3/8/15/20/24/26),
// now expressed through the seam-G1 decorator contract (docs/19 appendix A)
// so the control plane's payloads keep landing while the composition root
// stays free to override the list.
//
// When 4zsession is extracted (P1-4's remaining move), these closures move
// into that extension and the composition root registers them explicitly;
// the default here is what makes that move behavior-identical.

import (
	aop "github.com/chainreactors/cyber/aop"
)

// defaultForkTurnDecorators returns the fork payload decorators in their
// historical application order: fence rules register first (the proxy judges
// this turn's requests against them), then the egress binding, then the
// input enrichments.
func defaultForkTurnDecorators() []RunTurnDecorator {
	return []RunTurnDecorator{
		fenceRulesDecorator,
		egressProxyDecorator,
		runGoalDecorator,
		caseSeedDecorator,
		toolEnvDecorator,
		workDirDecorator,
	}
}

// fenceRulesDecorator registers the project scope rules and the instance
// fence for the turn's session. A full table rejects the turn: an unfenced
// run is never acceptable.
func fenceRulesDecorator(req *aop.RunTurnRequest, input *RunInput) error {
	if err := turnScopeRules(req); err != nil {
		return err
	}
	return turnGlobalFence(req)
}

// egressProxyDecorator binds the session's outbound calls to the project
// proxy the manifest held at dispatch time.
func egressProxyDecorator(req *aop.RunTurnRequest, _ *RunInput) error {
	turnEgressProxy(req)
	return nil
}

// runGoalDecorator separates the evaluator's goal from the executor's turn
// message; its own extension wins over AgentRunOptions.eval_rounds.
func runGoalDecorator(req *aop.RunTurnRequest, input *RunInput) error {
	goal, rounds := turnRunGoal(req)
	if rounds == "" {
		rounds = input.EvalRounds
	}
	input.EvalGoal, input.EvalRounds = goal, rounds
	return nil
}

// caseSeedDecorator materializes the turn's case files. A malformed payload
// is an error: the control plane must learn the inputs did not land.
func caseSeedDecorator(req *aop.RunTurnRequest, input *RunInput) error {
	seed, err := turnCaseSeed(req)
	if err != nil {
		return err
	}
	input.Seed = seed
	return nil
}

// toolEnvDecorator carries the per-turn tool environment.
func toolEnvDecorator(req *aop.RunTurnRequest, input *RunInput) error {
	input.ToolEnv = turnToolEnv(req)
	return nil
}

// workDirDecorator carries the turn's workspace (a resumed turn never
// re-opens its session).
func workDirDecorator(req *aop.RunTurnRequest, input *RunInput) error {
	input.WorkDir = turnWorkDir(req)
	return nil
}
