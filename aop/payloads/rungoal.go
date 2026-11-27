package payloads

import (
	"encoding/json"
	"strconv"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// RunGoalPayload separates the evaluator's goal from the executor's turn
// message: a control plane that owns the intent judges against its own goal,
// not the executor's brief. EvalRounds stays raw so a producer that models
// the round budget as a JSON number still delivers the goal.
type RunGoalPayload struct {
	Goal       string          `json:"goal"`
	EvalRounds json.RawMessage `json:"eval_rounds,omitempty"`
}

// RunGoalExtension encodes an evaluated turn's goal. Empty goal and empty
// round pacing return nil, which keeps the upstream behavior (the evaluator
// derives its goal from the turn input) for runs that are not evaluated.
func RunGoalExtension(goal, evalRounds string) *anypb.Any {
	goal = strings.TrimSpace(goal)
	evalRounds = strings.TrimSpace(evalRounds)
	if goal == "" && evalRounds == "" {
		return nil
	}
	payload := RunGoalPayload{Goal: goal}
	if evalRounds != "" {
		payload.EvalRounds = json.RawMessage(strconv.Quote(evalRounds))
	}
	return extension(RunGoalExtensionURL, payload)
}

// ParseRunGoal decodes the evaluator goal. ok is false when the extension is
// absent or malformed.
func ParseRunGoal(ext *anypb.Any) (payload RunGoalPayload, ok bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), RunGoalURLs) {
		return RunGoalPayload{}, false
	}
	if err := json.Unmarshal(ext.GetValue(), &payload); err != nil {
		return RunGoalPayload{}, false
	}
	return payload, true
}

// EvalRoundsText normalizes the optional pacing spec: a string is taken
// as-is, a number is its decimal form, null/invalid is empty.
func EvalRoundsText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil {
		return strconv.FormatFloat(number, 'f', -1, 64)
	}
	return ""
}
