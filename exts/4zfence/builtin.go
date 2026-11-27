package fence

// The guaranteed audit (fork patch 23b, docs/04): a built-in corpus of
// destructive and exfiltration command patterns is audited unconditionally —
// before the policy nil-check, the scope filter and the mode logic — so a
// capture node without any provider still records the audit rows the control
// plane renders with the "builtin." source badge. The corpus lives in
// tools/resources (guardrail_builtin.yaml, compiled by builtin_gen.go) and
// ships in every binary form: unlike the template resources it is never
// stripped, because the audit duty is not a capability.

import (
	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/tools/resources"
)

// BuiltinCommandReason returns the guaranteed-audit reason for one tool call,
// or "" when the call's command text matches no built-in pattern. The reason
// is "builtin.<id> (<desc>)"; the control plane recognizes the prefix and
// renders the row with source=builtin (hub audit rows, P3).
func BuiltinCommandReason(call *aop.ToolCall) string {
	text := commandText(call)
	if text == "" {
		return ""
	}
	for _, pattern := range resources.GuardrailBuiltinPatterns {
		if pattern.Pattern.MatchString(text) {
			return "builtin." + pattern.ID + " (" + pattern.Desc + ")"
		}
	}
	return ""
}
