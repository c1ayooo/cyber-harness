package fence

// The command-field rule the fence shares with the tools it guards: the bash
// tool decodes arguments into its own struct through encoding/json, which
// matches field names case-insensitively and assigns repeated keys in
// document order, so the later value wins. The fence reads the command out of
// the raw arguments under those same rules — otherwise a case-folded command
// key the tool executes escapes judgment entirely.

import (
	"bytes"
	"encoding/json"
	"strings"
)

// commandKeys are the documented command fields, in priority order.
var commandKeys = []string{"command", "cmd", "script", "input", "code"}

// commandField reads the command text out of a tool call's raw JSON arguments
// the way a command tool decodes them. A bare JSON string is the command text
// itself; invalid JSON and other non-objects are not commands. An object is
// walked in document order: a key folding-matching a command key
// (strings.EqualFold) records its value when that value is a JSON string, and
// a later match overrides an earlier one — exactly how encoding/json assigns
// a repeated key to the same struct field twice. The first command key
// holding non-blank text (in commandKeys order) wins. When none does, ok is
// false and the text falls back to the raw arguments, so the guaranteed
// audit's line-end-anchored patterns still match the original JSON.
func commandField(raw []byte) (text string, ok bool) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw), false
	}
	switch typed := value.(type) {
	case string:
		return typed, strings.TrimSpace(typed) != ""
	case map[string]any:
		return objectCommandField(raw)
	default:
		return string(raw), false
	}
}

// objectCommandField walks an argument object's keys in document order, which
// the decoded map cannot preserve. Keys matching no command key are decoded
// past and skipped; a matched key whose value is not a string is ignored —
// the tool's own decode rejects such a payload, so it never executes.
func objectCommandField(raw []byte) (text string, ok bool) {
	values := make(map[string]string, len(commandKeys))
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if _, err := decoder.Token(); err != nil { // the opening '{'
		return string(raw), false
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		name, _ := token.(string)
		var field any
		if err := decoder.Decode(&field); err != nil {
			break
		}
		for _, commandKey := range commandKeys {
			if !strings.EqualFold(name, commandKey) {
				continue
			}
			if value, isString := field.(string); isString {
				values[commandKey] = value
			}
			break
		}
	}
	for _, commandKey := range commandKeys {
		if text, has := values[commandKey]; has && strings.TrimSpace(text) != "" {
			return text, true
		}
	}
	return string(raw), false
}
