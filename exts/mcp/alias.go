package mcp

import (
	"fmt"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// ValidateBashAlias rejects server aliases that collide with the bash
// namespace the extension installs native commands into. Extension.Load
// enforces the same rule at scan startup; exporting it lets a configuration
// editor (the control plane's settings save) reject the alias while the
// operator is editing instead of at the next node start. Fork-owned file:
// docs/19-decoupling-plan.md 已决 20 keeps each product section's rules in one
// place, shared by the extension and its editors.
func ValidateBashAlias(name string) error {
	if interp.IsBuiltin(name) || syntax.IsKeyword(name) {
		return fmt.Errorf("MCP server alias %q conflicts with a bash builtin or keyword; choose another alias", name)
	}
	return nil
}
