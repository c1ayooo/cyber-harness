package mcp

import (
	"strings"
	"testing"
)

func TestValidateBashAliasRejectsNamespaceConflicts(t *testing.T) {
	for _, name := range []string{"echo", "test", "printf", "if", "for", "declare"} {
		err := ValidateBashAlias(name)
		if err == nil {
			t.Fatalf("bash namespace conflict %q accepted", name)
		}
		if !strings.Contains(err.Error(), "conflicts with a bash builtin or keyword") {
			t.Fatalf("alias %q error = %q", name, err.Error())
		}
	}
	for _, name := range []string{"ida", "a-b_C", "nmap"} {
		if err := ValidateBashAlias(name); err != nil {
			t.Fatalf("legal alias %q rejected: %v", name, err)
		}
	}
}
