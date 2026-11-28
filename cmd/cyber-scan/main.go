// Package main is the cyber-scan command. The application assembly lives in
// pkg/assembly so an embedding control plane runs the exact same node; this
// file owns only the process shell (signals, exit codes).
package main

import (
	"fmt"
	"os"

	"github.com/chainreactors/cyber/pkg/assembly"
)

func main() {
	if err := assembly.Exec(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
