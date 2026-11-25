// Package main is the cyber-harness command. The application assembly lives
// in pkg/web/hubapp so an embedding control plane shares the exact same
// wiring; this file owns only the process shell (signals, exit codes).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/c1ayooo/cyber/pkg/web/hubapp"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "cyber-harness: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return hubapp.App(ctx, args, stdout, stderr, nil)
}
