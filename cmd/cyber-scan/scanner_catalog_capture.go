//go:build captureonly

package main

// The capture recipe's scanner catalog (docs/04 §3.3): empty. No scanner or
// discovery product exists in this binary, so the CLI's scanner sections and
// the passive-recon flag group are compiled out with the engines.

import "github.com/chainreactors/cyber/core/resource"

func productScannerNames() []string { return nil }

func productScannerAvailable(string) bool { return false }

func productScannerUsage(string) (string, bool) { return "", false }

func productScannerDescription(string) string { return "" }

func productScannerUsageLines() []string { return nil }

func resourceAddReconFlags(*resource.Registry) error { return nil }
