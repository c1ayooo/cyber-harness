package main

import (
	"os"
	"path/filepath"
	"slices"

	"github.com/c1ayooo/cyber/agent"
	"github.com/c1ayooo/cyber/agent/prompt"
	"github.com/c1ayooo/cyber/core/extension"
	loopext "github.com/c1ayooo/cyber/exts/agent"
	arsenalext "github.com/c1ayooo/cyber/exts/arsenal"
	guardrailext "github.com/c1ayooo/cyber/exts/guardrail"
	mcpext "github.com/c1ayooo/cyber/exts/mcp"
	okfext "github.com/c1ayooo/cyber/exts/okf"
	searchext "github.com/c1ayooo/cyber/exts/search"
	subagentext "github.com/c1ayooo/cyber/exts/subagent"
	terminalext "github.com/c1ayooo/cyber/exts/terminal"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	harness "github.com/c1ayooo/cyber/pkg/harness"
	"github.com/c1ayooo/cyber/tools/scan"
)

// extensions returns the product's extensions in the order they must load. It
// threads no capabilities: every extension borrows what it needs from the ones
// ahead of it, so this reads as a membership decision and nothing else.
func extensions(config appConfig, loop agent.Loop, workDir string, proxy extension.Extension, guardrailConfig guardrailext.Config) ([]extension.Extension, error) {
	config.DataDir = cfg.ResolveDataDir(config.DataDir)
	config.Scanner.Resources.CacheDir = filepath.Join(config.DataDir, "cache")

	bundle, err := EmbeddedBundle()
	if err != nil {
		return nil, err
	}
	arsenal, err := arsenalext.New(filepath.Join(config.DataDir, "arsenal"), ToolSpec.ManagerOption(bundle))
	if err != nil {
		return nil, err
	}
	childEnv := map[string]string{"PATH": arsenal.BinPath() + string(os.PathListSeparator) + os.Getenv("PATH")}

	extensions, err := harness.BaseExtensions(harness.BaseConfig{
		Guardrail:  guardrailConfig,
		Directory:  workDir,
		SkillPaths: config.CLISkillPaths,
		Terminal:   terminalext.Config{Environment: childEnv},
		Provider:   config.Provider,
		Logger:     config.Logger,
		Egress:     proxy,
	})
	if err != nil {
		return nil, err
	}
	// The loop installation publishes agent.Loop, so it precedes every
	// extension that runs against one.
	extensions = append(extensions, okfext.New(prompt.MainSystem, scan.ScannerSystemTarget), loopext.New(loop))
	// CYBER_EXCLUDE_TOOLS removes the model-facing subagent tool (profile.go
	// skips subagentext.NewTools). The Point itself is only dropped when no
	// engine extension is composed: the scan engines install scanner subagent
	// definitions and borrow the Subagent capability, so dropping it there would
	// break their composition rather than expose a tool.
	if !toolExcluded("subagent") || !config.SkipEngines {
		extensions = append(extensions, subagentext.New())
	}
	extensions = append(extensions, arsenal)

	// The engine block is the recipe boundary (docs/04 §3.3): the scan-capture
	// build (-tags captureonly) compiles an empty twin, so the scanner, proton
	// and discovery extension packages — and with them the gogo/spray/zombie/
	// neutron/katana tool chains — never enter that binary. The traffic proxy
	// and guardrail above are the capture recipe's actual payload.
	extensions = append(extensions, engineExtensions(config, workDir)...)
	if optionalToolEnabled(config.OptionalTools, "search") {
		extensions = append(extensions, searchext.New(searchext.Options{TavilyKeys: config.TavilyKeys}))
	}
	browser, err := browserExtension(config, workDir)
	if err != nil {
		return nil, err
	}
	if browser != nil {
		extensions = append(extensions, browser)
	}
	record, err := recordExtension(config, workDir)
	if err != nil {
		return nil, err
	}
	if record != nil {
		extensions = append(extensions, record)
	}
	// External MCP servers are operator configuration, not a distribution
	// capability: an empty section keeps the graph identical to a build that
	// never linked this extension.
	if len(config.MCP.MCPServers) > 0 {
		extensions = append(extensions, mcpext.New(config.MCP))
	}
	return extensions, nil
}

func optionalToolEnabled(selected []string, name string) bool {
	return len(selected) == 0 || slices.Contains(selected, name)
}
