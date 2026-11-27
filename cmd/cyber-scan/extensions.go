package main

import (
	"os"
	"path/filepath"
	"slices"

	webshellext "github.com/c1ayooo/4zwebshell/extension"
	"github.com/chainreactors/cyber/agent"
	"github.com/chainreactors/cyber/agent/prompt"
	"github.com/chainreactors/cyber/core/extension"
	loopext "github.com/chainreactors/cyber/exts/agent"
	arsenalext "github.com/chainreactors/cyber/exts/arsenal"
	"github.com/chainreactors/cyber/exts/gateway"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	mcpext "github.com/chainreactors/cyber/exts/mcp"
	okfext "github.com/chainreactors/cyber/exts/okf"
	proxyext "github.com/chainreactors/cyber/exts/proxy"
	searchext "github.com/chainreactors/cyber/exts/search"
	subagentext "github.com/chainreactors/cyber/exts/subagent"
	terminalext "github.com/chainreactors/cyber/exts/terminal"
	"github.com/chainreactors/cyber/pkg/assembly"
	cfg "github.com/chainreactors/cyber/pkg/config"
	harness "github.com/chainreactors/cyber/pkg/harness"
	"github.com/chainreactors/cyber/tools/scan"
)

// extensions returns the product's extensions in load order. Gateway binds
// configuration to the existing owners before their consumers are loaded.
func extensions(config appConfig, loop agent.Loop, workDir string, proxy *proxyext.Extension, guardrailConfig guardrailext.Config, judge assembly.Judge) ([]extension.Extension, error) {
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
		Policy:     judge.Ahead,
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
	// Behind the base: the bind hands the fence the guardrail runtime the
	// base just installed (docs/19 E3-2).
	extensions = append(extensions, judge.Behind...)
	engines, passiveBindings := assembly.Engines(assembly.EnginesInput{
		SkipEngines:      config.SkipEngines,
		Scanner:          config.Scanner,
		Recon:            config.Recon,
		ReconCredentials: config.ReconCredentials,
	}, workDir)
	search := searchext.New(searchext.Options{TavilyKeys: config.TavilyKeys})
	bindings := append([]gateway.Kind{proxy.Gateway(config.ProxyService)}, search.Gateway()...)
	bindings = append(bindings, passiveBindings...)
	extensions = append(extensions, gateway.New(config.Gateway, bindings...))
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

	// Webshell management (4zrcin docs/18): one ledger in the control plane,
	// two executors. The tools run a shell from this host and read the ledger
	// over the run's own identity, so a capture node that never gets a shell
	// call pays nothing and every turn without identity makes them unavailable.
	extensions = append(extensions, webshellext.New(webshellext.Config{NodeID: cfg.DefaultNodeID}))

	// The engine block is the recipe boundary (docs/04 §3.3): the scan-capture
	// build (-tags captureonly) compiles an empty twin, so the scanner, proton
	// and discovery extension packages — and with them the gogo/spray/zombie/
	// neutron/katana tool chains — never enter that binary. The traffic proxy
	// and guardrail above are the capture recipe's actual payload.
	extensions = append(extensions, engines...)
	if optionalToolEnabled(config.OptionalTools, "search") {
		extensions = append(extensions, search)
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
		extensions = append(extensions, mcpext.New(config.MCP.MCPServers))
	}
	return extensions, nil
}

func optionalToolEnabled(selected []string, name string) bool {
	return len(selected) == 0 || slices.Contains(selected, name)
}
