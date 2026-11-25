package scanner

import (
	"context"
	"fmt"
	"io/fs"

	curltools "github.com/c1ayooo/cyber/tools/curl"
	"github.com/c1ayooo/cyber/tools/cyberhub"
	gotools "github.com/c1ayooo/cyber/tools/gogo"
	neutrontools "github.com/c1ayooo/cyber/tools/neutron"
	"github.com/c1ayooo/cyber/tools/scan"
	spraytools "github.com/c1ayooo/cyber/tools/spray"
	zombietools "github.com/c1ayooo/cyber/tools/zombie"
	"github.com/chainreactors/sdk/pkg/association"

	"github.com/c1ayooo/cyber/agent"
	"github.com/c1ayooo/cyber/agent/prompt"
	"github.com/c1ayooo/cyber/agent/provider"
	"github.com/c1ayooo/cyber/agent/skills"
	"github.com/c1ayooo/cyber/agent/subagent"
	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/hooks"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"

	scannerskills "github.com/c1ayooo/cyber/exts/scanner/skills"
	"github.com/c1ayooo/cyber/tools/files"
	"github.com/c1ayooo/cyber/tools/resources"
	"github.com/c1ayooo/cyber/tools/scan/engine"
	"github.com/chainreactors/utils/parsers"
)

// Config contains only scanner inputs selected by the Profile.
type Config struct {
	Resources resources.Options
	Crawler   scan.Crawler
	// AgentName tags the scanner worker's AOP events; the composition root
	// sets it (cyber-scan passes "cyber").
	AgentName string
	Verify    string
}

type Extension struct {
	config        Config
	workDir       string
	engines       *engine.Set
	executionOnly bool
	files         *files.Files
}

func New(config Config, workDir string) *Extension {
	return &Extension{config: config, workDir: workDir}
}

// NewExecution installs scanner commands without borrowing model, prompt, skills,
// or agent-loop resources. Engine ownership and command construction are shared
// with the AI-enhanced distribution.
func NewExecution(config Config, workDir string) *Extension {
	return &Extension{config: config, workDir: workDir, executionOnly: true}
}

func (e *Extension) Load(scope *extension.Scope) error {
	if e == nil || scope == nil {
		return fmt.Errorf("scanner extension is not configured")
	}
	logger, err := extension.Use[telemetry.Logger](scope)
	if err != nil {
		return err
	}
	endpoint, err := extension.Use[egress.Endpoint](scope)
	if err != nil {
		return err
	}
	stream, err := extension.Use[*events.Stream](scope)
	if err != nil {
		return err
	}
	if err := scan.ValidateVerify(e.config.Verify); err != nil {
		return err
	}
	proxyURL := endpoint.ProxyURL()
	if proxyURL == "" {
		proxyURL = e.config.Resources.Proxy
	}
	e.engines, err = engine.InitWithOptions(scope.Init(), e.config.Resources, logger)
	if err != nil {
		logger.Warnf("scanner engines init error=%q action=continue_without_scanners", err)
		e.engines = nil
	}

	options := []scan.Option{scan.WithCrawler(e.config.Crawler)}
	if !e.executionOnly {
		providers, err := extension.Use[*provider.State](scope)
		if err != nil {
			return err
		}
		tools, err := extension.Use[coretool.Executor](scope)
		if err != nil {
			return err
		}
		store, err := extension.Use[*skills.Store](scope)
		if err != nil {
			return err
		}
		hookRegistry, err := extension.Use[*hooks.Registry](scope)
		if err != nil {
			return err
		}
		loop, err := extension.Use[agent.Loop](scope)
		if err != nil {
			return err
		}
		promptResolver, err := extension.Use[prompt.Resolver](scope)
		if err != nil {
			return err
		}
		if err := extension.Add(scope, scannerPromptContribution(), cyberPromptContribution()); err != nil {
			return err
		}
		bundle, bundleDiags := scannerskills.Bundle()
		for _, diag := range bundleDiags {
			logger.Warnf("scanner skills: %s %s", diag.Path, diag.Message)
		}
		if err := extension.Add(scope, bundle); err != nil {
			return err
		}
		// Mount the owned skill tree so the read tool resolves the command
		// DescriptionPaths; the store bundle above serves skill invocations.
		filesCap, err := extension.Use[*files.Files](scope)
		if err != nil {
			return err
		}
		e.files = filesCap
		for _, dir := range []string{"cyber", "scan"} {
			sub, err := fs.Sub(scannerskills.FS(), dir)
			if err != nil {
				return err
			}
			if err := filesCap.Mount("cyber://skills/"+dir+"/", sub); err != nil {
				return err
			}
		}
		executor, err := extension.Use[subagent.Executor](scope)
		if err != nil {
			return err
		}
		readSkill := func(name string) string {
			content, ok, err := store.ReadVirtual("cyber://skills/scan/" + name + ".md")
			if !ok || err != nil {
				return ""
			}
			return content
		}
		if err := extension.Add(scope, scannerSubagents(readSkill)...); err != nil {
			return err
		}
		model, providerConfig := providers.Current()
		config := agent.Config{
			AgentName:      e.config.AgentName,
			Lifetime:       scope.Lifetime(),
			Hooks:          hookRegistry,
			Loop:           loop,
			Provider:       model,
			Tools:          tools,
			Model:          providerConfig.Model,
			MaxTokens:      providerConfig.MaxTokens,
			ContextWindow:  providerConfig.ContextWindow,
			Logger:         logger,
			Bus:            stream,
			PromptResolver: promptResolver,
		}
		currentConfig := func(ctx context.Context) agent.Config {
			if caller, ok := agent.ToolAgentConfig(ctx); ok {
				return caller
			}
			current := config
			model, pc := providers.Current()
			current.Provider = model
			current.Model, current.MaxTokens, current.ContextWindow = pc.Model, pc.MaxTokens, pc.ContextWindow
			return current
		}
		options = append(options,
			scan.WithVerification(e.config.Verify, func(ctx context.Context) bool { return currentConfig(ctx).Provider != nil }),
			scan.WithWorker(func(ctx context.Context, name string, loot parsers.Loot) (string, error) {
				config := currentConfig(ctx)
				if config.Provider == nil {
					return "", fmt.Errorf("scanner subagent %q requires a model provider", name)
				}
				result, err := executor.Execute(ctx, config, subagent.Request{Name: name, Input: subagent.Input{Payload: loot}})
				if err != nil {
					return "", err
				}
				if result == nil {
					return "", nil
				}
				return result.Output, nil
			}),
		)
	} else {
		options = append(options, scan.WithExecutionOnly(), scan.WithVerification(e.config.Verify, nil))
	}
	options = append(options, scan.WithLogger(logger))

	var values []coretool.Command
	values = append(values, curltools.NewCommand(logger, proxyURL, stream))
	if command, err := gotools.NewCommand(e.engines, logger, proxyURL, stream); err != nil {
		logger.Warnf("gogo unavailable: %v", err)
	} else {
		values = append(values, command)
	}
	if command, err := neutrontools.NewCommand(e.engines, logger, proxyURL, stream); err != nil {
		logger.Warnf("neutron unavailable: %v", err)
	} else {
		values = append(values, command)
	}
	if command, err := spraytools.NewCommand(e.engines, logger, proxyURL, stream); err != nil {
		logger.Warnf("spray unavailable: %v", err)
	} else {
		values = append(values, command)
	}
	if command, err := zombietools.NewCommand(e.engines, logger, proxyURL, stream); err != nil {
		logger.Warnf("zombie unavailable: %v", err)
	} else {
		values = append(values, command)
	}
	// cyberhub searches the fingerprint and POC index this extension builds, so
	// it is contributed by its owner. A nil index is not an empty one: the
	// command says how to configure the resources instead of reporting no hits.
	var index *association.Index
	if e.engines != nil {
		index = e.engines.Index
	}
	cyberhub := cyberhub.NewCyberhubSearch(index)
	values = append(values, coretool.Command{
		Name: cyberhub.Name(), Usage: cyberhub.Usage(),
		DescriptionPath: "cyber://skills/runtime/search.md",
		Run:             cyberhub.Run,
	})
	if e.engines == nil || e.engines.Gogo == nil || e.engines.Spray == nil {
		logger.Warnf("scan unavailable: scan engines are unavailable")
	} else {
		if proxyURL != "" {
			options = append(options, scan.WithProxy(proxyURL))
		}
		if stream != nil {
			options = append(options, scan.WithEvents(stream))
		}
		impl := scan.New(e.engines, options...)
		values = append(values, coretool.Command{
			Name: impl.Name(), Usage: impl.Usage(), QuickReference: impl.QuickReference(),
			DescriptionPath: "cyber://skills/cyber/okf/easm/scan.md",
			Run:             impl.Run,
		})
	}
	if err := extension.Add(scope, values...); err != nil {
		return err
	}
	return extension.Provide[*Availability](scope, availability(values, e.engines))
}

func (e *Extension) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	if e.files != nil {
		for _, dir := range []string{"scan", "cyber"} {
			if err := e.files.Unmount(ctx, "cyber://skills/"+dir+"/"); err != nil {
				return err
			}
		}
		e.files = nil
	}
	if e.engines != nil {
		e.engines.Close()
		e.engines = nil
	}
	return nil
}

var _ extension.Extension = (*Extension)(nil)
