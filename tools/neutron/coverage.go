package neutron

import (
	"context"
	"fmt"
	"strings"

	coretool "github.com/chainreactors/cyber/core/tool"
	"github.com/chainreactors/neutron/templates"
	sdkneutron "github.com/chainreactors/sdk/neutron"
	"github.com/chainreactors/sdk/pkg/provider"
)

// templateCoverage counts what -t handed in versus what the engine can run.
// A parsed template may still be dropped at compile time.
type templateCoverage struct {
	Paths    int
	Parsed   int
	Compiled int
}

func (c templateCoverage) Dropped() int {
	if c.Parsed <= c.Compiled {
		return 0
	}
	return c.Parsed - c.Compiled
}

// emitCoverage puts the compile-time drop count into the tool result itself, so
// the model reads it in this turn and can write it down. The host log alone
// leaves the difference between "the library had nothing" and "the template
// never ran" invisible to the operator.
//
// It goes to stderr on purpose: stdout may be JSON lines (-j) or a redirected
// file, and a notice line there would break the records the caller parses.
func emitCoverage(execution *coretool.Execution, coverage templateCoverage) {
	if execution == nil || execution.Stderr == nil || coverage.Dropped() == 0 {
		return
	}
	fmt.Fprintf(execution.Stderr, "[neutron] template coverage: parsed=%d compiled=%d dropped=%d — unsupported protocol or invalid template body dropped at compile time; the -t set and the templates this run could use differ.\n",
		coverage.Parsed, coverage.Compiled, coverage.Dropped())
}

func loadNeutronTemplatePaths(paths []string, proxyURL string) ([]*templates.Template, templateCoverage, error) {
	if len(paths) == 0 {
		return nil, templateCoverage{}, nil
	}
	cfg := sdkneutron.NewConfig().WithProxy(proxyURL)
	engine, err := sdkneutron.NewEngine(cfg.WithTemplates([]*templates.Template{minimalCompilableTemplate()}))
	if err != nil {
		return nil, templateCoverage{}, fmt.Errorf("neutron: initialize template loader: %w", err)
	}
	defer engine.Close()
	var coverage templateCoverage
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		// Parse first so the parsed count is observable: AddPocsFile hides it,
		// and without the input number a compile-time drop cannot be reported.
		pocs, err := provider.NewFileProvider("", path).POCs(context.Background())
		if err != nil {
			return nil, templateCoverage{}, fmt.Errorf("neutron: load templates %s: %w", path, err)
		}
		coverage.Paths++
		coverage.Parsed += len(pocs)
		if err := engine.AddPocs(pocs); err != nil {
			return nil, templateCoverage{}, fmt.Errorf("neutron: compile templates %s: %w", path, err)
		}
	}

	var loaded []*templates.Template
	for _, tmpl := range engine.Get() {
		if tmpl == nil || tmpl.Id == minimalTemplateID {
			continue
		}
		loaded = append(loaded, tmpl)
	}
	coverage.Compiled = len(loaded)
	return nonNilSortedTemplates(loaded), coverage, nil
}
