package mcp

import (
	"strings"
	"testing"

	"github.com/chainreactors/cyber/core/resource"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

func TestConfigurationDeclaresAndReadsServers(t *testing.T) {
	resources := resource.New()
	sections := cfg.NewSections()
	if _, err := resource.Define[cfg.Section](resources, sections); err != nil {
		t.Fatal(err)
	}
	if err := Declare(resources); err != nil {
		t.Fatal(err)
	}
	if !sections.Has(ConfigKey) {
		t.Fatal("mcp section was not declared")
	}
	fields := cfg.Values{ConfigKey: {"mcpServers": map[string]any{
		"ida":  map[string]any{"command": "ida-mcp", "args": []any{"--stdio"}, "tools": []any{"decompile"}},
		"docs": map[string]any{"url": "https://example.test/mcp"},
	}}}
	resolved, err := sections.ResolveValues(fields, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	config, err := cfg.Get[*Config](resolved, ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.MCPServers) != 2 {
		t.Fatalf("mcpServers = %+v", config.MCPServers)
	}
	if ida := config.MCPServers["ida"]; ida.Command != "ida-mcp" || len(ida.Args) != 1 || ida.Args[0] != "--stdio" {
		t.Fatalf("stdio server = %+v", ida)
	}
	if docs := config.MCPServers["docs"]; docs.URL != "https://example.test/mcp" {
		t.Fatalf("http server = %+v", docs)
	}

	// Both configuration evaluation paths used by hosts must decode the same
	// section: the resolved snapshot and a raw extensions map.
	for name, option := range map[string]*cfg.Option{
		"resolved": {Resolved: resolved, Extensions: resolved.Values()},
		"raw":      {Extensions: cfg.CloneValues(fields)},
	} {
		read, err := ReadConfig(option)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(read.MCPServers) != 2 || read.MCPServers["ida"].Command != "ida-mcp" {
			t.Fatalf("%s: ReadConfig() = %+v", name, read)
		}
	}

	empty, err := ReadConfig(&cfg.Option{})
	if err != nil || len(empty.MCPServers) != 0 {
		t.Fatalf("default ReadConfig() = %+v, %v", empty, err)
	}
}

func TestConfigurationRejectsUnknownServerFields(t *testing.T) {
	sections := cfg.NewSections()
	resources := resource.New()
	if _, err := resource.Define[cfg.Section](resources, sections); err != nil {
		t.Fatal(err)
	}
	if err := Declare(resources); err != nil {
		t.Fatal(err)
	}
	_, err := sections.ResolveValues(cfg.Values{ConfigKey: {"mcpServers": map[string]any{
		"ida": map[string]any{"command": "ida-mcp", "retired_field": true},
	}}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), ConfigKey) {
		t.Fatalf("unknown MCP server field was accepted: %v", err)
	}
}
