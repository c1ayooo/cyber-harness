package main

import (
	"context"
	"slices"
	"time"

	"github.com/c1ayooo/cyber/exts/gateway"
	ioaclient "github.com/c1ayooo/cyber/exts/ioa/client"
	passiveconfig "github.com/c1ayooo/cyber/exts/passive/config"
	scannerext "github.com/c1ayooo/cyber/exts/scanner"
	searchext "github.com/c1ayooo/cyber/exts/search"
	"github.com/c1ayooo/cyber/pkg/cli/configuration"
	cfg "github.com/c1ayooo/cyber/pkg/config"
)

// Product connections are contributed here; the shared commands do not import
// scanner, search, or collaboration implementations.
func configChecks(ctx context.Context, option *cfg.Option, online bool) []configuration.Check {
	if !online {
		return nil
	}
	value, err := cfg.SharedFromOption(option)
	if err != nil {
		return []configuration.Check{{Name: "connections", Message: "cannot resolve connection settings"}}
	}
	cfg.NormalizeLLMConfig(value.Llm)
	var selected []string
	if hub, err := scannerext.ReadCyberhub(option); err == nil && hub.URL != "" {
		selected = append(selected, scannerext.CyberhubConfigKey)
	}
	recon, reconErr := passiveconfig.Read(option)
	if reconErr == nil && recon.HunterAPIKey != "" {
		selected = append(selected, passiveconfig.ConfigKey)
	}
	searchKeys, searchErr := searchext.ReadKeys(option)
	if (reconErr == nil && recon.TavilyKey != "") || (searchErr == nil && searchKeys != "") {
		selected = append(selected, searchext.ConfigKey)
	}
	if services, err := gateway.Read(option); err == nil {
		configured := map[string]bool{}
		for name, fields := range services {
			kind, _ := fields["kind"].(string)
			if kind == "" {
				kind = name
			}
			configured[kind] = true
		}
		if configured["fofa"] {
			selected = append(selected, "gateway.fofa")
		}
		if configured["hunter"] && !slices.Contains(selected, passiveconfig.ConfigKey) {
			selected = append(selected, passiveconfig.ConfigKey)
		}
		if configured["tavily"] && !slices.Contains(selected, searchext.ConfigKey) {
			selected = append(selected, searchext.ConfigKey)
		}
	}
	if client, err := ioaclient.ReadOptions(option); err == nil && client.URL != "" {
		selected = append(selected, ioaclient.ConfigKey)
	}
	var checks []configuration.Check
	for _, section := range selected {
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		results, err := defaultSections().TestConnection(checkCtx, section, value, value)
		cancel()
		if err != nil {
			checks = append(checks, configuration.Check{Name: section, Message: "connection check failed"})
			continue
		}
		for _, result := range results {
			message := "connection successful"
			if !result.Ok {
				message = "connection failed; check endpoint and credentials"
			}
			checks = append(checks, configuration.Check{Name: result.Name, OK: result.Ok, Message: message})
		}
	}
	return checks
}
