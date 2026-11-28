// Package rulesconfig is the rule hot-reload brick's own configuration
// section (4zrcin docs/20): one key, the directory of instance rules the node
// watches. The package depends on nothing from the engine beyond the
// configuration declarations, so a host can read the section without linking
// the brick.
package rulesconfig

import (
	cfg "github.com/chainreactors/cyber/pkg/config"
)

// ConfigKey is the section key.
const ConfigKey = "rules"

// EnvDir carries the directory to a node whose file sections are replaced by
// what the Hub distributes.
const EnvDir = "CYBER_RULES_DIR"

// Config is the brick's configuration. An empty Dir leaves the brick inert.
type Config struct {
	Dir string `config:"dir" json:"dir" description:"Directory of instance rules (fingers/ and pocs/); empty disables the rule hot reload"`
}

// Section declares the section, including the environment mapping.
func Section() cfg.Section {
	return cfg.Section{
		Key:         ConfigKey,
		New:         func() any { return &Config{} },
		Environment: environment,
	}
}

func environment(sources cfg.Sources) (map[string]any, map[string]any, error) {
	overrides := map[string]any{}
	if _, explicit := sources.CLI["dir"]; !explicit {
		if value, ok := sources.LookupEnv(EnvDir); ok && value != "" {
			overrides["dir"] = value
		}
	}
	if len(overrides) == 0 {
		return nil, nil, nil
	}
	return overrides, nil, nil
}

// Read decodes the section from a parsed option set.
func Read(option *cfg.Option) (Config, error) {
	if option == nil {
		return Config{}, nil
	}
	if option.Resolved != nil {
		decoded, err := cfg.Get[*Config](option.Resolved, ConfigKey)
		if err != nil {
			return Config{}, err
		}
		return *decoded, nil
	}
	raw, err := Section().Decode(option.Extensions[ConfigKey])
	if err != nil {
		return Config{}, err
	}
	return *raw.(*Config), nil
}
