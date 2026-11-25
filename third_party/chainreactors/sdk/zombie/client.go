package zombie

import (
	"fmt"

	"github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/types"
)

func init() {
	client.Register("zombie", func(c *client.Client, raw any) (types.Engine, error) {
		cfg, ok := raw.(*Config)
		if raw != nil && !ok {
			return nil, fmt.Errorf("zombie config must be *zombie.Config, got %T", raw)
		}
		if cfg == nil {
			cfg = NewConfig()
		}

		if cfg.ResourceProvider == nil {
			cfg.WithResourceProvider(c.ResourceProvider())
		}
		if len(cfg.Proxy) == 0 {
			cfg.Proxy = c.Proxy()
		}
		return NewEngine(cfg)
	})
}

func WithClientConfig(cfg *Config) client.Option {
	return client.WithEngineConfig("zombie", cfg)
}

func FromClient(c *client.Client) (*Engine, error) {
	eng, err := c.Engine("zombie")
	if err != nil {
		return nil, err
	}
	zombieEng, ok := eng.(*Engine)
	if !ok {
		return nil, fmt.Errorf("registered zombie engine has unexpected type %T", eng)
	}
	return zombieEng, nil
}
