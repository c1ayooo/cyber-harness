package spray

import (
	"fmt"

	"github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/types"
)

func init() {
	client.Register("spray", func(c *client.Client, raw any) (types.Engine, error) {
		cfg, ok := raw.(*Config)
		if raw != nil && !ok {
			return nil, fmt.Errorf("spray config must be *spray.Config, got %T", raw)
		}
		if cfg == nil {
			cfg = NewConfig()
		}

		fingersEng, err := c.Fingers()
		if err != nil {
			return nil, fmt.Errorf("spray requires fingers: %w", err)
		}
		if len(cfg.Providers) == 0 {
			cfg.WithProvider(c.Providers()...)
		}
		if cfg.FingersEngine == nil {
			cfg.WithFingersEngine(fingersEng)
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
	return client.WithEngineConfig("spray", cfg)
}

func FromClient(c *client.Client) (*Engine, error) {
	eng, err := c.Engine("spray")
	if err != nil {
		return nil, err
	}
	sprayEng, ok := eng.(*Engine)
	if !ok {
		return nil, fmt.Errorf("registered spray engine has unexpected type %T", eng)
	}
	return sprayEng, nil
}
