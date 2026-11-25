package gogo

import (
	"fmt"

	"github.com/chainreactors/sdk/client"
	"github.com/chainreactors/sdk/pkg/types"
)

func init() {
	client.Register("gogo", func(c *client.Client, raw any) (types.Engine, error) {
		cfg, ok := raw.(*Config)
		if raw != nil && !ok {
			return nil, fmt.Errorf("gogo config must be *gogo.Config, got %T", raw)
		}
		if cfg == nil {
			cfg = NewConfig()
		}

		fingersEng, err := c.Fingers()
		if err != nil {
			return nil, fmt.Errorf("gogo requires fingers: %w", err)
		}
		neutronEng, err := c.Neutron()
		if err != nil {
			return nil, fmt.Errorf("gogo requires neutron: %w", err)
		}
		if cfg.FingersEngine == nil {
			cfg.WithFingersEngine(fingersEng)
		}
		if cfg.NeutronEngine == nil {
			cfg.WithNeutronEngine(neutronEng)
		}
		if len(cfg.Providers) == 0 {
			cfg.WithProvider(c.Providers()...)
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
	return client.WithEngineConfig("gogo", cfg)
}

func FromClient(c *client.Client) (*Engine, error) {
	eng, err := c.Engine("gogo")
	if err != nil {
		return nil, err
	}
	gogoEng, ok := eng.(*Engine)
	if !ok {
		return nil, fmt.Errorf("registered gogo engine has unexpected type %T", eng)
	}
	return gogoEng, nil
}
