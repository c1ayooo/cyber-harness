package provider

import (
	"context"

	"github.com/chainreactors/fingers/alias"
	fingersEngine "github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/sdk/pkg/types"
	"gopkg.in/yaml.v3"
)

// EmbedProvider 从 fingers/gogo 库内置的 embed 资源加载指纹、别名和 POC 数据。
type EmbedProvider struct{}

func NewEmbedProvider() *EmbedProvider {
	return &EmbedProvider{}
}

func (p *EmbedProvider) Fingers(ctx context.Context) (types.Fingers, []*types.Alias, error) {
	httpFingers, err := fingersEngine.LoadFingers(resources.FingersHTTPData)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range httpFingers {
		if f.Protocol == "" {
			f.Protocol = "http"
		}
	}

	socketFingers, err := fingersEngine.LoadFingers(resources.FingersSocketData)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range socketFingers {
		if f.Protocol == "" {
			f.Protocol = "tcp"
		}
	}

	var aliases []*alias.Alias
	if len(resources.AliasesData) > 0 {
		if err := yaml.Unmarshal(resources.AliasesData, &aliases); err != nil {
			return nil, nil, err
		}
	}

	return append(httpFingers, socketFingers...), aliases, nil
}
