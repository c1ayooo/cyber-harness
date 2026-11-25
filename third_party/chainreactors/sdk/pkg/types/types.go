package types

import (
	"context"
	"io"
)

// ====================
// SDK Core
// ====================

type (
	Engine interface {
		Name() string
		Execute(ctx Context, task Task) (<-chan Result, error)
		io.Closer
	}

	// Provider 是统一的数据源接口，CyberHub 和 Embed 均实现此接口。
	Provider interface {
		Fingers(ctx context.Context) (Fingers, []*Alias, error)
		POCs(ctx context.Context) ([]*Template, error)
	}

	Context interface {
		Context() context.Context
	}

	Task interface {
		Type() string
		Validate() error
	}

	Result interface {
		Success() bool
		Error() error
		Data() interface{}
	}
)
