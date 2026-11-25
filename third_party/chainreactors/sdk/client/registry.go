package client

import (
	"fmt"
	"strings"
	"sync"

	"github.com/chainreactors/sdk/pkg/types"
)

type Factory func(*Client, any) (types.Engine, error)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Factory)
)

func Register(name string, factory Factory) {
	name = normalizeName(name)
	if name == "" {
		panic("client: empty engine name")
	}
	if factory == nil {
		panic("client: nil engine factory")
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("client: engine %q already registered", name))
	}
	registry[name] = factory
}

func Lookup(name string) Factory {
	name = normalizeName(name)
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[name]
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
