package agent

import (
	coretool "github.com/c1ayooo/cyber/core/tool"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
	"testing"
)

func newTestTools(t testing.TB, tools ...coretool.Tool) coretool.Executor {
	t.Helper()
	return hosttest.Tools(t, tools...)
}
