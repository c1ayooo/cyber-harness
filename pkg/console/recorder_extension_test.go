package console

import (
	"context"
	coreevents "github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	telemetry "github.com/c1ayooo/cyber/exts/telemetry"
	"testing"
)

// loadOutputRecorder mounts a recorder against the stream it should observe.
func loadOutputRecorder(t *testing.T, stream *coreevents.Stream, recorder *telemetry.Extension) error {
	t.Helper()
	set, err := extension.New(extension.Provided[*coreevents.Stream](stream), recorder)
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = set.Close(context.Background()) })
	return set.Load(t.Context())
}
