package scanner

import (
	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/telemetry"
	"github.com/c1ayooo/cyber/tools/curl"
)

// NewHTTP installs curl without loading scan engines or model capabilities.
func NewHTTP() extension.Extension {
	return extension.Func{LoadFunc: func(scope *extension.Scope) error {
		logger, err := extension.Use[telemetry.Logger](scope)
		if err != nil {
			return err
		}
		endpoint, err := extension.Use[egress.Endpoint](scope)
		if err != nil {
			return err
		}
		stream, err := extension.Use[*events.Stream](scope)
		if err != nil {
			return err
		}
		return extension.Add(scope, curl.NewCommand(logger, endpoint.ProxyURL(), stream))
	}}
}
