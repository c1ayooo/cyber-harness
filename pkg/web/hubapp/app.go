// Package hubapp assembles the Hub application from raw command-line
// arguments, exactly as the cyber-harness command does. It exists so the
// command and an embedding control plane (the 4zrcin single binary, patch 22)
// share one source of truth: the codec, the flag surface, the config store and
// the management wiring are defined once, and a caller only overrides what it
// owns — most importantly the listener (docs/04 M1).
package hubapp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/telemetry"
	ioaserver "github.com/c1ayooo/cyber/exts/ioa/server"
	webext "github.com/c1ayooo/cyber/exts/web"
	"github.com/c1ayooo/cyber/pkg/cli/configuration"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	webpkg "github.com/c1ayooo/cyber/pkg/web"
	managementapi "github.com/c1ayooo/cyber/pkg/web/api"
	webhost "github.com/c1ayooo/cyber/pkg/web/host"
	webservice "github.com/c1ayooo/cyber/pkg/web/service"
	ioaservice "github.com/c1ayooo/cyber/tools/ioa/server"
	webstatic "github.com/c1ayooo/cyber/web"
	flags "github.com/jessevdk/go-flags"
)

// options is the cyber-harness command's flag surface. It stays here so the
// command, its help output and an embedded host cannot drift apart.
type options struct {
	MaxScans        int    `long:"max-scans" default:"3" description:"Maximum concurrent remote scans"`
	ScanTimeout     int    `long:"scan-timeout" default:"600" description:"Maximum scan runtime in seconds"`
	Addr            string `long:"addr" default:"127.0.0.1:8080" description:"HTTP listen address"`
	DB              string `long:"db" default:"cyber-harness.db" description:"SQLite database path"`
	Token           string `long:"token" description:"Access key (auto-generated if empty)"`
	cfg.LLMOptions  `group:"Shared model settings"`
	cfg.MiscOptions `group:"Options"`
}

// App parses args the way the cyber-harness command does (including the
// configuration subcommands and help handling) and runs the Hub until ctx is
// cancelled. stdout/stderr receive CLI output and the telemetry logger's
// stream. override, when non-nil, runs after parsing but before Serve — an
// embedding control plane passes a Listener there (patch 22) and may adjust
// the assembled config; it must not replace the management wiring.
func App(ctx context.Context, args []string, stdout, stderr io.Writer, override func(*webhost.Config)) error {
	codec := webhost.SharedConfigCodec()
	if handled, err := configuration.Run(ctx, args, configuration.Host{Name: "cyber-harness", Sections: codec.Sections, Out: stdout, Err: stderr}); handled {
		return err
	}
	var opts options
	parser := flags.NewParser(&opts, flags.Default&^flags.PrintErrors)
	parser.Name = "cyber-harness"
	parser.Usage = "[OPTIONS]\n\nProfile-neutral Web Hub. Connect cyber-scan, cyber-audit or custom AOP nodes."
	configuration.RegisterHelp(parser)
	parser.SubcommandsOptional = true
	rest, err := parser.ParseArgs(args)
	if err != nil {
		var flagErr *flags.Error
		if errors.As(err, &flagErr) && flagErr.Type == flags.ErrHelp {
			parser.WriteHelp(stdout)
			return nil
		}
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}
	if opts.Version {
		_, err := fmt.Fprintf(stdout, "cyber-harness v%s\n", cfg.Version)
		return err
	}
	explicit := cfg.Option{LLMOptions: opts.LLMOptions, MiscOptions: opts.MiscOptions, Sections: codec.Sections}
	cfg.CaptureExplicitFlags(&explicit, parser)
	option := explicit
	if _, err := cfg.ResolveRuntimeConfig(&option); err != nil {
		return err
	}
	if option.Snapshot != nil {
		for _, message := range option.Snapshot.Diagnostics {
			fmt.Fprintln(stderr, message)
		}
	}
	store := &webhost.FileConfigStore{Explicit: opts.ConfigFile, Runtime: &option, Overrides: &explicit, Codec: codec}
	key := opts.Token
	if key == "" {
		key = rand.Text()
	}
	static, err := fs.Sub(webstatic.FS, "static")
	if err != nil {
		return err
	}
	logger := telemetry.GlobalLogger(telemetry.LogConfig{Debug: opts.Debug, Quiet: opts.Quiet, Output: stderr, Color: !opts.NoColor})
	config := webhost.Config{
		Addr: opts.Addr, Static: static, Logger: logger,
		Management: webext.Config{
			Product: "cyber-harness", Profiles: []webpkg.Profile{{ID: "cyber-scan", Title: "Cyber Scan"}, {ID: "cyber-audit", Title: "Cyber Audit"}},
			Manifest: []webpkg.Capability{{ID: "ioa", Title: "IOA", APIRoutes: []string{"/ioa/nodes", "/ioa/spaces", "/ioa/messages"}, UIContribs: []string{"ioa-console", "ioa-mentions"}}},
			Database: opts.DB, AccessKey: key, ConfigStore: store,
			ConfigAPI: managementapi.ConfigOptions{Sections: codec.Sections}, RuntimeLLM: store.RuntimeLLM,
			Scans: &webservice.ScanServiceConfig{MaxConcurrent: opts.MaxScans, ScanTimeout: time.Duration(opts.ScanTimeout) * time.Second},
		},
		Extensions: []extension.Extension{ioaserver.NewBrowser(ioaservice.Config{AccessKey: key})},
	}
	if override != nil {
		override(&config)
	}
	return webhost.Serve(ctx, config)
}
