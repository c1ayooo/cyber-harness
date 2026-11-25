package harness

import (
	"io/fs"

	"github.com/c1ayooo/cyber/agent/provider"
	toolpb "github.com/c1ayooo/cyber/aop/tool"
	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/eventbus"
	"github.com/c1ayooo/cyber/core/events"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/hooks"
	"github.com/c1ayooo/cyber/core/telemetry"
	coretool "github.com/c1ayooo/cyber/core/tool"
	fileext "github.com/c1ayooo/cyber/exts/files"
	guardrailext "github.com/c1ayooo/cyber/exts/guardrail"
	promptext "github.com/c1ayooo/cyber/exts/prompt"
	providerext "github.com/c1ayooo/cyber/exts/provider"
	skillsext "github.com/c1ayooo/cyber/exts/skills"
	terminalext "github.com/c1ayooo/cyber/exts/terminal"
	tmuxext "github.com/c1ayooo/cyber/exts/tmux"

	"github.com/c1ayooo/cyber/tools/files"
)

type BaseConfig struct {
	// Directory is the working directory the file and terminal tools operate in.
	Directory string
	// SkillPaths and SkillExclude select the skill library's contents.
	SkillPaths   []string
	SkillExclude []string
	Terminal     terminalext.Config
	Provider     provider.StartupConfig
	Logger       telemetry.Logger
	Guardrail    guardrailext.Config
	// Egress publishes the routing endpoint the terminal borrows. A host that
	// installs a proxy passes that extension; one that routes nothing passes
	// NoEgress.
	Egress extension.Extension
}

// BaseExtensions returns the default capabilities in load order. The caller
// owns their extension.Set and chooses any additional extensions explicitly.
func BaseExtensions(c BaseConfig) ([]extension.Extension, error) {
	if c.Logger == nil {
		c.Logger = telemetry.NopLogger()
	}
	library, err := skillsext.NewLibrary(skillsext.LibraryConfig{
		Directory: c.Directory, Paths: c.SkillPaths, Exclude: c.SkillExclude,
	})
	if err != nil {
		return nil, err
	}
	terminal := c.Terminal
	if terminal.Directory == "" {
		terminal.Directory = c.Directory
	}
	egressProvider := c.Egress
	if egressProvider == nil {
		egressProvider = NoEgress()
	}
	// Each entry borrows only from the ones ahead of it: the registries publish
	// the executors, the egress provider publishes the routing endpoint the
	// terminal needs. Session and product consumers are installed after this base.
	return []extension.Extension{
		extension.Provided[*hooks.Registry](hooks.New()),
		extension.Provided[*events.Stream](events.New()),
		extension.Provided[*eventbus.Bus[*toolpb.Progress]](eventbus.New[*toolpb.Progress]()),
		extension.Provided[telemetry.Logger](c.Logger),
		coretool.NewCommandRegistry(),
		coretool.NewToolRegistry(),
		guardrailext.New(c.Guardrail),
		library,
		promptext.New(),
		egressProvider,
		fileext.New(files.Config{Directory: c.Directory, Mounts: map[string]fs.FS{
			skillsext.RuntimeDocsURI: skillsext.RuntimeDocsFS(),
		}}),
		terminalext.New(terminal),
		tmuxext.New(),
		providerext.New(c.Provider),
	}, nil
}

// NoEgress publishes the routing endpoint of a host that routes nothing.
func NoEgress() extension.Extension {
	return extension.Provided[egress.Endpoint](egress.Disabled())
}
