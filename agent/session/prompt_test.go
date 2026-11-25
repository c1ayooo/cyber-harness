package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/cyber/agent"
	agentprompt "github.com/c1ayooo/cyber/agent/prompt"
	"github.com/c1ayooo/cyber/agent/skills"
	"github.com/c1ayooo/cyber/core/extension"
	"github.com/c1ayooo/cyber/core/telemetry"
	promptext "github.com/c1ayooo/cyber/exts/prompt"
	cfg "github.com/c1ayooo/cyber/pkg/config"
	"github.com/c1ayooo/cyber/pkg/testutil/apptest"
	"github.com/c1ayooo/cyber/pkg/testutil/hosttest"
)

func defaultPromptResolver(t *testing.T) agentprompt.Resolver {
	t.Helper()
	var resolver agentprompt.Resolver
	hosttest.Load(t, t.Context(), promptext.New(), extension.Func{LoadFunc: func(scope *extension.Scope) error {
		var err error
		resolver, err = extension.Use[agentprompt.Resolver](scope)
		return err
	}})
	return resolver
}

type fixedPromptResolver string

func (r fixedPromptResolver) Build(context.Context, agentprompt.Context) agentprompt.Result {
	return agentprompt.Result{Prompt: string(r)}
}

func TestResolveSystemPromptUsesConfigResolver(t *testing.T) {
	rt := &Runtime{
		agentConfig: agent.Config{PromptResolver: fixedPromptResolver("runtime")},
		Logger:      telemetry.NopLogger(),
	}
	result, err := rt.resolveSystemPrompt(t.Context(), nil)
	if err != nil || result != "runtime" {
		t.Fatalf("runtime resolver result = %q, %v", result, err)
	}

	result, err = rt.resolveSystemPrompt(t.Context(), &agent.Config{PromptResolver: fixedPromptResolver("config")})
	if err != nil || result != "config" {
		t.Fatalf("config resolver result = %q, %v", result, err)
	}
}

type capturePromptResolver struct{ at time.Time }

func (r *capturePromptResolver) Build(_ context.Context, input agentprompt.Context) agentprompt.Result {
	r.at = input.Agent.Now
	return agentprompt.Result{Prompt: input.Agent.Now.Format(time.RFC3339Nano)}
}

// The system prompt is rebuilt at the start of every run. Using the wall clock
// there made every wake a different prefix, so the provider cache missed the
// whole history. The session creation time is stable across runs.
func TestSystemPromptTimeIsSessionStable(t *testing.T) {
	started := time.Date(2026, 11, 15, 22, 0, 0, 0, time.UTC)
	resolver := &capturePromptResolver{}
	rt := &Runtime{
		agentConfig: agent.Config{PromptResolver: resolver},
		Logger:      telemetry.NopLogger(),
		startedAt:   started,
	}
	first, err := rt.resolveSystemPrompt(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	second, err := rt.resolveSystemPrompt(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("system prompt changed between runs: %q vs %q", first, second)
	}
	if !resolver.at.Equal(started) {
		t.Fatalf("prompt time = %s, want session start %s", resolver.at, started)
	}
}

// baseSkillBundle stands in for an extension-contributed base skill so the
// preload test stays neutral about which distribution owns the content.
func baseSkillBundle() skills.Bundle {
	return skills.Bundle{
		Skills: []skills.Skill{{
			Name: "baseline", Description: "fixture base skill",
			Source: skills.SourceBundle, Location: "fixture://skills/baseline/SKILL.md",
			BaseDir: "fixture://skills/baseline",
		}},
		ReadVirtual: func(location string) (string, bool, error) {
			if location != "fixture://skills/baseline/SKILL.md" {
				return "", false, nil
			}
			return "---\nname: baseline\ndescription: fixture base skill\n---\n# Fixture Baseline\n\nBASE_SKILL_MARKER", true, nil
		},
	}
}

func TestRuntimePreloadsBaseSkillOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		skills []string
	}{
		{name: "default"},
		{name: "explicit duplicate", skills: []string{"baseline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option := &cfg.Option{}
			option.Skills = tc.skills
			application := apptest.NewFixture(t, telemetry.NopLogger(), nil)
			resolver := defaultPromptResolver(t)

			applicationSet := loadTestApplication(t, application)
			defer applicationSet.Close(context.Background())
			if _, err := application.Skills.Add(baseSkillBundle()); err != nil {
				t.Fatal(err)
			}
			rt, err := newUnitResource(t, application, Config{BaseSkills: []string{"baseline"}, SelectedSkills: option.Skills, Logger: telemetry.NopLogger(), Loop: agent.StandardLoop{}, PromptResolver: resolver})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			rtSet := hosttest.Set(t, extension.Provided[*apptest.Fixture](application), rt)
			if err := rtSet.Load(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer rtSet.Close(context.Background())

			systemPrompt, err := rt.Runtime().resolveSystemPrompt(t.Context(), &rt.Runtime().agentConfig)
			if err != nil {
				t.Fatal(err)
			}
			if count := strings.Count(systemPrompt, "## Skill: baseline"); count != 1 {
				t.Fatalf("base skill count = %d, want 1", count)
			}
			if !strings.Contains(systemPrompt, "BASE_SKILL_MARKER") {
				t.Fatal("system prompt missing base skill body")
			}
		})
	}
}
