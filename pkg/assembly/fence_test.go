package assembly

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainreactors/cyber/core/egress"
	"github.com/chainreactors/cyber/core/events"
	"github.com/chainreactors/cyber/core/extension"
	"github.com/chainreactors/cyber/core/hooks"
	"github.com/chainreactors/cyber/core/namespaces"
	"github.com/chainreactors/cyber/core/operation"
	"github.com/chainreactors/cyber/core/resource"
	coretool "github.com/chainreactors/cyber/core/tool"
	fenceext "github.com/chainreactors/cyber/exts/4zfence"
	fenceconfig "github.com/chainreactors/cyber/exts/4zfence/config"
	"github.com/chainreactors/cyber/exts/4zfence/egressroutes"
	guardrailext "github.com/chainreactors/cyber/exts/guardrail"
	proxyext "github.com/chainreactors/cyber/exts/proxy"
	cfg "github.com/chainreactors/cyber/pkg/config"
)

// resolve builds a resolved configuration with the guardrail section and,
// optionally, the fence section declared — the two shapes Fence must read.
func resolve(t *testing.T, withFence bool, file cfg.Values) *cfg.Resolved {
	t.Helper()
	resources := resource.New()
	sections := cfg.NewSections()
	if _, err := resource.Define[cfg.Section](resources, sections); err != nil {
		t.Fatal(err)
	}
	if err := guardrailext.Declare(resources); err != nil {
		t.Fatal(err)
	}
	if withFence {
		if err := fenceext.Declare(resources); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := sections.ResolveValues(file, nil, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func guardrailOf(t *testing.T, resolved *cfg.Resolved) guardrailext.Config {
	t.Helper()
	value, err := cfg.Get[*guardrailext.Config](resolved, guardrailext.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	return *value
}

// The judge's provider is the fence section's, falling back to the guardrail
// section's; JEV is needed exactly when that provider is jev or hybrid.
func TestFenceProviderAndJEVNeed(t *testing.T) {
	llm := map[string]any{"base_url": "http://127.0.0.1:1/v1", "model": "judge"}
	for _, test := range []struct {
		name    string
		withF   bool
		file    cfg.Values
		wantJEV bool
	}{
		{name: "fence_jev", withF: true, file: cfg.Values{"fence": {"provider": "jev"}}, wantJEV: true},
		{name: "fence_hybrid", withF: true, file: cfg.Values{"fence": {"provider": "hybrid", "llm": llm}}, wantJEV: true},
		{name: "fence_llm", withF: true, file: cfg.Values{"fence": {"provider": "llm", "llm": llm}}},
		{name: "fence_none", withF: true, file: cfg.Values{"fence": {"provider": "none"}, "guardrail": {"provider": "jev"}}},
		{name: "fence_empty_falls_back_to_guardrail_jev", withF: true, file: cfg.Values{"fence": {}, "guardrail": {"provider": "jev"}}, wantJEV: true},
		{name: "no_fence_section_guardrail_jev", file: cfg.Values{"guardrail": {"provider": "jev"}}, wantJEV: true},
		{name: "no_fence_section_guardrail_none", file: cfg.Values{"guardrail": {"provider": "none"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolve(t, test.withF, test.file)
			judge := Fence(resolved, guardrailOf(t, resolved))
			if judge.Fence == nil || len(judge.Ahead) != 1 || len(judge.Behind) != 1 {
				t.Fatalf("judge block = fence %v, ahead %d, behind %d", judge.Fence != nil, len(judge.Ahead), len(judge.Behind))
			}
			if judge.Fence != judge.Ahead[0] {
				t.Fatalf("the entry loading ahead of the guardrail is not the fence the proxy judges with")
			}
			if judge.NeedsJEV() != test.wantJEV {
				t.Fatalf("NeedsJEV = %v, want %v", judge.NeedsJEV(), test.wantJEV)
			}
			proxy := judge.Proxy(proxyext.Config{WorkDir: t.TempDir()}, "")
			if proxy == nil {
				t.Fatal("Proxy returned no extension")
			}
		})
	}
}

// Judge.Proxy dresses the proxy with the fence extension's own session-route
// table: the lookup it installs reads the store the fence loaded and
// provided, so a route the fence registered for a live session serves that
// session's calls, and a cleared route falls back to the node default — the
// package-global registry is gone (4zdesign/19 E4 round 2).
func TestJudgeProxySessionRoutesShareTheFenceTable(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	judge := Policy(fenceconfig.Config{}, guardrailext.Rules{})
	var endpoint egress.Endpoint
	var routes *egressroutes.Store
	entries := append([]extension.Extension{
		extension.Provided[*hooks.Registry](hooks.New()),
		extension.Provided[*events.Stream](events.New()),
		namespaces.New(),
		coretool.NewCommandRegistry(),
	}, judge.Ahead...)
	// The composition order profile.go uses: judge.Proxy reads the fence's
	// seam before any Load, so the lookup must resolve its table lazily.
	entries = append(entries,
		judge.Proxy(proxyext.Config{WorkDir: t.TempDir()}, ""),
		extension.Func{LoadFunc: func(scope *extension.Scope) error {
			value, err := extension.Use[egress.Endpoint](scope)
			if err != nil {
				return err
			}
			endpoint = value
			store, err := extension.Use[*egressroutes.Store](scope)
			if err != nil {
				return err
			}
			routes = store
			return nil
		}},
	)
	set, err := extension.New(entries...)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close(context.Background()) })
	if routes == nil || endpoint == nil {
		t.Fatal("the fence store or the proxy endpoint was not provided")
	}

	throughHub := func(sessionID, callID string) {
		t.Helper()
		ctx := operation.ContextWithInvocation(context.Background(), operation.Invocation{SessionID: sessionID, CallID: callID})
		proxyURL, _, release := endpoint.Egress(ctx)
		defer release()
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			t.Fatalf("parse proxy url: %v", err)
		}
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true}, Timeout: 5 * time.Second}
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("request through hub: %v", err)
		}
		resp.Body.Close()
	}

	var hits atomic.Int32
	routes.Set("sess-judge", func(ctx context.Context, network, address string) (net.Conn, error) {
		hits.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	throughHub("sess-judge", "tool-1")
	if hits.Load() != 1 {
		t.Fatalf("session route used %d times, want 1", hits.Load())
	}

	// Clearing the fence's own entry sends the session back to the default.
	routes.Clear("sess-judge")
	throughHub("sess-judge", "tool-2")
	if hits.Load() != 1 {
		t.Fatalf("cleared session still routed: %d hits", hits.Load())
	}
}
