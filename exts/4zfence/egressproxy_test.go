package fence

import (
	"context"
	"errors"
	"net"
	"testing"

	agenthooks "github.com/chainreactors/cyber/agent/hooks"
	aop "github.com/chainreactors/cyber/aop"
	"google.golang.org/protobuf/types/known/anypb"
)

func egressExtension(namespace string, body string) *anypb.Any {
	return &anypb.Any{TypeUrl: "type.googleapis.com/" + namespace + ".EgressProxy", Value: []byte(body)}
}

func egressTurnRequest(sessionID, namespace, body string) *aop.RunTurnRequest {
	return &aop.RunTurnRequest{
		SessionId:  sessionID,
		Extensions: []*anypb.Any{egressExtension(namespace, body)},
	}
}

// turnEgressProxy never touches the store when the turn carries no extension:
// a control plane without the feature leaves every session on the node
// default (the zero-value behavior).
func TestTurnEgressProxyAbsentKeepsDefault(t *testing.T) {
	installStores(t)
	testFence.turnEgressProxy(&aop.RunTurnRequest{SessionId: "sess-epx1"})
	testFence.turnEgressProxy(nil)
	if got := testFence.routes.Lookup("sess-epx1"); got != nil {
		t.Fatal("extension-less turn changed the session route")
	}
}

// A valid endpoint binds the session; the control plane re-sends every turn,
// and a later disabled draft unbinds the same session.
func TestTurnEgressProxyBindAndDisable(t *testing.T) {
	installStores(t)
	testFence.turnEgressProxy(egressTurnRequest("sess-epx2", "4zrcin",
		`{"enabled":true,"scheme":"socks5","host":"10.0.0.9","port":1080,"username":"ops","password":"secret","url":"socks5://ops:secret@10.0.0.9:1080"}`))
	if got := testFence.routes.Lookup("sess-epx2"); got == nil {
		t.Fatal("enabled endpoint did not bind the session")
	}

	testFence.turnEgressProxy(egressTurnRequest("sess-epx2", "4zrcin",
		`{"enabled":false,"scheme":"socks5","host":"10.0.0.9","port":1080,"url":"socks5://10.0.0.9:1080"}`))
	if got := testFence.routes.Lookup("sess-epx2"); got != nil {
		t.Fatal("disabled draft left the session bound")
	}
}

// Both fork namespaces are accepted for the same payload (the tianwu → 4zrcin
// rename keeps pre-rename control planes working, same as scope rules).
func TestTurnEgressProxyAcceptsBothNamespaces(t *testing.T) {
	installStores(t)
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		testFence.routes.ClearAll()
		testFence.turnEgressProxy(egressTurnRequest("sess-epx3", namespace,
			`{"enabled":true,"scheme":"http","host":"proxy.test","port":3128,"url":"http://proxy.test:3128"}`))
		if got := testFence.routes.Lookup("sess-epx3"); got == nil {
			t.Fatalf("namespace %s: endpoint did not bind", namespace)
		}
	}
}

// Garbage never routes: unparsable JSON and an undialable URL are logged and
// cleared, leaving the session on the node default rather than on garbage.
func TestTurnEgressProxyInvalidClears(t *testing.T) {
	installStores(t)
	testFence.turnEgressProxy(egressTurnRequest("sess-epx4", "4zrcin", `{"enabled":true,`))
	if got := testFence.routes.Lookup("sess-epx4"); got != nil {
		t.Fatal("unparsable payload left a route")
	}

	testFence.turnEgressProxy(egressTurnRequest("sess-epx4", "4zrcin",
		`{"enabled":true,"scheme":"unknown-scheme","host":"x.test","url":"unknown-scheme://x.test"}`))
	if got := testFence.routes.Lookup("sess-epx4"); got != nil {
		t.Fatal("undialable url left a route")
	}
}

// A turn that carries the extension while the fence holds no store is
// refused, not silently dropped: a registration that went nowhere would run
// the session on the node default chain as if no proxy existed — the same
// ErrNotLoaded contract as the rule tables.
func TestTurnEgressProxyWithoutStoreRefuses(t *testing.T) {
	var unloaded *Extension
	err := unloaded.turnEgressProxy(egressTurnRequest("sess-epx-nostore", "4zrcin",
		`{"enabled":true,"scheme":"http","host":"proxy.test","port":3128,"url":"http://proxy.test:3128"}`))
	if !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("store-less registration err = %v, want ErrNotLoaded", err)
	}
	// An extension-less turn stays a no-op without a store, not an error.
	if err := unloaded.turnEgressProxy(&aop.RunTurnRequest{SessionId: "sess-epx-nostore"}); err != nil {
		t.Fatalf("extension-less turn without a store errored: %v", err)
	}
}

// Session close unbinds the route, so a later session reusing the id cannot
// inherit a route nobody re-sent. The drop runs in the fence extension's
// SessionEnd hook; the runtime emits it from CloseSession, so the binding is
// torn down regardless of the close outcome. A rotation close clears the
// route too — routes ride every turn, so the continuation re-binds from its
// own payload instead of inheriting (unlike the rule tables, which park).
func TestSessionDropUnbindsRoute(t *testing.T) {
	installStores(t)
	testFence.routes.Set("sess-epx-close", func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, context.Canceled
	})
	if _, err := testFence.dropOnClose(t.Context(), agenthooks.SessionEvent{SessionID: "sess-epx-close"}); err != nil {
		t.Fatal(err)
	}
	if got := testFence.routes.Lookup("sess-epx-close"); got != nil {
		t.Fatal("closed session kept its proxy binding")
	}
}
