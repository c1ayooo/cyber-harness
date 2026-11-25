package session

import (
	"context"
	"net"
	"testing"

	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/egress"
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

// turnEgressProxy never touches the registry when the turn carries no
// extension: a control plane without the feature leaves every session on the
// node default (the zero-value behavior).
func TestTurnEgressProxyAbsentKeepsDefault(t *testing.T) {
	egress.ClearSessionRoute("sess-epx1")
	turnEgressProxy(&aop.RunTurnRequest{SessionId: "sess-epx1"})
	turnEgressProxy(nil)
	if got := egress.LookupSessionRoute("sess-epx1"); got != nil {
		t.Fatal("extension-less turn changed the session route")
	}
}

// A valid endpoint binds the session; the control plane re-sends every turn,
// and a later disabled draft unbinds the same session.
func TestTurnEgressProxyBindAndDisable(t *testing.T) {
	egress.ClearSessionRoute("sess-epx2")
	turnEgressProxy(egressTurnRequest("sess-epx2", "4zrcin",
		`{"enabled":true,"scheme":"socks5","host":"10.0.0.9","port":1080,"username":"ops","password":"secret","url":"socks5://ops:secret@10.0.0.9:1080"}`))
	if got := egress.LookupSessionRoute("sess-epx2"); got == nil {
		t.Fatal("enabled endpoint did not bind the session")
	}

	turnEgressProxy(egressTurnRequest("sess-epx2", "4zrcin",
		`{"enabled":false,"scheme":"socks5","host":"10.0.0.9","port":1080,"url":"socks5://10.0.0.9:1080"}`))
	if got := egress.LookupSessionRoute("sess-epx2"); got != nil {
		t.Fatal("disabled draft left the session bound")
	}
}

// Both fork namespaces are accepted for the same payload (the tianwu → 4zrcin
// rename keeps pre-rename control planes working, same as scope rules).
func TestTurnEgressProxyAcceptsBothNamespaces(t *testing.T) {
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		egress.ClearSessionRoute("sess-epx3")
		turnEgressProxy(egressTurnRequest("sess-epx3", namespace,
			`{"enabled":true,"scheme":"http","host":"proxy.test","port":3128,"url":"http://proxy.test:3128"}`))
		if got := egress.LookupSessionRoute("sess-epx3"); got == nil {
			t.Fatalf("namespace %s: endpoint did not bind", namespace)
		}
	}
}

// Garbage never routes: unparsable JSON and an undialable URL are logged and
// cleared, leaving the session on the node default rather than on garbage.
func TestTurnEgressProxyInvalidClears(t *testing.T) {
	egress.ClearSessionRoute("sess-epx4")
	turnEgressProxy(egressTurnRequest("sess-epx4", "4zrcin", `{"enabled":true,`))
	if got := egress.LookupSessionRoute("sess-epx4"); got != nil {
		t.Fatal("unparsable payload left a route")
	}

	turnEgressProxy(egressTurnRequest("sess-epx4", "4zrcin",
		`{"enabled":true,"scheme":"unknown-scheme","host":"x.test","url":"unknown-scheme://x.test"}`))
	if got := egress.LookupSessionRoute("sess-epx4"); got != nil {
		t.Fatal("undialable url left a route")
	}
}

// Session close unbinds the route, so a later session reusing the id cannot
// inherit a route nobody re-sent. The runtime rejection path (unknown session)
// still clears: the binding is torn down regardless of the close outcome.
func TestCloseAOPSessionUnbindsRoute(t *testing.T) {
	rt := newBareRuntime(t, nil, nil)
	egress.SetSessionRoute("sess-epx-close", func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, context.Canceled
	})
	rt.CloseAOPSession(t.Context(), &aop.CloseSessionRequest{SessionId: "sess-epx-close"})
	if got := egress.LookupSessionRoute("sess-epx-close"); got != nil {
		t.Fatal("closed session kept its proxy binding")
	}
}
