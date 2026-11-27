package fence

import (
	"testing"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/chainreactors/cyber/exts/4zfence/globalfence"
	"google.golang.org/protobuf/types/known/anypb"
)

// The instance fence registers for the session the turn belongs to, in both
// extension namespaces (spec #1 工单3); an invalid payload is ignored without
// opening a hole in the previous set.
func TestTurnGlobalFenceRegistration(t *testing.T) {
	installStores(t)
	valid := `{"enabled_commands":true,"commands":[{"id":"gf-1","pattern":"rm -rf /","action":"deny"}],"enabled_domains":true,"domains":[{"id":"gf-10","host":"gov.cn"}]}`
	for _, namespace := range []string{"tianwu", "4zrcin"} {
		req := &aop.RunTurnRequest{SessionId: "sess-gf", Extensions: []*anypb.Any{{
			TypeUrl: "type.googleapis.com/" + namespace + ".GlobalFence", Value: []byte(valid),
		}}}
		turnGlobalFence(req)
		if _, hit := globalfence.JudgeCommand("sess-gf", "rm -rf /"); !hit {
			t.Fatalf("namespace %s: command fence not registered", namespace)
		}
		if _, hit := globalfence.DomainHit("sess-gf", "www.gov.cn"); !hit {
			t.Fatalf("namespace %s: domain fence not registered", namespace)
		}
	}
	invalid := `{"enabled_commands":true,"commands":[{"id":"x","pattern":"(","action":"deny"}]}`
	turnGlobalFence(&aop.RunTurnRequest{SessionId: "sess-gf", Extensions: []*anypb.Any{{
		TypeUrl: "type.googleapis.com/4zrcin.GlobalFence", Value: []byte(invalid),
	}}})
	if _, hit := globalfence.JudgeCommand("sess-gf", "rm -rf /"); !hit {
		t.Fatal("invalid payload wiped the previous fence")
	}
}
