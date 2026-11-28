package fence

// The fence reads a command out of a tool call's arguments under the same
// rules encoding/json uses to fill the tool's own string field: key names
// match case-insensitively and a key repeated later overrides the earlier
// value. The bash tool decodes arguments through encoding/json
// (BashArgs.UnmarshalJSON), so a case-folded command key bash would execute
// must be judged — the old exact-key lookup let {"Command":"rm -rf /"} skip
// every instance red line and the guaranteed audit alike. The last test here
// pins the fence to the tool's decode one payload at a time, so the two
// rules cannot drift apart again.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/chainreactors/cyber/aop"
	operationpb "github.com/chainreactors/cyber/aop/operation"
	"github.com/chainreactors/cyber/core/operation"
	toolhooks "github.com/chainreactors/cyber/core/tool/hooks"
	"github.com/chainreactors/cyber/tools/terminal"
)

func commandCall(payload string) *aop.ToolCall {
	return &aop.ToolCall{Name: "bash", Arguments: &aop.EncodedValue{Data: []byte(payload)}}
}

// The integrator's measured table: bash decodes every case-folded spelling of
// "command", but a key carrying extra characters (a trailing space) does not
// match, and a non-string value fails the tool's decode so it never executes.
func TestCommandFieldMatchesCaseVariants(t *testing.T) {
	cases := []struct {
		payload string
		like    bool
		text    string
	}{
		{`{"command":"rm -rf /"}`, true, "rm -rf /"},
		{`{"Command":"rm -rf /"}`, true, "rm -rf /"},
		{`{"COMMAND":"rm -rf /"}`, true, "rm -rf /"},
		{`{"cOmMaNd":"rm -rf /"}`, true, "rm -rf /"},
		// A key with a trailing space matches nothing; the audit text falls
		// back to the raw arguments so its anchored patterns can still run.
		{`{"Command ":"x"}`, false, `{"Command ":"x"}`},
		// A non-string value fails BashArgs's decode; the call is not judged.
		{`{"command":["rm","-rf","/"]}`, false, `{"command":["rm","-rf","/"]}`},
	}
	for _, test := range cases {
		if like := commandLikeCall(commandCall(test.payload)); like != test.like {
			t.Errorf("%s: commandLikeCall = %v, want %v", test.payload, like, test.like)
		}
		if text := commandText(commandCall(test.payload)); text != test.text {
			t.Errorf("%s: commandText = %q, want %q", test.payload, text, test.text)
		}
	}
}

// encoding/json assigns repeated keys to the same field in document order, so
// the later value wins regardless of spelling — not the exactly-spelled one.
func TestCommandFieldLaterKeyOverrides(t *testing.T) {
	cases := []struct {
		payload string
		text    string
	}{
		{`{"command":"echo hi","Command":"rm -rf /"}`, "rm -rf /"},
		{`{"Command":"rm -rf /","command":"echo hi"}`, "echo hi"},
	}
	for _, test := range cases {
		if like := commandLikeCall(commandCall(test.payload)); !like {
			t.Errorf("%s: commandLikeCall = false, want true", test.payload)
		}
		if text := commandText(commandCall(test.payload)); text != test.text {
			t.Errorf("%s: commandText = %q, want %q", test.payload, text, test.text)
		}
	}
}

// The command-key priority order (command, cmd, script, input, code) is
// independent of the spelling a payload uses for those keys.
func TestCommandFieldPriorityOrder(t *testing.T) {
	cases := []struct {
		payload string
		text    string
	}{
		{`{"script":"a","command":"b"}`, "b"},
		{`{"Script":"a","COMMAND":"b"}`, "b"},
		{`{"code":"c","cmd":"d"}`, "d"},
	}
	for _, test := range cases {
		if text := commandText(commandCall(test.payload)); text != test.text {
			t.Errorf("%s: commandText = %q, want %q", test.payload, text, test.text)
		}
	}
}

// The instance fence judges a folded command key: today {"Command":"rm -rf /"}
// executes while commandLikeCall calls it "not a command" and skips the red
// lines entirely.
func TestInstanceFenceDeniesFoldedCommandKey(t *testing.T) {
	e, _, _ := redlineFixture(t)
	if err := testFence.globals.SetRules("sess-fold", []byte(`{
		"enabled_commands": true,
		"commands": [{"id": "gf-fold", "pattern": "^rm\\s+-rf\\b", "desc": "递归强制删除", "action": "deny"}]
	}`)); err != nil {
		t.Fatal(err)
	}
	invocation := operation.Invocation{SessionID: "sess-fold", TurnID: "turn-1"}
	ctx := operation.ContextWithInvocation(context.Background(), invocation)

	denied, _ := e.admit(ctx, toolhooks.CallEvent{
		Call:      commandCall(`{"Command":"rm -rf /"}`),
		Operation: &operationpb.Ref{OperationId: "op-gf-fold"},
	})
	if denied.Deny == nil {
		t.Fatal(`{"Command":"rm -rf /"} passed the instance fence`)
	}
}

// The guaranteed audit sees a folded command key: BuiltinCommandReason reads
// the same command text the fence judges, so the row keeps its "builtin."
// source badge instead of falling back to unmatchable raw JSON.
func TestBuiltinAuditSeesFoldedCommandKey(t *testing.T) {
	if got := BuiltinCommandReason(commandCall(`{"Command":"rm -rf /"}`)); !strings.HasPrefix(got, "builtin.recursive-force-delete") {
		t.Fatalf(`{"Command":"rm -rf /"}: builtin reason = %q, want prefix "builtin.recursive-force-delete"`, got)
	}
}

// The gate against future drift: for every payload, the fence's command text
// must be exactly what encoding/json hands the bash tool when the tool would
// execute it. Whenever BashArgs decodes to a non-blank Command, the fence must
// judge the same text as a command; payloads whose decode fails or stays blank
// are the tool's business and carry no fence assertion.
func TestCommandFieldTracksBashDecode(t *testing.T) {
	payloads := []string{
		`{"command":"rm -rf /"}`,                       // exact lowercase
		`{"Command":"rm -rf /"}`,                       // folded
		`{"COMMAND":"rm -rf /"}`,                       // folded
		`{"cOmMaNd":"rm -rf /"}`,                       // folded
		`{"command":"echo hi","Command":"rm -rf /"}`,   // override, folded last
		`{"Command":"rm -rf /","command":"echo hi"}`,   // override, exact last
		`{"Command":"ls -la","wait":30,"timeout":600}`, // sibling fields
		`{"command":"   "}`,                            // blank: the tool sees no command
		`{"command":["rm","-rf","/"]}`,                 // array: the decode fails
		`{"Command":`,                                  // invalid JSON: the decode fails
		`"ls -la"`,                                     // bare string: the decode fails, the fence still judges
		`{"wait":1,"timeout":2}`,                       // no command key at all
	}
	for _, payload := range payloads {
		var args terminal.BashArgs
		if err := json.Unmarshal([]byte(payload), &args); err != nil {
			continue // the tool refuses this payload outright; nothing to align
		}
		if strings.TrimSpace(args.Command) == "" {
			continue // nothing the tool would execute; nothing to align
		}
		call := commandCall(payload)
		if got := commandText(call); got != args.Command {
			t.Errorf("%s: commandText = %q, bash decodes %q", payload, got, args.Command)
		}
		if !commandLikeCall(call) {
			t.Errorf("%s: bash executes %q but the fence does not judge a command", payload, args.Command)
		}
	}
}

// foldedCommandKey spells "command" with every letter independently folded,
// now and then as the escaped spelling of the same key or as a near-miss
// (a trailing or leading space, a different word) that must not match.
func foldedCommandKey(rng *rand.Rand) string {
	switch rng.Intn(12) {
	case 0:
		return `"co\u006dmand"`
	case 1:
		return `"command "`
	case 2:
		return `" command"`
	case 3:
		return `"commmand"`
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range "command" {
		if rng.Intn(2) == 0 {
			c = 'C' - 'c' + c
		}
		b.WriteRune(c)
	}
	b.WriteByte('"')
	return b.String()
}

// commandValue is mostly a command text (plain, padded, quoted, non-ASCII) and
// now and then a value the tool's own decode refuses.
func commandValue(rng *rand.Rand) string {
	switch rng.Intn(14) {
	case 0:
		return `"   "`
	case 1:
		return "123"
	case 2:
		return `["rm","-rf","/"]`
	case 3:
		return `{"nested":"x"}`
	case 4:
		return "null"
	case 5:
		return "true"
	}
	texts := []string{"rm -rf /", "echo hi", "  ls -la  ", "curl http://127.0.0.1/", "echo \"quoted\"", "echo \\n newline", "echo \u4e2d\u6587", "\tleading tab"}
	raw, _ := json.Marshal(texts[rng.Intn(len(texts))])
	return string(raw)
}

// The hand-written payload table above covers the shapes that were thought of.
// This one covers the shapes that were not: twenty-odd thousand generated
// argument objects — keys folded at random, repeated in random order, mixed
// with sibling fields, refusal values and near-miss keys — each decoded by the
// bash tool's own type. The seed is fixed, so a failure reproduces. On the
// exact-key lookup this fails on its first executable payload.
func TestCommandFieldRandomPayloadsTrackBashDecode(t *testing.T) {
	rng := rand.New(rand.NewSource(20261128))
	compared := 0
	for i := 0; i < 60000; i++ {
		var parts []string
		for k := rng.Intn(5) + 1; k > 0; k-- {
			switch rng.Intn(5) {
			case 1:
				parts = append(parts, fmt.Sprintf(`"wait":%d`, rng.Intn(60)))
			case 2:
				parts = append(parts, fmt.Sprintf(`"timeout":%d`, rng.Intn(600)))
			case 3:
				parts = append(parts, `"note":"just text"`)
			default:
				parts = append(parts, foldedCommandKey(rng)+":"+commandValue(rng))
			}
		}
		payload := "{" + strings.Join(parts, ",") + "}"
		var args terminal.BashArgs
		if err := json.Unmarshal([]byte(payload), &args); err != nil || strings.TrimSpace(args.Command) == "" {
			continue // the tool refuses this payload, or has no command to run
		}
		compared++
		call := commandCall(payload)
		if got := commandText(call); got != args.Command {
			t.Fatalf("payload %s: the fence reads %q, bash executes %q", payload, got, args.Command)
		}
		if !commandLikeCall(call) {
			t.Fatalf("payload %s: bash executes %q but the fence judges no command", payload, args.Command)
		}
	}
	if compared < 15000 {
		t.Fatalf("only %d generated payloads were executable; the generator got too narrow", compared)
	}
	t.Logf("compared %d executable payloads", compared)
}
