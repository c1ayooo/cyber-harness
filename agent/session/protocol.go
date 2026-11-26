package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	aop "github.com/c1ayooo/cyber/aop"
	"github.com/c1ayooo/cyber/core/egress"
	"github.com/c1ayooo/cyber/core/globalfence"
	"github.com/c1ayooo/cyber/core/scoperules"
	types "github.com/c1ayooo/cyber/core/types"
	"github.com/chainreactors/proxyclient"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// workDirExtensionURL is the Tianwu fork's per-session workspace extension on
// OpenSessionRequest. The AOP schema has no session work dir (a session runs in
// the agent process directory), so a control plane that owns a per-run case
// directory sends it here instead of editing the shared schema. The value is
// JSON: {"work_dir":"<absolute path>","single_task":true}. The optional
// scheduling flag uses the runtime's existing SingleTask mailbox policy.
//
// Patch 20 (2026-11-25): the control plane renamed its fork namespace from
// tianwu.* to 4zrcin.*, so every extension it sends now carries the new type
// URL while this file still matched only the old one — the host silently
// ignored WorkDir/ToolEnv/RunGoal again. Both spellings are accepted for the
// same payload; the old URL keeps pre-rename control planes working.
const workDirExtensionURL = "type.googleapis.com/tianwu.WorkDir"

// forkWorkDirExtensionURLs lists every type URL the WorkDir payload has been
// published under, oldest first.
var forkWorkDirExtensionURLs = []string{
	"type.googleapis.com/tianwu.WorkDir",
	"type.googleapis.com/4zrcin.WorkDir",
}

// extensionWithURL returns the first extension whose type URL matches one of
// the given fork URLs. Fork payloads have carried two namespaces across the
// tianwu → 4zrcin rename; matching by list keeps both generations working.
func extensionWithURL(extensions []*anypb.Any, urls []string) *anypb.Any {
	for _, extension := range extensions {
		if extension == nil {
			continue
		}
		for _, url := range urls {
			if extension.GetTypeUrl() == url {
				return extension
			}
		}
	}
	return nil
}

type workDirExtension struct {
	WorkDir    string `json:"work_dir"`
	SingleTask bool   `json:"single_task,omitempty"`
}

// sessionWorkDir returns the workspace a control plane attached to this open
// request. Empty means "use the agent's own working directory", which keeps old
// control planes working.
func sessionWorkspace(req *aop.OpenSessionRequest) workDirExtension {
	if req == nil {
		return workDirExtension{}
	}
	if extension := extensionWithURL(req.GetExtensions(), forkWorkDirExtensionURLs); extension != nil {
		var value workDirExtension
		if err := json.Unmarshal(extension.GetValue(), &value); err != nil {
			return workDirExtension{}
		}
		value.WorkDir = strings.TrimSpace(value.WorkDir)
		if value.WorkDir != "" || value.SingleTask {
			return value
		}
	}
	return workDirExtension{}
}

// runGoalExtensionURLs lists every type URL the RunGoal payload has been
// published under (see the WorkDir namespace note above).
var runGoalExtensionURLs = []string{
	"type.googleapis.com/tianwu.RunGoal",
	"type.googleapis.com/4zrcin.RunGoal",
}

type runGoalExtension struct {
	Goal string `json:"goal"`
	// EvalRounds is kept raw so a producer that models the round budget as a
	// JSON number still delivers the goal instead of failing the whole value.
	EvalRounds json.RawMessage `json:"eval_rounds"`
}

// evalRoundsText normalizes the optional pacing spec: a string is taken as-is,
// a number is its decimal form, and null/invalid is empty.
func evalRoundsText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String()
	}
	return ""
}

// turnRunGoal returns the goal a control plane attached to this run request.
// Empty means "derive the goal from the input message", which keeps old control
// planes working.
func turnRunGoal(req *aop.RunTurnRequest) (goal, rounds string) {
	if req == nil {
		return "", ""
	}
	if extension := extensionWithURL(req.GetExtensions(), runGoalExtensionURLs); extension != nil {
		var value runGoalExtension
		if err := json.Unmarshal(extension.GetValue(), &value); err == nil {
			goal, rounds = strings.TrimSpace(value.Goal), evalRoundsText(value.EvalRounds)
			if goal != "" || rounds != "" {
				return goal, rounds
			}
		}
	}
	return "", ""
}

// turnWorkDir returns the workspace a control plane attached to this turn. It
// rides the same WorkDir extension the session opening carries: a resumed turn
// never re-opens its session, so a session the host re-created after a restart
// would otherwise keep the agent's process directory as its workspace.
func turnWorkDir(req *aop.RunTurnRequest) string {
	if req == nil {
		return ""
	}
	if extension := extensionWithURL(req.GetExtensions(), forkWorkDirExtensionURLs); extension != nil {
		var value workDirExtension
		if err := json.Unmarshal(extension.GetValue(), &value); err == nil {
			return strings.TrimSpace(value.WorkDir)
		}
	}
	return ""
}

// caseSeedExtensionURLs lists every type URL the CaseSeed payload has been
// published under (same fork namespace generations as WorkDir). The payload is
// {"files":[{"path":".zrcin/context.json","mode":420,"data":"<base64>"}]};
// paths are relative to the turn's workspace.
var caseSeedExtensionURLs = []string{
	"type.googleapis.com/tianwu.CaseSeed",
	"type.googleapis.com/4zrcin.CaseSeed",
}

// CaseSeedFile is one file of a turn seed (fork patch 26).
type CaseSeedFile struct {
	Path string
	Mode uint32
	Data []byte
}

type caseSeedExtension struct {
	Files []struct {
		Path string `json:"path"`
		Mode uint32 `json:"mode"`
		Data string `json:"data"`
	} `json:"files"`
}

// turnCaseSeed decodes the files a control plane sends with this turn. A
// malformed payload is an error: a control plane that believes it delivered
// the inputs must learn that it did not, instead of the model reading stale
// or missing context.
func turnCaseSeed(req *aop.RunTurnRequest) ([]CaseSeedFile, error) {
	if req == nil {
		return nil, nil
	}
	extension := extensionWithURL(req.GetExtensions(), caseSeedExtensionURLs)
	if extension == nil {
		return nil, nil
	}
	var value caseSeedExtension
	if err := json.Unmarshal(extension.GetValue(), &value); err != nil {
		return nil, fmt.Errorf("case seed payload: %w", err)
	}
	files := make([]CaseSeedFile, 0, len(value.Files))
	for i, file := range value.Files {
		data, err := base64.StdEncoding.DecodeString(file.Data)
		if err != nil {
			return nil, fmt.Errorf("case seed file %d data: %w", i, err)
		}
		files = append(files, CaseSeedFile{Path: file.Path, Mode: file.Mode, Data: data})
	}
	return files, nil
}

// toolEnvExtensionURLs lists every type URL the ToolEnv payload has been
// published under (see the WorkDir namespace note above).
var toolEnvExtensionURLs = []string{
	"type.googleapis.com/tianwu.ToolEnv",
	"type.googleapis.com/4zrcin.ToolEnv",
}

// scopeRulesExtensionURLs is the control plane's per-turn test-range rule set
// (manifest scope_rules JSON). The proxy's scope judge reads what this
// registers; a set that fails to parse is logged and ignored — the request
// pipeline stays record-only rather than judging on garbage.
var scopeRulesExtensionURLs = []string{
	"type.googleapis.com/tianwu.ScopeRules",
	"type.googleapis.com/4zrcin.ScopeRules",
}

// turnScopeRules registers the test-range rule set a control plane attached to
// this turn. The set rides every turn (disabled drafts included) so the proxy
// judges each request against what the project manifest held when the run
// dispatched — never a stale push-once copy.
func turnScopeRules(req *aop.RunTurnRequest) {
	if req == nil {
		return
	}
	extension := extensionWithURL(req.GetExtensions(), scopeRulesExtensionURLs)
	if extension == nil {
		return
	}
	if err := scoperules.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
		log.Printf("aop: ignore invalid scope rules for session %s: %v", req.GetSessionId(), err)
	}
}

// globalFenceExtensionURLs is the control plane's instance-wide red lines
// (spec #1 工单3): command patterns that never execute and domains that are
// never reached, on every project the instance drives — judged before the
// project fence, so a project allowlisting a denied domain still cannot reach
// it. Same per-turn carriage and both-namespace recognition as ScopeRules.
var globalFenceExtensionURLs = []string{
	"type.googleapis.com/tianwu.GlobalFence",
	"type.googleapis.com/4zrcin.GlobalFence",
}

// turnGlobalFence registers the instance fence for this turn's session. An
// invalid payload is logged and ignored; the previous set stays in force
// rather than opening a hole on one malformed send.
func turnGlobalFence(req *aop.RunTurnRequest) {
	if req == nil {
		return
	}
	extension := extensionWithURL(req.GetExtensions(), globalFenceExtensionURLs)
	if extension == nil {
		return
	}
	if err := globalfence.SetRules(req.GetSessionId(), extension.GetValue()); err != nil {
		log.Printf("aop: ignore invalid global fence for session %s: %v", req.GetSessionId(), err)
	}
}

// egressProxyExtensionURLs is the control plane's per-turn egress proxy (the
// project manifest "proxy" JSON: enabled/scheme/host/port/username/password
// plus the normalized dial url). The proxy hub reads what this registers; an
// unparsable endpoint is logged and cleared — the session falls back to the
// node default chain rather than routing on garbage.
var egressProxyExtensionURLs = []string{
	"type.googleapis.com/tianwu.EgressProxy",
	"type.googleapis.com/4zrcin.EgressProxy",
}

// egressProxyPayload mirrors the manifest's "proxy" shape. url is the control
// plane's normalized dial URL (computed at every save, so it is authoritative);
// the field derivation below only serves control planes older than the url
// field, and the default-port table matches internal/project's DialURL.
type egressProxyPayload struct {
	Enabled  bool   `json:"enabled"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
}

// turnEgressProxy binds this turn's session to the project proxy a control
// plane attached. The binding rides every turn — a disabled draft included —
// so a session that outlives the save learns the endpoint was switched off
// and falls back to the node default. Registration lives in core/egress (same
// pattern as scoperules): the session layer writes, the proxy hub reads, and
// neither imports the other.
//
// NewClient needs the extra protocol factories (trojan/vmess/hysteria2/anytls/
// clash) registered; those blank imports live in tools/proxy, which every
// agent binary links, so the factories are in the registry by the time a turn
// with such an endpoint arrives.
func turnEgressProxy(req *aop.RunTurnRequest) {
	if req == nil {
		return
	}
	extension := extensionWithURL(req.GetExtensions(), egressProxyExtensionURLs)
	if extension == nil {
		return
	}
	sessionID := req.GetSessionId()
	var payload egressProxyPayload
	if err := json.Unmarshal(extension.GetValue(), &payload); err != nil {
		log.Printf("aop: ignore invalid egress proxy for session %s: %v", sessionID, err)
		egress.ClearSessionRoute(sessionID)
		return
	}
	// Disabled is a stored state the operator kept, not a deletion: clearing
	// the route is exactly how "off" reaches a session that is already live.
	if !payload.Enabled {
		egress.ClearSessionRoute(sessionID)
		return
	}
	raw := payload.URL
	if raw == "" {
		// Legacy control planes without the url field: derive from the fields.
		host := payload.Host
		if payload.Port > 0 {
			host = fmt.Sprintf("%s:%d", host, payload.Port)
		}
		u := &url.URL{Scheme: payload.Scheme, Host: host}
		if payload.Username != "" {
			if payload.Password != "" {
				u.User = url.UserPassword(payload.Username, payload.Password)
			} else {
				u.User = url.User(payload.Username)
			}
		}
		raw = u.String()
	}
	endpoint, err := url.Parse(raw)
	if err != nil {
		log.Printf("aop: ignore invalid egress proxy url for session %s: %v", sessionID, err)
		egress.ClearSessionRoute(sessionID)
		return
	}
	dial, err := proxyclient.NewClient(endpoint)
	if err != nil {
		log.Printf("aop: ignore undialable egress proxy for session %s: %v", sessionID, err)
		egress.ClearSessionRoute(sessionID)
		return
	}
	egress.SetSessionRoute(sessionID, egress.Dial(dial))
}

type toolEnvExtension struct {
	Env map[string]string `json:"env"`
}

// turnToolEnv returns the per-turn tool environment as KEY=VALUE pairs.
func turnToolEnv(req *aop.RunTurnRequest) []string {
	if req == nil {
		return nil
	}
	if extension := extensionWithURL(req.GetExtensions(), toolEnvExtensionURLs); extension != nil {
		var value toolEnvExtension
		if err := json.Unmarshal(extension.GetValue(), &value); err != nil {
			return nil
		}
		if len(value.Env) == 0 {
			return nil
		}
		env := make([]string, 0, len(value.Env))
		for key, val := range value.Env {
			if key != "" {
				env = append(env, key+"="+val)
			}
		}
		return env
	}
	return nil
}

func (rt *Runtime) OpenAOPSession(req *aop.OpenSessionRequest) *aop.OpenSessionResponse {
	response := &aop.OpenSessionResponse{}
	if rt == nil || req == nil || strings.TrimSpace(req.SessionId) == "" {
		response.Outcome = &aop.OpenSessionResponse_Rejected{Rejected: rejection("INVALID_ARGUMENT", "session_id is required")}
		return response
	}
	workspace := sessionWorkspace(req)
	session, err := rt.EnsureSession(SessionOptions{
		ID: req.SessionId, ParentSessionID: req.ParentSessionId, ParentToolCallID: req.ParentToolCallId,
		WorkDir: workspace.WorkDir, SingleTask: workspace.SingleTask,
	})
	if err != nil {
		response.Outcome = &aop.OpenSessionResponse_Rejected{Rejected: rejection("FAILED_PRECONDITION", err.Error())}
		return response
	}
	response.Outcome = &aop.OpenSessionResponse_Accepted{Accepted: &aop.Session{Id: session.ID(), State: "open", NodeId: req.NodeId, Title: req.Title}}
	return response
}

func (rt *Runtime) RunAOPTurn(ctx context.Context, req *aop.RunTurnRequest) *aop.RunTurnResponse {
	response := &aop.RunTurnResponse{}
	if rt == nil || req == nil || (!req.ContinueSession && req.Input == nil) || strings.TrimSpace(req.SessionId) == "" || strings.TrimSpace(req.TurnId) == "" {
		response.Outcome = &aop.RunTurnResponse_Rejected{Rejected: rejection("INVALID_ARGUMENT", "session_id, turn_id, and input are required unless continue_session is true")}
		return response
	}
	options := new(types.AgentRunOptions)
	for _, extension := range req.Extensions {
		if extension != nil && extension.MessageIs(options) {
			if err := extension.UnmarshalTo(options); err != nil {
				response.Outcome = &aop.RunTurnResponse_Rejected{Rejected: rejection("INVALID_ARGUMENT", "invalid Cyber run options: "+err.Error())}
				return response
			}
			break
		}
	}
	// The test-range rule set registers before the turn starts so the proxy
	// judges this turn's requests against it. The project's egress proxy binds
	// in the same breath: the hub routes this session's outbound calls through
	// the endpoint the manifest held at dispatch time.
	turnScopeRules(req)
	turnGlobalFence(req)
	turnEgressProxy(req)
	var message *aop.Message
	if req.Input != nil {
		message = protobuf.CloneOf(req.Input)
	}
	// A control plane may separate the evaluator's goal from the executor's
	// turn message. Its own extension wins over AgentRunOptions.eval_rounds
	// when both carry a pacing spec.
	evalGoal, evalRounds := turnRunGoal(req)
	if evalRounds == "" {
		evalRounds = options.EvalRounds
	}
	seed, seedErr := turnCaseSeed(req)
	if seedErr != nil {
		response.Outcome = &aop.RunTurnResponse_Rejected{Rejected: rejection("FAILED_PRECONDITION", seedErr.Error())}
		return response
	}
	_, err := rt.RunSession(ctx, req.SessionId, RunInput{
		TurnID: req.TurnId, Message: message, Continue: req.ContinueSession,
		MaxTurns: int(req.MaxTurns), EvalCriteria: options.EvalCriteria, EvalRounds: evalRounds, EvalGoal: evalGoal,
		ToolEnv: turnToolEnv(req), WorkDir: turnWorkDir(req), Seed: seed,
	})
	if err != nil {
		response.Outcome = &aop.RunTurnResponse_Rejected{Rejected: rejection("FAILED_PRECONDITION", err.Error())}
		return response
	}
	response.Outcome = &aop.RunTurnResponse_Accepted{Accepted: &aop.TurnReceipt{SessionId: req.SessionId, TurnId: req.TurnId, State: "running"}}
	return response
}

func (rt *Runtime) CancelAOPTurn(req *aop.CancelTurnRequest) *aop.CancelTurnResponse {
	response := &aop.CancelTurnResponse{}
	if rt == nil || req == nil || strings.TrimSpace(req.SessionId) == "" || strings.TrimSpace(req.TurnId) == "" {
		response.Outcome = &aop.CancelTurnResponse_Rejected{Rejected: rejection("INVALID_ARGUMENT", "session_id and turn_id are required")}
		return response
	}
	if err := rt.CancelSessionRun(req.SessionId, req.TurnId); err != nil {
		response.Outcome = &aop.CancelTurnResponse_Rejected{Rejected: rejection("NOT_FOUND", err.Error())}
		return response
	}
	response.Outcome = &aop.CancelTurnResponse_Accepted{Accepted: &aop.TurnReceipt{SessionId: req.SessionId, TurnId: req.TurnId, State: "canceled"}}
	return response
}

func (rt *Runtime) CloseAOPSession(ctx context.Context, req *aop.CloseSessionRequest) *aop.CloseSessionResponse {
	response := &aop.CloseSessionResponse{}
	if rt == nil || req == nil || strings.TrimSpace(req.SessionId) == "" {
		response.Outcome = &aop.CloseSessionResponse_Rejected{Rejected: rejection("INVALID_ARGUMENT", "session_id is required")}
		return response
	}
	// The session is gone: its project proxy binding must go with it, or a
	// later session reusing the id would inherit a route nobody re-sent.
	egress.ClearSessionRoute(req.SessionId)
	if err := rt.CloseSession(ctx, req.SessionId, SessionCloseReason(req.Reason)); err != nil {
		response.Outcome = &aop.CloseSessionResponse_Rejected{Rejected: rejection("FAILED_PRECONDITION", err.Error())}
		return response
	}
	response.Outcome = &aop.CloseSessionResponse_Accepted{Accepted: &aop.Session{Id: req.SessionId, State: "closed"}}
	return response
}

// NamespaceBindings publishes the protocols implemented by this runtime. The
// profile's typed namespace registry installs them on each connection.
func (rt *Runtime) NamespaceBindings() []aop.Binding {
	if rt == nil {
		return nil
	}
	return []aop.Binding{
		aop.Shared(&aop.ProtocolMessage{}, rt.HandleCoreNamespace),
		aop.Shared(&types.CommandProtocolMessage{}, rt.HandleCommandNamespace),
	}
}

// HandleCoreNamespace implements session control for all existing transports.
func (rt *Runtime) HandleCoreNamespace(ctx context.Context, envelope *aop.Envelope, message protobuf.Message, send aop.SendFunc) error {
	value, ok := message.(*aop.ProtocolMessage)
	if !ok {
		return fmt.Errorf("unexpected core namespace message %T", message)
	}
	reply := func(message protobuf.Message) error { return send(aop.Reply(envelope.Id, message)) }
	switch payload := value.Message.(type) {
	case *aop.ProtocolMessage_OpenSessionRequest:
		return reply(&aop.ProtocolMessage{Message: &aop.ProtocolMessage_OpenSessionResponse{OpenSessionResponse: rt.OpenAOPSession(payload.OpenSessionRequest)}})
	case *aop.ProtocolMessage_RunTurnRequest:
		return reply(&aop.ProtocolMessage{Message: &aop.ProtocolMessage_RunTurnResponse{RunTurnResponse: rt.RunAOPTurn(ctx, payload.RunTurnRequest)}})
	case *aop.ProtocolMessage_CancelTurnRequest:
		return reply(&aop.ProtocolMessage{Message: &aop.ProtocolMessage_CancelTurnResponse{CancelTurnResponse: rt.CancelAOPTurn(payload.CancelTurnRequest)}})
	case *aop.ProtocolMessage_CloseSessionRequest:
		return reply(&aop.ProtocolMessage{Message: &aop.ProtocolMessage_CloseSessionResponse{CloseSessionResponse: rt.CloseAOPSession(ctx, payload.CloseSessionRequest)}})
	default:
		return fmt.Errorf("unsupported AOP core message")
	}
}

// HandleCommandNamespace implements the existing command namespace.
func (rt *Runtime) HandleCommandNamespace(ctx context.Context, envelope *aop.Envelope, message protobuf.Message, send aop.SendFunc) error {
	value, ok := message.(*types.CommandProtocolMessage)
	if !ok {
		return fmt.Errorf("unexpected command namespace message %T", message)
	}
	reply := func(message protobuf.Message) error { return send(aop.Reply(envelope.Id, message)) }
	request := value.GetRequest()
	if request == nil || strings.TrimSpace(request.Line) == "" {
		return reply(aop.NewProtocolError("INVALID_ARGUMENT", "command line is required"))
	}
	if err := rt.ready(); err != nil {
		return reply(aop.NewProtocolError("COMMAND_FAILED", err.Error()))
	}
	// Close cancels the context before taking mu and waiting for operations.
	// Admission must use the same gate so Add cannot race with an empty Wait.
	rt.mu.Lock()
	if err := rt.ctx.Err(); err != nil {
		rt.mu.Unlock()
		return reply(aop.NewProtocolError("COMMAND_FAILED", err.Error()))
	}
	rt.operations.Add(1)
	rt.mu.Unlock()
	go func() {
		defer rt.operations.Done()
		result, err := rt.CommandSession(ctx, request.SessionId, request.Line)
		if err != nil {
			_ = reply(aop.NewProtocolError("COMMAND_FAILED", err.Error()))
			return
		}
		_ = reply(&types.CommandProtocolMessage{Message: &types.CommandProtocolMessage_Result{Result: result}})
	}()
	return nil
}

func rejection(code, message string) *aop.Rejection {
	return &aop.Rejection{Code: code, Message: message}
}
