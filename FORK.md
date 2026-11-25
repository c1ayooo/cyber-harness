# 4zrcin fork of cyber-harness

4zrcin uses the Hub and scan node from the `tianwu/fixes` branch of
[kksty/cyber-harness](https://github.com/kksty/cyber-harness). Upstream lives at
[chainreactors/cyber-harness](https://github.com/chainreactors/cyber-harness).

## Remotes and branches

| Remote | Branch | Role |
|---|---|---|
| `upstream` | `master` | Upstream source |
| `origin` | `tianwu/fixes` | Maintained 4zrcin fork |

The local `master` tracks `upstream/master` without local patches. Its
checkout may lag the upstream commit already integrated into `tianwu/fixes`.
The maintained fork uses merge commits and fast-forward updates.

## Sync upstream

Fetch the two remotes separately. Compare the published fork with upstream
before creating a review worktree. `git cherry` can identify identical
patches. For refactored code, compare the affected behavior and its tests.

```sh
git fetch origin
git fetch upstream
git rev-list --left-right --count upstream/master...origin/tianwu/fixes
git cherry upstream/master origin/tianwu/fixes
git worktree add -b chore/harness-sync ../harness-sync origin/tianwu/fixes
git -C ../harness-sync merge upstream/master
```

For each merge conflict, check the upstream behavior and the contract the fork
test protects. If upstream supersedes a patch, keep the upstream implementation
and record the replacement in [Superseded patches](#superseded-patches).
During review, compare the worktree with both parents and run the tests for
the touched contracts.

From the 4zrcin checkout, compare its generated AOP files with the candidate
fork using `go run ./cmd/zrcin-gate -check-aop-protos -harness-dir ../harness-sync`.
Run the affected package tests before updating `tianwu/fixes`. Publish approved
changes as a fast-forward of the remote fork branch.

On 2026-11-24, upstream `master` at `585d8643` was an ancestor of the
published fork at `8f61e0d4`. The merge retained the upstream search extension
and the fork's OpenCode request routing. All 12 generated AOP files matched
the 4zrcin checkout at `425e6175`.

## Local patches

1. **`fix(session): deliver continued turn input to the inbox`**
   `agent/session/session.go`.
   A `Continue` turn called `agent.Continue` without pushing its new user
   message into the mailbox. `validateContinue` then rejected the turn with
   `cannot continue from message role: assistant` whenever the previous turn
   ended on an assistant message (every steer after a cancelled run).

2. **`feat(usage): report the resolved context_window with token usage`**
   `agent/retry.go`, `agent/loop.go`, `agent/loop_test.go`.
   The model window is resolved inside the agent (`ModelContextWindow`) but a
   control plane only saw `context_tokens`, so 4zrcin duplicated the model table
   to place its 85% handoff line (D80) — wrong for any model whose real window
   differs from the profile fallback. `usage.detail.context_window` now carries
   the resolved window, and the transcript keeps it scalar instead of summing it
   with the additive detail counters.

3. **`feat(session): per-session working directory`**
   `agent/session/protocol.go`, `agent/session/session.go`, `agent/session/workdir_test.go`,
   `agent/types.go`, `agent/loop.go`, `agent/workdir_test.go`, `tools/files/*`,
   `tools/playwright/*`, `core/tool` (no change needed; tools already read
   `operation.WorkDirFromContext`).
   Upstream AOP has no session working directory: `OpenSessionRequest` has no
   work-dir field and one agent process serves every run, so tools resolve
   relative paths against the agent's process directory. 4zrcin sends a work-dir
   extension on `OpenSessionRequest` (`type.googleapis.com/tianwu.WorkDir`,
   JSON `{"work_dir":"<absolute path>"}`); the agent stores it per session
   (`SessionOptions.WorkDir` → `agent.Config.WorkDir`), puts it in each tool
   invocation's `operation.Invocation.WorkDir`, and the files/playwright tools
   resolve their relative input/output paths against it. The `os.Root` boundary
   stays the agent's configured directory: a workspace outside it is refused.
   Empty/absent extension keeps the old behavior, so old control planes and new
   agents stay compatible. Tests: `go test ./agent ./agent/session ./tools/files ./tools/playwright`.

4. **`fix(provider): activate a slow but working endpoint`**
   `agent/provider/state.go`, `agent/provider/state_test.go`.
   The probe that decides whether a configured endpoint becomes this node's
   provider used a hard-coded 5s timeout. A gateway whose first token takes
   3-7s is usable but failed that probe; the caller treated the reload as
   rejected, discarded the candidate, and kept the provider-disabled profile —
   every session then failed with `agent provider is nil`, and the control
   plane's readiness gate (agent present but no provider/model) never passed.
   Activation (`Reload`) now uses the full request probe budget
   (`llmProbeTimeout`, 30s); the fast 5s probe remains for live `Update`
   replacement, where failing keeps the previous client. The probe helper takes
   an explicit timeout so the two paths cannot drift apart again.
   Test: `go test ./agent/provider -run TestReloadKeepsAProviderWhoseEndpointIsSlowToAnswer`.

5. **`feat(aiscan): exclude agent tools via CYBER_EXCLUDE_TOOLS`**
   `cmd/aiscan/*`.
   The harness always installs the native `subagent` tool once a session
   configuration exists; `--tools` only selects search/browser/record and
   `--no-agent` removes the whole agent. A subagent child session is created
   outside 4zrcin's ledger (no run/usage/parent/cancel record), so 4zrcin starts
   every host with `CYBER_EXCLUDE_TOOLS=subagent` and keeps
   `--allow-native-subagent` as the explicit operator escape hatch. The
   variable is an exclusion list owned by the host process, not a prompt rule.
   Tests: `go test ./cmd/aiscan`.

6. **Native command invocation directories** (2026-11-06, 4zrcin D127)
   The control plane and shell already pass the per-session working directory
   into Execution.Dir. Scanner commands instead resolved file flags against
   their shared startup Base.WorkDir, so a shell-created case/raw directory
   existed while gogo wrote relative to the host root. Base.ResolvePaths now
   uses execution directory, then invocation context, then startup default;
   gogo, spray, zombie, neutron, proton, scan and katana use that boundary.
   Existing path normalizers in gogo/katana are removed in favor of the common
   resolver. No process-wide chdir or mutation of the shared command is used.
   Explicit native file arguments follow the command's shell directory,
   including after cd. This does not rewrite scanner-internal default config
   or scratch paths, and does not create missing output parent directories.
   A foreground proton with empty stdin reports missing input rather than
   a successful no-findings scan; explicit empty files remain valid input.
   Tests: actual gogo through shell and registry, loopback-only input/output,
   shell cd, resolution precedence and concurrent calls; existing command and
   terminal regressions. The gogo directory regression fails on the previous
   binding and passes on the new one. Rollback: restore the previous checkout
   and rebuild the executor; no user data migration is performed.

7. **Null device arguments and environment contracts** (2026-11-06, 4zrcin D129)
   Touch passed `/dev/null` to the built-in curl output flag on Windows.
   The embedded shell already maps null redirection correctly; curl instead
   joined that path to the case directory. Its file resolver now maps the
   POSIX null device to os.DevNull for body, header, trace and file inputs.
   Loopback HTTP regressions cover body/header/trace discard with write-out,
   and the terminal regression proves shell redirection needs no new handler.
   Native bash descriptions identify the host OS/architecture and POSIX
   interpreter; file schemas identify session-relative paths. Arsenal knowledge
   distinguishes host artifacts, the file-service root and WSL environments.
   No distribution name, forced installation or attack workflow is introduced.
   Tests: tools/curl, tools/terminal, tools/files, tools/arsenal, exts/skills.
   Rollback: restore the prior fork revision and rebuild the executor; no data
   migration or system configuration change is involved.

8. **Externally scheduled AOP mailboxes** (2026-11-06, 4zrcin D129)
   Idle native sessions can start automatic model turns on peer/background
   input. A control plane owns tracked turn admission and pause, so its
   existing workspace extension now forwards the runtime's SingleTask option.
   This is opt-in; standalone sessions retain native automatic behavior.
   SingleTask already disables mailbox-triggered scheduling, while explicit
   RunTurn continuation and active mailbox admission remain available. Preserve
   the policy through native clear/compact/resume session rotation as well.
   No tools are removed and no model, strategy or fee policy is introduced.
   Tests: AOP extension -> runtime -> idle delivery -> explicit execution,
   repeated manual turns, rotation, active delivery, and the existing native
   automatic-session tests. 4zrcin observes new directed commander messages
   and wakes its own paused-aware scheduler; historical replay never does.
   Rollback requires rebuilding both executables from matching revisions;
   there is no user-data migration.

9. **`fix(provider): fail fast on quota-exhausted 429`** (2026-11-11, 4zrcin D67/D95)
   `agent/provider/errors.go`, `agent/provider/types.go`, `agent/retry.go`,
   tests in `agent/retry_test.go` and `agent/provider/errors_test.go`.
   A gateway may report an exhausted account as HTTP 429 (WorkBuddy answers
   `{"error":{"type":"insufficient_quota",...}}` with `Retry-After: 60`). The
   retry loop treated every 429 as transient and retried for ~9 minutes, so the
   control plane saw only `status llm_request` events: runs neither failed nor
   paused, and credential rotation/fallback could not trigger. `APIError`
   `IsRetryable` now returns false for a 429 whose body carries quota/billing
   markers (OpenAI `insufficient_quota`, `insufficient balance`, Chinese
   `额度已用尽` / `余额不足`, …); a plain rate-limit 429 still retries, and
   plain/wrapped errors go through the same text check. The vendor body still
   reaches the control plane, which classifies it as quota and pauses or switches
   per D67/D95. Tests: quota 429 call count == 1 with the body preserved, plain
   429 still retryable, provider classification table.

10. **OpenCode Go conversation routing** (2026-11-12, 4zrcin D149)
    OpenCode Go uses `https://opencode.ai/inference/go/openai/v1` and expects
    a stable `x-opencode-session` plus the client's own User-Agent. The existing
    OpenAI adapter only set Authorization; 4zrcin's AOP request has no vendor
    HTTP-header injection contract, so this fix belongs at the provider boundary.
    The OpenAI adapter now binds headers per request for non-streaming, SSE,
    catalogue and auxiliary requests. The exact HTTPS opencode.ai hostname is
    checked; metered and subscription URL prefixes are preserved. Pasted full
    chat endpoints are normalized without duplicating the suffix.

    Logical model conversation identity survives physical session rotations;
    event SessionID and existing prompt_cache_key semantics are unchanged.
    Agent runs bind the logical identity into context for auxiliary model calls;
    independent child tasks reset it. Requests without an owning conversation
    use a provider-local auxiliary identity. Shared providers never mutate a
    global current-session header.

    Tests: `go test ./agent ./agent/session ./agent/provider`, `go vet ./agent/...`;
    targeted cases cover concurrent conversations, SSE, auxiliary context,
    hostname boundaries, cache-key preservation and compaction rotation.
    `CYBER_TEST_OPENCODE_KEY` explicitly opts into `TestOpenCodeLiveChatAndStream`;
    it is skipped by default and never saves the key. Actual Go non-streaming
    and streaming requests passed during 4zrcin's review.
    Rollback: retain the previous executable and rebuild without this patch;
    no schema, stored credentials or project data are migrated. The same
    OpenCode patch was validated on `codex/opencode-session` and this rebased
    `codex/upstream-sync-20261112` worktree. Publication consolidates the #200
    base and test-fixture corrections into the sole maintained patch branch,
    `tianwu/fixes`, using the checked remote-tip lease described above.

11. **Scanner test resource and Windows manifest alignment** (2026-11-12)
    Test-only changes in `tools/scan/main_test.go`,
    `tools/scan/engine/main_test.go`, `tools/scan/command_test.go` and
    `cmd/aiscan/manifest_test.go`. Both scan test binaries initialize resources
    through the host's existing `InitWithOptions` and close the engines after
    the suite. Worker counts and local dictionary/crawl/Host assertions stay
    intact; JS/URL extraction rules must be installed before crawling. The
    manifest assertion accepts the complete Windows tag set without only
    `netgo`, preserving the native DNS build policy and exact matching for
    every other tag. Missing sqlite and unexpected tags are still rejected.
    Tests pass for default, production full, and netgo full scan compositions,
    shuffled/repeated scan execution, the complete production full aiscan
    suite and focused manifest checks. No scanner/dependency runtime behavior
    is changed; missing crawl resources still need validation in the dependency.

12. **Session-stable system prompt for prefix caching** (2026-11-15, 4zrcin cache audit)
    `agent/session/runtime.go`, `agent/session/dependencies.go`,
    `exts/prompt/defaults.go`, `agent/session/prompt_test.go`.
    `resolveSystemPrompt` used `time.Now()` for the Environment `Current Time`
    field at the start of every run. A long-lived commander session therefore
    rebuilt a different system prompt on every wake, and the provider's prefix
    cache missed the entire history (first request of wake 2: 86k input,
    cache_read 0; subsequent requests in the same run hit 90%+ because the
    system was resolved once). The system now carries `Session Started`
    (Runtime creation time), and 4zrcin injects the current time in the new
    user turn, after the stable prefix. Test:
    `go test ./agent/session -run TestSystemPromptTimeIsSessionStable`.
    Rollback: restore the prior fork revision and rebuild the executor; no
    session data or ledger migration is involved.

13. **Accept 4zrcin-owned provider metadata** (2026-11-15)
    `pkg/config/options.go`.
    4zrcin stores `paused`, `tier`, `fallback`, `max_concurrency` and
    `api_keys` beside the harness fields in the operator's
    `~/.cyber/cyber.yaml`. A standalone `aiscan` (or a test that reads the real
    file) failed the strict config validator with
    `unknown configuration field llm.providers[0].paused`. The struct now
    accepts those keys and ignores them; 4zrcin's filtered per-host runtime copy
    still strips them, so provider behavior and secret handling are unchanged.
    Test: `go test ./cmd/aiscan -run TestInboxHostRejectsRemoteTransport`.

14. **Isolate configuration-precedence tests from operator state** (2026-11-16)
    `pkg/config/loader_test.go`.
    Changing only the working directory still overlays the real user
    `~/.cyber/cyber.yaml`. Environment fallback tests therefore inherited an
    active profile, failed on developer machines, and could print operator
    credentials in assertion output. Reuse the existing `isolatedContext`
    fixture for project, home, executable and environment discovery; supply
    only each test's synthetic environment through `Context.LookupEnv`.
    No provider selection or runtime configuration behavior changes. Tests:
    `go test ./pkg/config ./agent/session -count=1`.
    Rollback: restore the previous `pkg/config/loader_test.go`; no executable
    rebuild, configuration change or project migration is required.

15. **`feat(session): accept the control plane's evaluator goal on RunTurn`**
    (2026-11-18, 4zrcin evaluator goal contract)
    `agent/session/protocol.go`, `agent/session/session.go`,
    `agent/session/run_goal_test.go`.
    Root cause: the evaluator always derived its goal from the turn input text
    (`evaluator.NewLoopConfigWithInput` uses `provider.MessageText(input)`). That
    is right for a standalone agent, but a control plane that owns the intent
    has a short goal and an acceptance criterion that are separate from the
    executor's brief. Making the goal part of the prompt would leak the
    evaluator's instructions to the executor and let the evaluator judge the
    executor's own wording. `RunTurnRequest` now accepts the fork extension
    `type.googleapis.com/tianwu.RunGoal` with JSON
    `{"goal":"...","eval_rounds":"..."}`; `RunAOPTurn` carries it into
    `RunInput.EvalGoal` (and `EvalRounds` when the extension supplies pacing,
    overriding `AgentRunOptions.eval_rounds`). `session.go`'s eval branch uses
    that goal as `EvalLoopConfig.Goal` only when eval criteria is non-empty;
    `InitialInput` stays the turn message. An absent extension keeps the old
    input-derived goal and default 20-round ceiling exactly. `eval_rounds`
    additionally accepts a JSON number so a producer that models rounds as a
    count still delivers the goal.
    Tests: `go test ./agent/session -run 'TestTurnRunGoalExtension|TestRunAOPTurnRunGoalShapesEvaluatorGoal'`.
    The integration case drives `RunAOPTurn` through the real prompt resolver
    with a scripted provider and asserts both halves of the contract: the
    executor still receives the message, the evaluator receives the extension
    goal and ceiling, and the no-extension case keeps the input-derived goal and
    default ceiling.
    Rollback: remove the extension parsing/`RunInput.EvalGoal` override and
    rebuild the executor; old control planes never send the extension, so no
    data or ledger migration is involved.

16. **Disable the recap worker in the reference scan profile** (2026-11-18)
    `cmd/cyber-scan/profile.go`.
    Root cause: `exts/recap` installs a worker that summarizes on every
    `TurnEnded` event with an extra model call (`agent/recap/model.go`, max 256
    tokens). That call's usage is not reported in the turn's token usage, so a
    control plane that accounts per-run spend and pauses/exhausts on quota
    silently undercounts it. 4zrcin reviews work through its decision log and
    handoff receipts, not through recaps, so the reference scan profile no
    longer appends `recapext.New()` and the import is gone. The `exts/recap`
    package itself is unchanged, so embedders that want recaps can still
    compose it explicitly.
    Tests: `go test ./cmd/cyber-scan -run TestProfileDoesNotLinkRecapWorker`
    pins that the reference binary no longer links the recap package;
    `go test ./cmd/cyber-scan` and `go build ./...` cover the profile itself.
    Rollback: re-add the `recapext` import and `recapext.New()` to the session
    extension list in `cmd/cyber-scan/profile.go`; no configuration or stored
    data is affected.

17. **Declare external MCP servers as operator configuration** (2026-11-18)
    `exts/mcp/config.go`, `exts/mcp/config_test.go`,
    `cmd/cyber-scan/{config.go,extensions.go,ioa_composition.go,config_test.go,mcp_test.go}`.
    Root cause: `exts/mcp` could expose MCP servers as native bash commands, but
    the reference distribution had no `mcp` configuration section and never
    composed the extension, so an operator had no way to enable it. MCP servers
    are per-deployment configuration, not a distribution capability. `exts/mcp`
    now declares config section `mcp` (json `mcpServers`, the same schema as MCP
    JSON config files), plus `Declare` for validation/`--init`/settings and
    `ReadConfig`; the cyber-scan composition root declares the section, reads it
    and appends the extension only when at least one server is configured. An
    absent/empty section leaves the extension graph identical to a build without
    MCP. The Hub uses its own profile-neutral declaration graph, so its build
    and configuration schema are unchanged; per-host config files must still
    keep host-specific sections out of the Hub's file.
    Tests: `go test ./exts/mcp ./cmd/cyber-scan -run 'TestConfiguration|TestExtensionsInstallMCPOnlyWhenServersAreConfigured|TestApplicationConfig'`.
    The config test pins raw and resolved decoding to the same server map and
    rejects unknown server fields; the composition test pins install-on-
    non-empty-only.
    Rollback: remove the `mcp` declaration/read and the composition append, and
    rebuild the executor; servers are external processes, so no data is
    migrated.

18. **Pluggable guardrail judges: Policy, LLM, hybrid, shadow and scope**
    (2026-11-18, 4zrcin P4-I guardrail judge)
    `exts/guardrail/{policy.go,policy_llm.go,policy_hybrid.go,runtime.go,extension.go,jev.go}`,
    `exts/guardrail/{admission_test.go,policy_llm_test.go,policy_hybrid_test.go,extension_config_test.go}`,
    `cmd/cyber-scan/{profile.go,guardrail_provider_test.go}`,
    `docs/configuration.md`, `docs/user/tools.md`.
    Root cause: guardrail's only judge was JEV and its stages were two bare
    function fields in `runtime.go`. The reference deployment needed a cheap
    OpenAI-compatible judge, a hybrid that escalates only uncertain cases to
    JEV, and a way to trial a judge without changing admission behavior
    (shadow) or to limit judgment by tool name (scope) and to fail explicitly
    (on_error). There was no shared abstraction, so any LLM code would have
    leaked into the JEV/runtime path.
    Shape: `Policy` (`Check`/`Confirm`) in `policy.go`; `jevPolicy` implements
    it (existing `check`/`confirm` methods remain, so `provider=jev` decisions
    are unchanged); `runtime.Admit` invokes only `Policy` and keeps the legacy
    function seam for the disabled provider. `policy_llm.go` is an
    OpenAI-compatible `/chat/completions` judge (temperature 0, max_tokens 128,
    non-streaming, 3s default timeout, semaphore 8, robust three-way parser
    accepting case/code fences/extra text/JSON confidence, redirects not
    followed) whose failures map to `on_error` (`allow`/`review` default/
    `block`) instead of surfacing provider errors; an on_error decision is
    marked with negative confidence and hybrid keeps it final.
    `policy_hybrid.go` escalates
    a LLM `REVIEW` or a low-confidence (`<0.7`) `ALLOW` to JEV and maps JEV
    `record`/`block`/`review` straight through; both stages are injected
    `Policy` values so unit tests never need a real JEV. New `guardrail` fields
    (`scope`, `allow_prefixes` safe-mode-only, `on_error`, `timeout`,
    `concurrency`, `shadow`, `llm.{base_url,model,api_key,temperature,max_tokens}`)
    are decoded/validated with readable Chinese reasons; JEV config fields are
    untouched. Admit order: scope filter (unmatched calls are not judged and
    emit no event) → Check/Confirm → emit the existing Decision/Review events →
    shadow (record and always allow) → safe-mode literal command-prefix
    allowlist → existing auto/safe handling. `on_error=allow` logs a WARN at
    load. `cmd/cyber-scan` constructs the shared JEV client for
    `provider=jev|hybrid` (or `jev.mode!=off`); `provider=llm` needs no JEV
    client or credentials. When the JEV response carries usage, guardrail
    publishes an AOP usage event (`Emitter=guardrail`) with the real tokens and
    never fabricates accounting when usage is missing.
    Judge accounting: the LLM judge previously reported no usage even though an
    OpenAI-compatible response carries a `usage` block, so referee token cost was
    invisible to the ledger for `provider=llm` and for the LLM stage of
    `provider=hybrid`. `policy_llm.go` now parses
    `prompt_tokens`/`completion_tokens`/`total_tokens` (plus
    `prompt_tokens_details.cached_tokens` and top-level cache counters when a
    gateway reports them) into `aop.TokenUsage` and publishes it through the
    injected reporter as an AOP usage event with `Emitter=guardrail-llm`. JEV
    keeps `Emitter=guardrail` (old-control-plane compatible), so the ledger
    classifies both as referee cost while separating the vendors. Hybrid
    publishes one event per stage and never merges them: one `guardrail-llm`
    event for its LLM request and, only when it actually escalates, one
    `guardrail` event for JEV. A missing usage block, a failed or unparsable
    judgment, and caller cancellation emit nothing; absent counters stay zero
    instead of being summed or estimated (the usage block is parsed separately
    from the verdict so malformed accounting cannot turn a completed judgment
    into a provider failure).
    Semantics amendment (2026-11-18, P6-M "uncertain means allow"): the LLM
    prompt was reduced from three options to `ALLOW` / `BLOCK: reason` only -
    default allow, and anything the judge cannot establish from the invocation
    itself is `ALLOW` (record); only clear and hard-to-recover damage to
    availability, data integrity or system configuration is `BLOCK`. `REVIEW`
    is no longer requested, but the parser keeps it for abnormal model output.
    Mapping now implements uncertainty-is-allow: an explicit `confidence` below
    0.7 maps to `ALLOW` regardless of the reported token; `REVIEW` without a
    confidence (or with a low one) also maps to `ALLOW`; an explicit `BLOCK`
    without a low-confidence signal stays `BLOCK`; only a high-confidence
    `REVIEW` is preserved (auto intercepts it, safe asks a human). Hybrid
    therefore escalates only an explicit `REVIEW`; a low-confidence ALLOW never
    triggers JEV. `on_error` is unchanged (default `review`): transport
    failures, timeouts, non-200 and unparsable answers are not silently
    allowed, and the configuration table distinguishes "uncertain => ALLOW"
    from "failure => on_error". JEV stays the harness-native implementation and
    is untouched in this amendment: no `jev.go` judgment or two-stage changes,
    hybrid only calls the existing `Policy`.
    Tests:
    `go build ./...`; `go vet ./exts/guardrail/... ./cmd/cyber-scan/...`;
    `go test ./exts/guardrail ./cmd/cyber-scan -count=1 -timeout 10m` covers a
    fake OpenAI server (ALLOW/BLOCK, abnormal REVIEW compatibility,
    uncertainty/confidence mapping, timeout/status/parse failures,
    three on_error states, concurrency cap, cancellation, redirect, oversized
    evidence), scope/shadow/allow_prefixes admission, hybrid escalation with
    two injected fake policies, provider enumeration, the LLM provider without
    a JEV capability, the hybrid credential gate, and JEV/LLM/hybrid usage
    reporting (fields, emitters, missing usage, failure/cancellation).
    Rollback: delete `policy_llm.go`/`policy_hybrid.go`, restore the
    `Policy`-free `runtime.go`/`extension.go` from the previous fork revision
    and rebuild; configuration with only the old fields stays valid, so no
    stored configuration or data migration is involved. For the accounting
    part alone, drop the LLM reporter assignment and the `usage` parsing and
    keep JEV's `usageReporter(stream, "guardrail")`; the extra usage events
    carry no persisted state.

19. **`docs(neutron): state the template-set default in the quick reference`**
    (2026-11-20, 4zrcin duplicate-submission cleanup)
    `tools/neutron/neutron.go`, `tools/neutron/neutron_test.go`.
    Root cause: `QuickReference()` listed `-t <path>` as "Extra template file or
    directory" and said nothing about the default, while the engine treats a `-t`
    load as the whole template set (`RestrictToTemplates` is set whenever
    templates were loaded). A control plane that has to know which templates run
    therefore restated the flag and its default inside its own dispatch prompt,
    creating a second copy of the tool contract that drifts as soon as either
    side changes. The quick reference now states that the given templates
    replace the built-in set and that omitting `-t` means the built-in set only;
    the example commands, the flags and the selection behavior are unchanged.
    Test: `go test ./tools/neutron -count=1`. The new
    `TestQuickReferenceStatesTemplateSetDefault` fails if that sentence is
    removed; the existing `TestUsageIsGeneratedFromNeutronFlags` flag assertions
    are kept.
    Rollback: restore the previous fork revision and rebuild the executor. This
    is quick-reference text only, so no session data, configuration or ledger
    migration is involved.

20. **`fix(session): accept both fork extension namespaces`**
    `agent/session/protocol.go`, `agent/session/scoperules_test.go`.
    The control plane renamed its fork namespace (`tianwu.*` → `4zrcin.*`),
    so every extension it sends now carries the new type URL while this file
    still matched only the old one — the host silently ignored WorkDir,
    ToolEnv and RunGoal again (workdir fell back to the agent process
    directory, evaluator goals fell back to input derivation, tool env
    vanished). Every fork extension parser now matches a URL list covering
    both generations; payloads are unchanged. Test:
    `go test ./agent/session -run 'TestForkExtensions|TestTurnScopeRules'
    -count=1`.

21. **`feat(scoperules): judge proxied HTTP against the control plane's test range`**
    `core/scoperules/`, `agent/session/protocol.go`, `exts/guardrail/scoperules.go`,
    `tools/proxy/hub.go`, `tools/proxy/mitm.go`, `tools/proxy/hub_traffic.go`,
    `exts/observe/extension.go`, `exts/proxy/extension.go`.
    The 4zrcin/4zrcin control plane sends the project's machine-matchable test
    range (manifest `scope_rules` JSON) as a per-turn fork extension
    (`tianwu.ScopeRules` / `4zrcin.ScopeRules`, mirrors 15/16/17). The session
    registers one set per session (`core/scoperules`, invalid sets are logged
    and ignored); the guardrail runtime implements the proxy's `ScopeJudge`
    seam: first-hit rule matching over method/host/path, miss falls to the
    default action. `record` rides only the flow's `TrafficVerdict` sidecar
    (one tool call fans out into many requests — journaling every record would
    flood the run journal); `review` holds the request on the ordinary
    pending-review lifecycle (synthetic tool `http.request`, operator answers
    through the existing guardrail Pending/Resolve RPC, expiry cancels);
    `block` short-circuits the exchange with a synthetic 403 that is itself
    captured; `shadow` judges and records but never holds or refuses. Only
    requests with a session attribution are judged; the outer CONNECT is not
    (relay-mode HTTPS only exposes the CONNECT host, so HTTPS coverage follows
    decrypt capture). A judgeless hub behaves byte-identically to before.
    Tests: `go test ./core/scoperules ./exts/guardrail -run TestJudgeScope
    ./tools/proxy -run TestScopeJudge ./agent/session -count=1`.
    Rollback: rebuild without the judge wiring (`SetScopeJudge` call) or with
    no `scope_rules` extension sent — both leave record-only behavior.

22. **`feat(web): the Hub becomes an embeddable library`** (2026-11-26)
    `pkg/web/host/host.go`, `pkg/web/hubapp/` (new), `cmd/cyber-harness/main.go`.
    The 4zrcin control plane embeds the Hub in-process (its single binary,
    docs/04 M1), so the host must accept a listener the caller owns and the
    command's assembly must be importable. `webhost.Config` gains an optional
    `Listener`: when set, Serve accepts on it and ignores `Addr` (the 4zrcin
    console already owns a loopback listener; binding a second port would be a
    new failure surface). The command's assembly moved to `pkg/web/hubapp.App`
    — same flag surface, same codec/store wiring, same help text; the command
    is now a thin process shell calling it with a nil override, so its CLI
    behavior is unchanged, and an embedding caller passes its own listener via
    the override seam. Scan-node processes are untouched (they stay separate
    subprocesses in both modes; CYBER_EXCLUDE_TOOLS consumers live in
    cmd/cyber-scan, so in-process hosting never needs to set that variable
    process-wide).
    Tests: `go test ./pkg/web/host ./pkg/web/hubapp -count=1`; the command
    suite `./cmd/harness` passes except the two OrderLab fixture scenarios
    that require python on PATH (environmental, pre-existing).
    Rollback: revert — the command regains its inline assembly and the
    embedding form disappears.

23. **`feat(core): the capture node fences, audits and ships evidence`** (2026-11-26)
    `core/scoperules/`, `exts/guardrail/` (+ `tools/resources/guardrail_builtin.yaml`,
    `tools/resources/builtin_gen.go`, generated `guardrail_builtin_gen.go`),
    `core/artifactsync/` (new), `exts/observe/extension.go`.
    The remote capture node's minimal capability set (docs/04 T3): fence
    judgment, guaranteed audit, evidence return.

    - **23a — CIDR rows** (`core/scoperules/hostMatches`): a rule host containing
      `/` parses as a CIDR prefix and matches the target's resolved address —
      IP-literal hosts directly, hostnames through a bounded, cached resolver
      (5 min TTL, 2 s timeout, 512 entries, negative results cached too). Every
      failure mode is a miss, never an invented verdict; an unparseable row
      falls back to the exact-hostname comparison (version-mismatch safety).
    - **23b — guaranteed audit** (`exts/guardrail`): a built-in corpus of
      destructive/exfiltration command patterns (rm -rf /, curl|sh, dd of=/dev/sd,
      mkfs, chmod -R 777 /, fork bomb, credential exfil) is audited
      unconditionally before the policy nil-check, scope filter and mode logic —
      a capture node without any provider still records the audit rows the
      control plane renders with the `builtin.` source badge. The corpus lives
      in `tools/resources/guardrail_builtin.yaml` (compiled at generation time,
      `go run ./builtin_gen.go` from `tools/resources`), ships in every binary
      form with no build tag — the audit duty is not a capability, unlike the
      template resources. The corpus only records; the call then flows through
      the normal policy path unchanged.
    - **23c — evidence sidecars** (`core/artifactsync` + `exts/observe`): a new
      observe kind `artifacts` ships changed case-directory files as
      `4zrcin.Artifact` JSON sidecars (path/kind/media_type/size/sha256/base64
      data) — process completions carry their snapshot diff, in-band file
      writes carry their hook content. Limits: 8 MiB per file, 16 files / 64 MiB
      per batch; `.zrcin` node metadata and deletions never ship. Old hubs
      ignore the unknown sidecar; old nodes never send it. This also fixes a
      latent bug: `observe`'s emit wrapped pre-built `*anypb.Any` sidecars in a
      second Any layer, so the control plane's exact-URL match could never see
      `4zrcin.TrafficVerdict` on the wire — pre-built Any sidecars are now
      appended directly.
    Tests: `core/scoperules` (CIDR hit/miss/IPv6/resolver cache), `exts/guardrail`
    (no-policy guaranteed audit, shadow survival, corpus table),
    `exts/observe` (sidecar round trip, `.zrcin` exclusion, single-Any wire
    shape). Rollback: revert; the control plane keeps working without the
    sidecars (shared-filesystem path untouched).

25. **`docs(fork): the control plane is zrcin`** (2026-11-26)
    `FORK.md` only — no harness code changes.
    The 4zrcin repository renamed its identity (`cmd/tw` → `cmd/zrcin`,
    `TW_*` env vars → `ZRCIN_*`, the per-project `.tw` metadata directory →
    `.zrcin`, theme utility prefix `tw-*` → `zrcin-*`). This file's prose and
    the `cmd/tw-gate` sync command were updated to match; the fork module
    (`github.com/c1ayooo/cyber`), the branch name (`tianwu/fixes`) and the
    legacy `tianwu.*` type URLs stay as they are — patch 20 keeps both
    extension namespaces recognized. Patch numbers 22/23 are reserved for the
    control plane's embedding work (webhost `Listener`, docs/03 §11 P5); 24
    is the egress proxy.

## Superseded patches

These commits were on `tianwu/fixes` and are intentionally **not** carried after
the 2026-11-09 rebase. Do not reintroduce them without new evidence.

- **`fix(bash): give foreground shells EOF on stdin`**,
  **`fix(bash): keep stdin only for wait>0 background sessions`**,
  **`fix(bash): preserve stdin ownership and interactive script input`**,
  and the matching `docs: note wait>0 stdin behavior` commit.
  Upstream `a06d054a` (#197) now fixes the same hang: `keepStdin` is set only
  for `wait > 0`, the interpreter closes the otherwise-unused pipe writer for
  foreground non-interactive commands, an explicit `BashExecOptions.Stdin`
  still wins, and `docs/user/tools.md` documents the EOF / `wait>0` /
  `tmux send-keys` contract. The upstream tests are
  `tools/terminal/interpreter_test.go`; verify with
  `go test ./tools/terminal`. The regression history is recorded in the fork commits.

## Tests

Use the regression tests listed with each patch. For provider routing and
configuration checks, the focused suites are:

```sh
go test ./agent/provider ./pkg/config
```

## Build and deploy

Use the [4zrcin build scripts](https://github.com/kksty/tianwu#从源码构建与启动)
with the same fork checkout for the Hub and scan binaries. The scripts select
platform tags and build `cmd/cyber-harness` and `cmd/cyber-scan`. Pass the
directory of a review worktree explicitly when checking an upstream merge.

Record the fork commit and AOP check with the build. Deployment and rollback
use [4zrcin's deployment guide](https://github.com/kksty/tianwu/blob/main/docs/02-deploy.md).

## Rule

Confirm whether a bug belongs to the caller, the protocol contract or the fork.
For each patch, record the cause, regression test and rollback notes in its commit.
