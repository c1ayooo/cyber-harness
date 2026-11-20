# Fork notes (kksty/cyber-harness)

This checkout is the **fork** `kksty/cyber-harness` of
`chainreactors/cyber-harness`. Tianwu consumes the `cyber-harness` Hub and `cyber-scan` node built
from this tree; upstream code is never edited in the tianwu repository.

## Remotes and branches

| Remote | URL | Role |
|---|---|---|
| `upstream` | `https://github.com/chainreactors/cyber-harness.git` | original project |
| `origin` | `https://github.com/kksty/cyber-harness.git` | our fork |

- `master` tracks `upstream/master` and carries **no local commits**.
  The local ref can lag the upstream base already used by the patch branch;
  update it with the sync procedure before the next rebase. The 2026-11-09
  patch-branch rebase used `6d5a4a7a` (`refactor: simplify package globals and
  centralize mutations (#198)`), including upstream #196, #197 and #198.
- `tianwu/fixes` is the patch branch on top of `master`. Keep it linear so
  upstream updates are a rebase, not a merge chore.

2026-11-13 publication: the maintained fork branch is `tianwu/fixes`.
Consolidate the validated #200 rebase, OpenCode conversation routing and scan
test-fixture corrections there; temporary `codex/*` worktrees are review
history, not additional maintained remote branches. Before replacing the old
patch tip, verify its 12 patches remain equivalent and use a force-with-lease
that names the exact fetched remote tip. Preserve the prior local tips for
rollback; do not push or merge into the upstream project.

## rc10 split (2026-11-16)

Rebased all 16 fork commits onto upstream `21e62cfd` (rc10). The tool-exclusion
patch now belongs to `cmd/cyber-scan`; the Hub stays profile-neutral. Session
rotation preserves SingleTask while retaining upstream's compact/resume history
snapshot handling. The prior tip is retained locally as
`codex/before-rc10-20261116` for rollback. Tianwu starts a Hub + scan node pair
for one shared model gateway connection, configures the model on the Hub, and
pins AOP to the node's hex id. IOA accepts that same registered node id.

Build `./cmd/cyber-harness` and `./cmd/cyber-scan` with sqlite resource tags;
only the Hub uses `full`. The scan command includes its complete scanner
profile without that tag. No combined `aiscan web` executable is used by this
version of Tianwu.

## Sync upstream

2026-11-12 local validation: this worktree is `codex/upstream-sync-20261112`
at `ee8776fa`, rebased onto upstream `f4b1fb2f` (#200). All 12 existing
commits retain identical patch semantics (`git range-diff` reports `=`);
no newly equivalent patch was found. The upstream scanner CLI/configuration
and compaction simplifications are kept unchanged. The uncommitted OpenCode
changes were copied from the original `codex/opencode-session` worktree, which
remains untouched; neither remote branch has been rewritten or pushed.
The default package checks, Windows production build and Tianwu's three real
harness contract tests pass with isolated configuration/coreutils. The initial
full scanner worker assertions/spray fixture panic and Windows no-netgo
manifest assertion also reproduced at `3d84434c`; the test-only correction
below now passes these suites with production tags. Browser tests
retain the real USERPROFILE while Rod creates temporary browser profiles:
a synthetic USERPROFILE makes Windows Chrome reject debugging on both bases;
normal-profile Playwright and Katana checks pass. See Tianwu's
`docs/harness/upstream-sync-2026-11-12.md`
for commands, ownership checks and deployment boundaries.

```sh
git fetch upstream
git checkout master
git merge --ff-only upstream/master
git push origin master

git checkout tianwu/fixes
git rebase master
git push --force-with-lease origin tianwu/fixes
```

If the rebase conflicts, resolve it on `tianwu/fixes`; do not merge upstream
into the patch branch. After a successful rebase, rebuild and reinstall the
binary (below) and rerun the Tianwu validation.

**When upstream ships an equivalent fix, delete our duplicate patch instead of
keeping a second implementation.** Record the dropped commit in
[Superseded patches](#superseded-patches) below and rerun the package tests that
covered it. Do not keep a patch just because it has been there for a while.

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
   control plane only saw `context_tokens`, so Tianwu duplicated the model table
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
   relative paths against the agent's process directory. Tianwu sends a work-dir
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
   outside Tianwu's ledger (no run/usage/parent/cancel record), so Tianwu starts
   every host with `CYBER_EXCLUDE_TOOLS=subagent` and keeps
   `--allow-native-subagent` as the explicit operator escape hatch. The
   variable is an exclusion list owned by the host process, not a prompt rule.
   Tests: `go test ./cmd/aiscan`.

6. **Native command invocation directories** (2026-11-06, Tianwu D127)
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

7. **Null device arguments and environment contracts** (2026-11-06, Tianwu D129)
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

8. **Externally scheduled AOP mailboxes** (2026-11-06, Tianwu D129)
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
   automatic-session tests. Tianwu observes new directed commander messages
   and wakes its own paused-aware scheduler; historical replay never does.
   Rollback requires rebuilding both executables from matching revisions;
   there is no user-data migration.

9. **`fix(provider): fail fast on quota-exhausted 429`** (2026-11-11, Tianwu D67/D95)
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

10. **OpenCode Go conversation routing** (2026-11-12, Tianwu D149)
    OpenCode Go uses `https://opencode.ai/inference/go/openai/v1` and expects
    a stable `x-opencode-session` plus the client's own User-Agent. The existing
    OpenAI adapter only set Authorization; Tianwu's AOP request has no vendor
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
    and streaming requests passed during Tianwu's review.
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

12. **Session-stable system prompt for prefix caching** (2026-11-15, Tianwu cache audit)
    `agent/session/runtime.go`, `agent/session/dependencies.go`,
    `exts/prompt/defaults.go`, `agent/session/prompt_test.go`.
    `resolveSystemPrompt` used `time.Now()` for the Environment `Current Time`
    field at the start of every run. A long-lived commander session therefore
    rebuilt a different system prompt on every wake, and the provider's prefix
    cache missed the entire history (first request of wake 2: 86k input,
    cache_read 0; subsequent requests in the same run hit 90%+ because the
    system was resolved once). The system now carries `Session Started`
    (Runtime creation time), and Tianwu injects the current time in the new
    user turn, after the stable prefix. Test:
    `go test ./agent/session -run TestSystemPromptTimeIsSessionStable`.
    Rollback: restore the prior fork revision and rebuild the executor; no
    session data or ledger migration is involved.

13. **Accept Tianwu-owned provider metadata** (2026-11-15)
    `pkg/config/options.go`.
    Tianwu stores `paused`, `tier`, `fallback`, `max_concurrency` and
    `api_keys` beside the harness fields in the operator's
    `~/.cyber/cyber.yaml`. A standalone `aiscan` (or a test that reads the real
    file) failed the strict config validator with
    `unknown configuration field llm.providers[0].paused`. The struct now
    accepts those keys and ignores them; Tianwu's filtered per-host runtime copy
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
    (2026-11-18, Tianwu evaluator goal contract)
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
    silently undercounts it. Tianwu reviews work through its decision log and
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
    (2026-11-18, Tianwu P4-I guardrail judge)
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
    (2026-11-20, Tianwu duplicate-submission cleanup)
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
  `go test ./tools/terminal`. Tianwu's own regression history stays in
  tianwu `docs/harness/issue-bash-stdin.md`; the build keeps one
  implementation.

## Tests

All local patches are covered by tests in their packages:

```sh
go test ./agent ./agent/session ./agent/provider ./tools/terminal ./tools/files \
  ./tools/playwright ./tools/curl ./tools/gogo ./tools/toolargs ./tools/scan ./cmd/aiscan
```

## Build and deploy

Keep the checkout on `tianwu/fixes` (not `master`) while building: `master`
has no local patches.

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -tags "forceposix emptytemplates noembed osusergo netgo full sqlite" \
  -o /path/to/tianwu/bin/aiscan-full.exe ./cmd/aiscan
```

Replacing the binary while a host is running requires stopping `tw` first.
Use Tianwu build scripts to select platform tags: Windows deliberately omits
netgo to preserve the system resolver (D125). Old binary retention or removal
is an operator choice. The 2026-11-09 build was produced by
`tianwu/scripts/build-harness.ps1` from the rebased `tianwu/fixes`.

## Rule

Do not reach for an upstream patch before proving our own usage, data, or
contract is correct. When an upstream change is justified, record the root
cause, the test, and the rollback path in the commit and in tianwu's
`agent.md`.
