# 4zrcin fork of cyber-harness

4zrcin uses the Hub and scan node from the `tianwu/fixes` branch of
[c1ayooo/cyber-harness](https://github.com/c1ayooo/cyber-harness), the
maintained fork of
[chainreactors/cyber-harness](https://github.com/chainreactors/cyber-harness).
The fork's `master` has been fast-forwarded to the same content as upstream's.

## Remotes and branches

| Remote | Branch | Role |
|---|---|---|
| `upstream` | `master` | Upstream source |
| `origin` | `tianwu/fixes` | Maintained 4zrcin fork |

The local `master` tracks `upstream/master` without local patches. Its
checkout may lag the upstream commit already integrated into `tianwu/fixes`.
The maintained fork uses merge commits and fast-forward updates.

`4zdesign/NN` names an archived process document in [c1ayooo/4zdesign](https://github.com/c1ayooo/4zdesign), under `4zrcin/NN-….md`.

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
the touched contracts. Run the affected package tests before updating
`tianwu/fixes`. Publish approved changes as a fast-forward of the remote fork
branch.

## Local patches

### Registered upstream files by exact path

`scripts/check-fork.sh` reads every backticked path from this heading up to
"## Superseded patches". The numbered entries describe each patch but often name a
directory or use a brace list the check cannot match, so this index lists every
modified upstream file by exact path. The budget is 20 added lines per upstream
Go source file that is not a test (4zdesign/19 red line 1); tests, docs and manifests
are registered without a budget (已决 24). Figures are added lines against
`upstream/master`, from the check itself.

- **#1 continued turn input to the inbox**
  - hooks: `agent/session/session.go` (20)
- **#2 resolved context_window with token usage**
  - hooks: `agent/loop.go` (8), `agent/retry.go` (20)
  - tests and docs: `agent/loop_test.go`, `agent/retry_test.go`
- **#3 per-session working directory** — includes the 2026-11-20 follow-up: the work dir is read on every turn, and curl creates a missing parent directory before writing
  - hooks: `agent/agent.go` (2), `agent/loop.go` (8), `agent/session/protocol.go` (4), `agent/session/session.go` (20), `agent/types.go` (11), `tools/curl/client.go` (14), `tools/curl/cookies.go` (8), `tools/files/fs.go` (8), `tools/files/list.go` (8), `tools/files/range.go` (8), `tools/playwright/browser.go` (9), `tools/playwright/interact.go` (2), `tools/playwright/recorder.go` (1), `tools/playwright/session.go` (5), `tools/playwright/storage.go` (2)
  - tests and docs: `tools/curl/client_test.go`, `tools/playwright/browser_test.go`
- **#4 activate a slow but working endpoint**
  - hooks: `agent/provider/state.go` (15)
  - tests and docs: `agent/provider/state_test.go`
- **#5 exclude agent tools via CYBER_EXCLUDE_TOOLS**
  - moved to `pkg/assembly` (4zdesign/19 P6): `cmd/cyber-scan/cli.go`
- **#6 native command invocation directories**
  - hooks: `tools/gogo/gogo.go` (10), `tools/katana/katana.go` (7), `tools/neutron/neutron.go` (15), `tools/proton/command.go` (3), `tools/scan/command.go` (1), `tools/spray/spray.go` (1), `tools/toolargs/resolve.go` (15), `tools/zombie/zombie.go` (1)
  - tests and docs: `tools/gogo/gogo_test.go`, `tools/neutron/neutron_test.go`, `tools/scan/command_test.go`
- **#7 null device arguments and environment contracts** — includes the 2026-11-20 change that passes the per-turn tool environment through the invocation context instead of the process-level baseEnv
  - hooks: `core/operation/operation.go` (0), `tools/terminal/bash.go` (3)
  - tests and docs: `exts/scanner/testdata/prompt_main_system.golden`, `exts/scanner/testdata/prompt_scanner_system.golden`, `exts/skills/assets/runtime/arsenal.md`, `tools/terminal/bash_test.go`
- **#8 externally scheduled AOP mailboxes** — the native file contracts of the same 2026-11-06 change
  - hooks: `tools/files/tools.go` (2)
- **#9 fail fast on quota-exhausted 429**
  - hooks: `agent/provider/errors.go` (0), `agent/provider/types.go` (9), `agent/retry.go` (20)
  - tests and docs: `agent/provider/errors_test.go`, `agent/retry_test.go`
- **#10 OpenCode Go conversation routing**
  - hooks: `agent/agent.go` (2), `agent/provider/openai.go` (12), `agent/task.go` (1)
- **#11 scanner fixtures and Windows manifest alignment** — and the 2026-11-16 alignment with the rc10 hub/scan split
  - tests and docs: `exts/scanner/testdata/prompt_main_system.golden`, `exts/scanner/testdata/prompt_scanner_system.golden`
- **#12 session-stable system prompt**
  - hooks: `exts/prompt/defaults.go` (7)
  - tests and docs: `agent/session/prompt_test.go`
- **#14 isolate configuration-precedence tests**
  - tests and docs: `pkg/config/loader_test.go`
- **#15–#18 control-plane goal, recap off, external MCP, pluggable judges** — composition root
  - moved to `pkg/assembly` (4zdesign/19 P6): `cmd/cyber-scan/config.go`, `cmd/cyber-scan/profile.go`
  - tests and docs: `docs/configuration.md`, `docs/user/tools.md`
- **#17 external MCP servers**
  - moved to `pkg/assembly` (4zdesign/19 P6): `cmd/cyber-scan/extensions.go`, `cmd/cyber-scan/ioa_composition.go`
- **#20 both fork extension namespaces**
  - hooks: `agent/session/protocol.go` (4)
- **#22 the Hub becomes an embeddable library**
  - hooks: `cmd/cyber-harness/main.go` (5), `pkg/web/host/host.go` (14)
- **#23 the capture node fences, audits and ships evidence**
  - hooks: `tools/resources/resources.go` (8)
- **#24 the capture recipe: resources and engines compile out**
  - hooks: none left — the tag plumbing this patch added to the generated resources (and the fork-added resource twins) is deleted now that capture is a runtime flag of the one scan binary; the resources files are upstream-identical again
  - manifests: `cmd/audit/go.mod`, `cmd/audit/go.sum`, `go.mod`
- **#25 the capture recipe announces itself in the hello**
  - moved to `pkg/assembly` (4zdesign/19 P6): `cmd/cyber-scan/agent_transport.go`
- **#21–#37 scope rules, proxy seam, instance fence** — the proxy side of seam G2
  - hooks: `tools/proxy/config.go` (7), `tools/proxy/hub.go` (6), `tools/proxy/hub_traffic.go` (9), `tools/proxy/mitm.go` (15)
  - tests and docs: `tools/proxy/mitm_test.go`
- **E3 round (2026-11-27, 4zdesign/19 appendix E)** — seams G1 and G4, the evidence switch, the judge block, SubmitReview (G3), the verdict sidecar hook, the Policy slot in the base composition
  - hooks: `agent/session/dependencies.go` (3), `agent/session/protocol.go` (4), `agent/session/runtime.go` (17), `agent/session/session.go` (20), `exts/guardrail/runtime.go` (9), `exts/observe/extension.go` (3), `exts/proxy/extension.go` (15), `pkg/config/options.go` (12), `pkg/harness/base.go` (11)
  - tests and docs: `docs/configuration.md`, `exts/observe/extension_test.go`
  - the options.go figure includes the P6 capture-mode flag (12; was 11 through the E3 round)
- **fence section migration (已决 15/19/20)**
  - hooks: `pkg/config/resolved.go` (4), `pkg/config/sections.go` (14)
- **#38 evaluator usage accounting**
  - hooks: `agent/evaluator/evaluator.go` (20), `agent/evaluator/loop.go` (13), `agent/provider/anthropic.go` (3), `agent/provider/openai.go` (12)
  - tests and docs: `agent/evaluator/loop_test.go`
- **#39 aopws close frame**
  - hooks: `pkg/aopws/stream.go` (20)
  - tests and docs: `pkg/aopws/stream_test.go`
- **#40 ioa send refuses its own session**
  - hooks: `tools/ioa/commands.go` (19)
  - tests and docs: `exts/ioa/client/assets/cyber/okf/runtime/ioa-send.md`, `tools/ioa/commands_test.go`
- **#41 TLS version switch and POSIX drive paths**
  - hooks: `core/tool/run_command.go` (7), `tools/curl/client.go` (14), `tools/curl/curl.go` (2), `tools/curl/parse.go` (16), `tools/terminal/bash.go` (3)
  - tests and docs: `core/tool/run_command_test.go`, `tools/curl/client_test.go`
- **#42 lint and formatting**
  - hooks: `core/tool/run_command_windows.go` (2)
  - tests and docs: `aop/mux_lifecycle_test.go`, `exts/scanner/prompt_cyber_test.go`, `exts/scanner/skills/skills_test.go`
- **#43 the MCP alias bash-conflict rule is one function**
  - hooks: `exts/mcp/extension.go` (2)
- **fork notes**
  - tests and docs: `README.md`, `README_CN.md`
- **dependencies** — the chainreactors modules resolve to the c1ayooo forks; the audit module follows patch 24
  - manifests: `cmd/audit/go.mod`, `cmd/audit/go.sum`, `go.mod`, `go.sum`
- **build convergence (4zdesign/19 §7, P4)** — the engine/scan targets the shell forwards to, make resources, make check-fork
  - manifests: `Makefile`

`scripts/check-fork.sh` itself lives in a directory upstream ignores
(`.gitignore` has `/scripts/`), so it is tracked by force-add and updated with
`git add -u`. The negation the fork once added to `.gitignore` cannot re-include a
file whose directory is excluded; it is removed, and `.gitignore` is upstream again.


- **P6 scan assembly moved (2026-11-28)**
  - hooks: `cmd/cyber-scan/main.go`
  - tests and docs: `.github/workflows/ci.yml`, `.github/workflows/scanner-regression.yml`, `pkg/internal/architecture/architecture_test.go`
- **4ztemplates: the rules source is the fork's maintenance branch (2026-11-28)**
  - manifests: `.gitmodules`, `tools/templates`
  - generated data: `tools/proton/resources/data/found_filter_dir.bin`, `tools/proton/resources/data/found_keys.bin`, `tools/proton/resources/data/found_spray.bin` (written by `make resources`, 4zdesign/19 §5.3)
- **Rule hot reload borrows the live engine set (2026-11-28, 4zrcin docs/rules.md)**
  - hooks: `exts/scanner/extension.go`
- **fork rules appended to AGENTS.md (2026-11-28)**
  - tests and docs: `AGENTS.md`
  - the upstream 20 lines are untouched; a "4z fork" section is appended at
    the end so coding agents — which auto-read only the root AGENTS.md — see
    the fork's red lines where they actually read. Rollback: delete the
    appended section.

### Upstream files moved into fork-owned packages

Whole upstream files relocated into a fork-owned package (4zdesign/19 P6). Their upstream
path is registered here so `scripts/check-fork.sh` can tell a deliberate move from an
accidental deletion; the content is upstream's plus the registered hooks, byte for
byte apart from the package clause. A merge with upstream follows the rename and lands
an upstream change on the new path.

`cmd/cyber-scan` → `pkg/assembly` (the scan command's assembly, 2026-11-28):

- hooks: `cmd/cyber-scan/agent_transport.go`, `cmd/cyber-scan/browser.go`, `cmd/cyber-scan/bundle.yaml`, `cmd/cyber-scan/bundle_external.go`, `cmd/cyber-scan/bundle_spec_generated.go`, `cmd/cyber-scan/cli.go`, `cmd/cyber-scan/config.go`, `cmd/cyber-scan/config_commands.go`, `cmd/cyber-scan/discovery.go`, `cmd/cyber-scan/extensions.go`, `cmd/cyber-scan/http_serve.go`, `cmd/cyber-scan/inbox.go`, `cmd/cyber-scan/ioa.go`, `cmd/cyber-scan/ioa_composition.go`, `cmd/cyber-scan/mode_profile.go`, `cmd/cyber-scan/modes.go`, `cmd/cyber-scan/pidlock.go`, `cmd/cyber-scan/pidlock_unix.go`, `cmd/cyber-scan/pidlock_windows.go`, `cmd/cyber-scan/profile.go`, `cmd/cyber-scan/record_absent.go`, `cmd/cyber-scan/record_linked.go`, `cmd/cyber-scan/scanner_catalog.go`, `cmd/cyber-scan/scanner_mode.go`, `cmd/cyber-scan/stdio.go`
- tests and docs: `cmd/cyber-scan/architecture_test.go`, `cmd/cyber-scan/bundle_test.go`, `cmd/cyber-scan/cli_fuzz_test.go`, `cmd/cyber-scan/cli_recon_test.go`, `cmd/cyber-scan/cli_test.go`, `cmd/cyber-scan/composition_test.go`, `cmd/cyber-scan/config_commands_test.go`, `cmd/cyber-scan/config_test.go`, `cmd/cyber-scan/gateway_test.go`, `cmd/cyber-scan/http_serve_test.go`, `cmd/cyber-scan/imports_record_test.go`, `cmd/cyber-scan/imports_test.go`, `cmd/cyber-scan/inbox_e2e_test.go`, `cmd/cyber-scan/inbox_test.go`, `cmd/cyber-scan/ioa_test.go`, `cmd/cyber-scan/jev_profile_flow_test.go`, `cmd/cyber-scan/jev_profile_test.go`, `cmd/cyber-scan/manifest_test.go`, `cmd/cyber-scan/modes_test.go`, `cmd/cyber-scan/pidlock_test.go`, `cmd/cyber-scan/profile_test.go`, `cmd/cyber-scan/provider_reload_test.go`, `cmd/cyber-scan/record_declaration_test.go`, `cmd/cyber-scan/scanner_available_test.go`, `cmd/cyber-scan/task_lifecycle_test.go`

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
    4zrcin docs/rules.md), so the host must accept a listener the caller owns and the
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
    The remote capture node's minimal capability set (4zrcin docs/rules.md): fence
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

25. **`feat(node): the capture recipe announces itself in the hello`** (2026-11-26)
    `cmd/cyber-scan/recipe_default.go` / `recipe_capture.go`, `agent_transport.go`.

    4zrcin docs/rules.md's capability routing input: the capture recipe appended
    `scan-capture` to the registration hello's capabilities; the full recipe
    appended nothing, so an absent marker keeps reading as full and every
    binary built before this change routes exactly as it did. The choice is
    now the `--capture-only` runtime flag, per launch. The control
    plane (zrcin 15c4830..) consumes the marker through ListAgents →
    nodeProber.Health → the fleet badge, and keeps implicit dispatch (an
    intent that names no node) off capture-only nodes while honouring an
    explicit operator placement. Verified end-to-end with two local
    processes: the capture node's hello carries the marker, the fleet
    interface reports it, implicit dispatch is refused at 409 with the
    routing reason, and an explicitly placed intent dispatches (202).
    Tests: both recipe forms green. Rollback: revert — full form is
    byte-identical in behavior.

24. **`feat(tools): the capture recipe - resources and engines compile out`** (2026-11-26)
    `tools/resources/` (two-file mode), `cmd/cyber-scan/` (recipe split), test
    forms.

    - **Resources two-file mode** (4zrcin docs/rules.md): `template.go` (the generated
      472K engine-template bundle) gained a recipe build tag, and an empty
      twin `resources_empty.go` provided the same single private
      `loadEmbeddedConfig` returning nil for the stripped build — the public
      surface (`Init/Set/Config`) untouched and every consumer compiling
      unchanged. The generator emitted the tag, so re-syncing could not drop
      it. `guardrail_builtin_gen.go` stayed tag-free: the guaranteed audit
      corpus ships in every binary form. `resources_test.go` was excluded
      from the stripped build (it asserts embedded-bundle behavior).
      Superseded: the recipes are runtime modes now and this plumbing is
      deleted.
    - **Engine recipe boundary** (4zrcin docs/rules.md): the scan-capture binary
      compiled an empty engine block — `engineExtensions` had a full twin and
      an empty twin, and `discovery.go`/`scanner_catalog.go` gained empty
      capture twins, so the scanner/proton/discovery extension packages and
      the gogo/spray/zombie/neutron/katana chains behind them never linked
      into that build. Measured at the time: full scan 185 MB -> capture
      158 MB (-15%). The traffic proxy, the guardrail (with the guaranteed
      audit) and the evidence sidecars stay. The hub connection still
      resolves through `CYBER_CYBERHUB_*` env/config; the CLI flag groups
      owned by the engine extensions were compiled out with them. Superseded:
      the empty block is a runtime skip now
      (`--capture-only`), the binary keeps its size from the linker-level
      twins' removal, and the flag surface is the full catalog in both modes.
    - **Test forms**: the CLI/scanner-catalog test files that assert the full
      recipe's surface were excluded from the capture build (that binary
      genuinely had no `scan` subcommand or scanner catalog); shared test
      helpers moved to an untagged `cli_helpers_test.go`;
      `TestScannerManifestTags` unchanged (the noconsole smoke stays
      build-only, as the gate designed). Also fixed the pre-existing
      `cmd/audit` module's stale go.sum (its own module; a tidy was missing
      after the fingers bump).
    Tests: green for the touched packages in every build form of the time;
    full tree built in all three. Rollback: revert — the default build never
    changes.

25. **`docs(fork): the control plane is zrcin`** (2026-11-26)
    `FORK.md` only — no harness code changes.
    The 4zrcin repository renamed its identity (`cmd/tw` → `cmd/zrcin`,
    `TW_*` env vars → `ZRCIN_*`, the per-project `.tw` metadata directory →
    `.zrcin`, theme utility prefix `tw-*` → `zrcin-*`). This file's prose and
    the `cmd/tw-gate` sync command were updated to match; the fork module
    (`github.com/c1ayooo/cyber`), the branch name (`tianwu/fixes`) and the
    legacy `tianwu.*` type URLs stay as they are — patch 20 keeps both
    extension namespaces recognized. Patch numbers 22/23 are reserved for the
    control plane's embedding work (webhost `Listener`, 4zdesign/03 §11 P5); 24
    is the egress proxy.

26. **`feat(session): a turn seed materialises the case for nodes without a shared filesystem`** (2026-11-26)
    `agent/session/protocol.go`, `agent/session/seed.go` (new), `agent/session/session.go`,
    `agent/session/seed_test.go` (new).
    A control plane on another machine cannot expect the node to see its case directory, and
    prompts reference those paths. `RunTurnRequest` gains the `4zrcin.CaseSeed` fork extension
    (JSON-in-Any, both `tianwu.*`/`4zrcin.*` namespaces recognized like WorkDir):
    `{"files":[{"path":".zrcin/context.json","mode":420,"data":"<base64>"}]}` with paths
    relative to the turn's workspace. `executeRun` applies the seed after `applyTurnWorkDir`
    and before the turn runs: parent directories created, files written atomically (temp +
    rename), mode masked to permission bits (default 0600). Safety: absolute paths, `..`
    segments and existing symlinked ancestors are refused; a seed without a workspace fails
    the turn; limits mirror artifactsync (8 MiB per file, 16 files / 64 MiB per request).
    A malformed payload rejects the turn at `RunTurn` ("FAILED_PRECONDITION") instead of
    silently dropping the inputs. An absent extension changes nothing.
    Tests: `go test ./agent/session -run 'TestTurnCaseSeed|TestApplyCaseSeed' -count=1`
    (both namespaces, apply/modes, escapes/absolute/symlink, limits, missing workspace).
    Rollback: revert — old control planes never send the extension.

27. **`feat(artifactsync): the handoff files ship, everything else under .zrcin stays private`** (2026-11-26)
    `core/artifactsync/artifactsync.go`, `core/artifactsync/artifactsync_test.go` (new),
    `exts/observe/artifact_internal_test.go`.
    `skipsArtifact` used to exclude the whole `.zrcin` directory. A node without a shared
    filesystem never got its declared facts or notes back, so the control plane's ledger ingest
    could not settle the run. The rule is now default-deny: only `.zrcin/facts.jsonl` and
    `.zrcin/worker-note.md` ship; `auth`, `identity.json`, `aop-session.json`, offsets,
    cursor-repair files and any future file stay excluded, and nothing nested deeper ships.
    Tests: `go test ./core/artifactsync ./exts/observe -count=1` (table over the allowlist;
    the sidecar round trip now ships the two handoff files and still refuses `auth`).
    Rollback: revert — old nodes never enable the `artifacts` kind, and the two extra files
    are plain sidecars the control plane may ignore.

28. **`feat(observe): the artifacts kind is self-sufficient`** (2026-11-26)
    `exts/observe/extension.go`, `exts/observe/artifact_internal_test.go`,
    `pkg/config/options.go`.
    `--observe artifacts` parsed but subscribed to no hook: the sidecars ride the
    process-completion snapshot diff and the in-band file writes, which were only subscribed
    for the `processes`/`files` kinds, so an artifacts-only node shipped nothing. `artifacts`
    now subscribes to those hooks itself and emits a carrier event only when it actually
    carries artifacts (a completion that changed nothing publishes no event); the file hook
    likewise publishes its observation only when the kind asks for observations or the write
    carries sidecars. Existing combinations (`processes,artifacts`, `files,artifacts`,
    `processes,files,artifacts`) keep their exact behaviour. The `--observe` help text lists
    `artifacts`.
    Tests: `go test ./exts/observe -run 'TestArtifacts' -count=1` (the full matrix plus an
    artifacts-only case: carrier with sidecars on change, nothing on a no-op completion).
    Rollback: revert — the flag was inert alone, so no working configuration changes.

29. **`feat(scoperules): one domain row covers the bare host and every subdomain`** (2026-11-26)
    `core/scoperules/scoperules.go`, `core/scoperules/scoperules_test.go`.
    The control plane's fence moves to allowlist semantics (4zrcin spec #1): a domain row
    must fence the domain itself, not only its subdomains. `hostMatches` now strips the
    legacy `*.`/`.` prefixes and compares bare-host-or-subdomain, so an exact host row, a
    `*.host` row and a `.host` row all match the identical set — the control plane
    canonicalizes those spellings onto the bare domain on save and the engine agrees. The
    base-host exclusion the wildcard forms used to carry is deliberately gone. The row cap
    rises to 512 (`maxRules`), mirroring the control plane's raised `MaxScopeRules`.
    Also fixed a latent test bug: `manyRules` closes the JSON array itself, so the old
    "too many rows" case appended a second `]}` and failed on JSON syntax instead of the
    row cap — the cap had never actually been exercised.
    Tests: `go test ./core/scoperules ./exts/guardrail -run TestJudgeScope
    ./tools/proxy -run TestScopeJudge -count=1` (host-form table over the three spellings
    in/out/leak/suffix-domain; the 512-row set parses, 513 is refused; the guardrail and
    proxy judge suites stay green under the new semantics).
    Rollback: revert — the control plane still sends rows the previous engine judges
    (exact-host rows just fence fewer requests), and no wire shape changes.

30. **`feat(scoperules): the default miss refuses and carries default_missed`** (2026-11-26)
    `core/scoperules/scoperules.go`, `core/scoperules/scoperules_test.go`,
    `exts/guardrail/scoperules.go`, `exts/guardrail/scoperules_test.go`.
    The allowlist fence's fallback is fixed (4zrcin spec #1 工单5): out-of-range
    traffic is refused and the ASSET — not the request — goes to the operator.
    `Verdict` gains `default_missed` (JSON, absent on a hit and on every
    pre-patch sidecar), set by `Judge` on the fallback branch; `JudgeScopeRequest`
    routes a default miss through the quiet path (sidecar only, no hold, no
    Decision/Review event) instead of the pending-review lifecycle. Holding
    was wrong three ways: it blocked the whole run for a decision that cannot
    admit the asset, a concurrent twin was refused anyway, and approving one
    request left the asset out of range. Explicit rule rows keep their
    event-backed hold (review) and refuse (block) semantics — those are
    verdicts the operator wrote by hand. The traffic sidecar JSON gains the
    optional flag; old control planes ignore it.
    Tests: `go test ./core/scoperules ./exts/guardrail ./tools/proxy -count=1`
    (the miss marks the flag and refuses immediately without events; the
    explicit review row still holds and resolves, sidecar without the flag;
    the no-operation-id refusal now exercises an explicit row; proxy and
    session suites unchanged).
    Rollback: revert — misses go back to holding on the pending lifecycle,
    and the control plane's flag-based routing simply never fires.

31. **`feat(globalfence): the instance's red lines fence every project`** (2026-11-26)
    `core/globalfence/` (new), `core/scoperules/scoperules.go` (+ `HostMatches`
    export, `JudgeConnect`, `JudgeSessionConnect`, `JudgeConnectHostForm` test),
    `agent/session/protocol.go` (+ `turnGlobalFence`, both namespaces),
    `exts/guardrail/{runtime.go,scoperules.go,scoperules_test.go}`,
    `tools/proxy/{hub.go,mitm.go,scope_judge_test.go}`.
    The instance fence (4zrcin spec #1 工单3): command patterns that never
    execute and domains that are never reached, on every project and node the
    instance drives. The control plane sends the set every turn as
    `4zrcin.GlobalFence` (both namespaces); the session registers it per
    session like the project scope rules, so a save takes effect next round
    without a restart and remote nodes are covered like any fence.

    - **Command deny** judges in `Admit` after the guaranteed audit and before
      every policy concern: a `deny` red line refuses even with no provider
      (its Decision event carries the `global.<id>` reason prefix the control
      plane badges); a `review` red line holds the call on the ordinary
      approval lifecycle. Uncompilable patterns are refused at registration —
      a pattern that failed at match time would silently stop fencing.
    - **Domain deny** wins before the project fence in `JudgeScopeRequest`:
      a project row allowlisting a denied domain still cannot reach it. The
      refusal publishes a Decision (hits are rare; the audit row is worth its
      journal line) and the sidecar names `global:<id>`.
    - **CONNECT tunnels** gain `JudgeConnect` (the `ScopeJudge` interface
      grows the method): the instance fence judges fully; the project fence
      judges its host form only — rows match on host alone (a method/path row
      refines decrypted inner requests, not the tunnel), CIDR rows match
      literal IPs directly and hostnames through the cached resolver, and an
      unmatched tunnel refuses under the allowlist default instead of passing
      unjudged. In relay mode this host-form pass/fail IS the fence.
    Domain matching delegates to the exported `scoperules.HostMatches`, so a
    domain row in either list means the identical thing to the matcher. Old
    control planes never send the extension; absent sets fence nothing.
    Tests: `go test ./core/globalfence ./core/scoperules ./exts/guardrail
    ./tools/proxy ./agent/session -count=1` (parse/switch/idempotency/
    unknown-session table; command deny+review through `Admit` with the
    resolve dance; global-domain wins over a project allowlist; CONNECT
    host-form table and the tunnel refusal paths).
    Rollback: revert — no extension is sent, nothing registers, and every
    judge path is byte-identical to before.

32. **`feat(webshell): manage shells through the control plane's ledger`** (2026-11-26)
    `cmd/cyber-scan/extensions.go`, `go.mod` (requires the standalone
    `github.com/c1ayooo/4zwebshell` module: `webshell/` protocol library,
    `tools/` typed tools, `extension/` assembly).
    The scan product installs a webshell tool set (`webshell_list`,
    `webshell_register`, `webshell_exec`, `webshell_files`, `webshell_info`,
    `webshell_remove`). The ledger and the sealed credential live in the
    control plane; the tools read one shell's connection material from the
    participant API with the run's own identity (`$ZRCIN_AGENT` /
    `$ZRCIN_AUTH` — the same face that already hands out access material) and
    run the operation in the scan process, so the traffic leaves the node that
    hosts the run. What an operation observed is posted back to the ledger.
    A turn without a session identity makes the tools unavailable rather than
    guessing a URL.
    The protocol is not copied into this fork: the module is the one source,
    and both 4zrcin and this fork consume it through a local `replace`.
    Tests: `go test github.com/c1ayooo/4zwebshell/...` (protocol, sealing, the
    tool face against a fake control plane and a fake target shell).
    Rollback: drop the extension line and the `require`/`replace` from
    `go.mod`; no other package imports the module.

33. **`feat(scoperules): the verdict travels verbatim, and child sessions inherit the fence`** (2026-11-26)
    `tools/proxy/{hub.go,mitm.go,scope_judge_test.go}`, `exts/guardrail/{scoperules.go,scoperules_test.go}`,
    `core/scoperules/{scoperules.go,scoperules_test.go}`, `core/globalfence/{globalfence.go,globalfence_test.go}`,
    `agent/subagent/sessionexec/tool.go`.
    The judge's answer reaches the traffic sidecar whole. `proxy.ScopeDecision` gains `Verdict`
    (`*scoperules.Verdict`); `judgeRequest` records the judge's own verdict under the canonical
    flow id instead of reconstructing `{action, rule_id, reason}` from the decision — which is
    exactly what dropped `default_missed` on the wire and silently disabled the control plane's
    asset-pending flow for real traffic (the flag existed only in synthetic tests). A judge that
    answers without a `Verdict` (stub judges) reconstructs the old three fields byte-identically.
    Also fixes the patch-31 assembly slip: `exts/proxy` did not compile — the `ScopeJudge`
    interface demanded `JudgeConnect` while the judge implemented `JudgeScopeConnect`; the
    interface and the call site now say `JudgeScopeConnect`.
    Child sessions inherit the fence. The control plane registers per session at `RunTurnRequest`
    time, a channel the subagent tool's freshly minted session ids never see, so a delegated
    direction judged nothing. `scoperules.InheritSessionRules` / `globalfence.InheritSessionRules`
    copy the parent's parsed set to the child slot at session open (read-only after Parse; an
    unregistered parent inherits nothing); a child living across a rule edit keeps the set it was
    born with, which is the honest reading of "registered for that session".
    Tests: `go test ./core/scoperules ./core/globalfence ./exts/guardrail ./tools/proxy ./agent/session ./agent/subagent/... ./exts/proxy -count=1`
    (a real proxied default miss keeps `default_missed` in the sidecar; the bare-stub
    reconstruction is unchanged; inherit tables in both core packages; the miss decision carries
    the verdict verbatim).
    Rollback: revert — decisions carry no `Verdict`, the proxy reconstructs as before, and
    delegated directions fence nothing again.

34. **`feat(scoperules): a page's own static subresources pass the allowlist fallback`** (2026-11-26)
    `tools/proxy/mitm.go`, `core/scoperules/scoperules.go`, `exts/guardrail/{scoperules.go,scoperules_test.go}`,
    `tools/proxy/scope_judge_test.go`.
    Under the allowlist fence every third-party script, stylesheet, image or font a page pulls by
    itself queued a pending asset the operator had to wave through. The synthetic call now carries
    the request's `Sec-Fetch-Dest` as a passive hint; a default miss on a passive request
    (`script`/`style`/`image`/`font`) is rewritten to `{record, passive}` — forwarded, journaled in
    the traffic view, never routed to the approval flow. Explicit rule rows and the instance fence
    keep full semantics; navigations (`document`) and API calls (`empty`) stay deliberate, and a
    client without the header (curl, wget) is never passive. The synthetic 403 body now also names
    the verdict reason and a `pending` flag, so the model reading its tool output can stop retrying
    an unadmittable host without a round trip.
    Tests: same command (passive miss records without events; an explicit block row beats the
    passive hint; a deliberate request under the same rules stays a miss; the refusal body carries
    reason and pending).
    Rollback: revert — passive subresources queue pending assets again and refusals return to the
    bare `error`/`host` body.

35. **`feat(guardrail): command red lines judge command-like calls only`** (2026-11-26)
    `exts/guardrail/runtime.go`, `exts/guardrail/scoperules_test.go`.
    The instance fence's command patterns matched every tool call's argument text: a write tool
    whose content quoted a blocked command held the call for review — every report mentioning
    `rm -rf /` became a pending approval. A red line is a statement about commands; `Admit` now
    judges the command lists only when the call IS one — a bare string argument, or an object
    carrying one of the documented command fields (`command`/`cmd`/`script`/`input`/`code`,
    matched the way encoding/json fills a tool's own field: keys fold case, a later key
    overrides an earlier one — the exact-key lookup this entry first shipped let
    `{"Command":"rm -rf /"}` execute past every red line; closed r10 lane D).
    The guaranteed builtin audit stays unconditional (it records, it does not judge).
    Tests: same command (the write-tool negative through `Admit` — no denial, no events — beside
    the bare-string positive; the existing command fence dance keeps passing).
    Rollback: revert — patterns judge every tool call's text again.

36. **`fix(proxy): the control plane's own calls are platform plumbing`** (2026-11-26)
    `tools/proxy/{hub.go,mitm.go,scope_judge_test.go}`, `exts/proxy/extension.go`,
    `cmd/cyber-scan/profile.go`.
    Under an enforced allowlist fence every attributed request missed the rule
    table unless the target was on it — including the executor's own
    bookkeeping calls to the control plane (`POST /api/intents/{id}/run`, the
    facts API): the pre-patch-30 judge held each one for review, so a
    direction spent its whole turn feeding the operator an endless approval
    queue, one approved call per step. The proxy now knows the control
    plane's host — the agent server URL's host, wired through the proxy
    extension config — and treats requests naming it as platform plumbing:
    forwarded unjudged and uncaptured, before any judge or capture state
    exists (capturing them leaked their Authorization headers into the
    traffic view). When the control plane itself lives on loopback, the whole
    loopback family counts as the platform; a public control-plane host
    matches exactly. Deliberate: a deny row naming the control plane cannot
    take effect through the proxy — the platform must always reach itself
    (the fence is a statement about the target range; 4zrcin docs/architecture.md §10.10 already
    defers node isolation).
    Tests: `go test ./tools/proxy ./exts/guardrail ./exts/proxy ./agent/session ./agent/subagent/... ./core/scoperules ./core/globalfence -count=1`
    (an exempted call forwards 200 with an empty flow store and no sidecar;
    a node without that control plane still refuses the same host; every
    pre-existing judge test keeps passing).
    Rollback: revert — the executor's own calls are judged like target
    traffic again.

37. **`feat(globalfence): the default-allow list — infrastructure the operator always permits`** (2026-11-27)
    `core/globalfence/{globalfence.go,globalfence_test.go}`,
    `exts/guardrail/{scoperules.go,scoperules_test.go}`.
    The fence's order is deny → project → fallback, which made every
    infrastructure name the executor legitimately reaches — DNS/DoH
    endpoints, passive intel sources like crt.sh — queue a pending asset per
    project, per spelling, forever. The instance fence gains an allow
    domain list (`enabled_allow_domains` / `allow_domains`, same host
    shapes as the deny list): judged after the deny list and before the
    project fence, a hit is recorded and forwarded with the
    `global.allow:<id>` sidecar — no Decision event, no pending asset, no
    hold. The deny list still wins when both name the host: a red line is a
    statement about the target range and outranks infrastructure. Child
    sessions inherit the allow list with the rest of the fence.
    Tests: `go test ./core/globalfence ./core/scoperules ./exts/guardrail ./tools/proxy ./agent/session -count=1`
    (allow hit + subdomain coverage; deny outranks allow on the same name;
    the disabled switch judges nothing; the guardrail judge records the
    global-allow sidecar before the project fence).
    Rollback: revert — infrastructure names queue pending assets again.

38. **`fix(evaluator): count evaluator tokens in run usage`** (2026-11-20, follow-up 2026-11-21)
    `agent/evaluator/evaluator.go`, `agent/evaluator/loop.go`, `agent/evaluator/loop_test.go`,
    `agent/provider/openai.go`, `agent/provider/anthropic.go`.
    The evaluator's model calls cost tokens that the turn's usage never
    counted, so a control plane accounting per run underreported every
    evaluated run. Evaluate/call now return usage; retries within one
    evaluation add up, the failure path is accounted too, and finish
    overwrites TotalUsage once. Two nil results stay nil: nothing invents a
    0. The follow-up records `usage_missing` in the turn usage detail when
    the evaluator's answer carries no usage, and a 64-bit fingerprint of
    the answering model as `eval_model_hash` — a missing entry and a fix
    that did not run looked identical. Observation only; the accounting
    semantics are unchanged. The two provider adapters carry the matching
    change. Tests: `go test ./agent/evaluator ./agent/provider -count=1`.
    Rollback: revert — evaluator tokens leave the run usage again.

39. **`feat(aopws): a close frame with a fixed reason before the connection closes`** (2026-11-20)
    `pkg/aopws/stream.go`, `pkg/aopws/stream_test.go`.
    The commit carries no body; this entry is read from the control plane's
    contract (4zrcin docs/architecture.md §7). A turn whose connection drops before
    `turn_ended` fails, and the error has to say who closed it. The writer
    now sends one close frame carrying a fixed enumerated reason before it
    closes; the client keeps the code and the text instead of collapsing
    them into EOF. One extra frame per connection teardown; no new fields,
    nothing enters the run journal. The control plane marks the
    host-closed case as implemented and awaiting a live confirmation.
    Tests: `go test ./pkg/aopws -count=1`. Rollback: revert — a host-side
    close reads as a transport error again.

40. **`fix(ioa): ioa send refuses its own session; the direct send can be switched off`** (2026-11-22)
    `tools/ioa/commands.go`, `tools/ioa/commands_test.go`,
    `exts/ioa/client/assets/cyber/okf/runtime/ioa-send.md`.
    A session could `ioa send` to itself. `send` now fails when the
    recipient is the current session and asks for another one.
    `CYBER_IOA_SEND_DISABLED=1` (environment or session tool env) turns the
    direct send off, which is how the control plane routes communication
    through its own ledger. The `ioa-send` document now states that the
    first argument is the recipient and that the current session is the
    sender. Tests: `go test ./tools/ioa -count=1`. Rollback: revert.

41. **`fix(curl,bash): TLS version switch and POSIX drive paths`** (2026-11-20)
    `core/tool/run_command.go`, `core/tool/run_command_test.go`,
    `tools/curl/curl.go`, `tools/curl/parse.go`.
    The built-in curl did not accept `--tlsv1`, `--tlsv1.0` … `--tlsv1.3`; it
    now sets the minimum handshake version the way real curl does and still
    rejects an unknown version. On Windows, bash maps `/c/...` to `C:\...`
    only for the program name and leaves ordinary arguments alone.
    `tools/curl/client.go` and `tools/curl/client_test.go` carry part of
    this change and are listed with #3. Tests:
    `go test ./core/tool ./tools/curl -count=1`. Rollback: revert.

42. **`chore(lint): lint findings and formatting`** (2026-11-24)
    `core/tool/run_command_windows.go`, `aop/mux_lifecycle_test.go`,
    `exts/scanner/prompt_cyber_test.go`, `exts/scanner/skills/skills_test.go`.
    A `#nosec G702` justification on the fixed `taskkill` fallback, and
    spelling or alignment in three tests. No behavior. Rollback: revert.

43. **`refactor(mcp): the alias bash-conflict rule is one function`** (2026-11-28, 4zrcin P2 / 4zdesign/19 已决 20)
    `exts/mcp/extension.go`, fork-owned additions `exts/mcp/alias.go`, `exts/mcp/alias_test.go`.
    Cause: the rule lived only inside `Extension.Load`, so a control plane that
    edits MCP configuration (4zrcin's settings save) accepted aliases the scan
    then refused at node start ("conflicts with a bash builtin or keyword").
    The check moves to the exported `ValidateBashAlias` (fork-owned file, pure
    addition) and `Load` calls it; the check and its error text are unchanged.
    Regression: upstream's `TestAliasRejectsBashNamespaceConflictsBeforeConnecting`
    passes unchanged, and `go test ./exts/mcp -run TestValidateBashAlias` pins
    the helper. Rollback: inline the check in `Load` again and delete the two
    new files.

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

A full `go test ./...` also shows failures that predate the current work
and depend on the machine, not on the code:

- `cmd/harness`: `TestUserOrderLabFixtureContract` and
  `TestUserIOALongTaskRuntimeSmoke` shell out to `python`; a machine with
  only `python3` fails both.
- `tools/arsenal`: the `TestE2E_*` suite downloads tools from GitHub
  releases and fails without that network path.
- `tools/curl`: `TestOutputToMissingScratchDirectory` and
  `TestCookieJarToMissingScratchDirectory` fail on Linux since b5a7c19d —
  the absolute `/tmp` output path is written where it says instead of the
  session scratch directory. Open.

## Build and deploy

Use the [4zrcin build scripts](https://github.com/c1ayooo/4zrcin)
with the same fork checkout for the Hub and scan binaries. The scripts select
platform tags and build `cmd/cyber-harness` and `cmd/cyber-scan`. Pass the
directory of a review worktree explicitly when checking an upstream merge.

Record the fork commit with the build. Deployment and rollback
use [4zrcin's deployment guide](https://github.com/c1ayooo/4zrcin/blob/main/docs/deploy.md).

## Rule

Confirm whether a bug belongs to the caller, the protocol contract or the fork.
For each patch, record the cause, regression test and rollback notes in its commit.

Rules for every change to this fork, whoever makes it:

- **Upstream's existing files carry registered hooks only.** A hook is at
  most 20 added lines (tests, docs and golden files are left out of the
  count but still registered; `go.mod` and `go.sum` are accounted line by
  line). The logic lives in fork-owned files: `exts/4z*`, `pkg/assembly`,
  `aop/payloads`. Register each changed upstream file by exact path under
  "Local patches"; a whole upstream file moved into a fork-owned package is
  registered under "Upstream files moved into fork-owned packages". `make check-fork` prints the verdict table;
  `make check-fork STRICT=1` fails on an unregistered file or an over-budget
  hook. No upstream file is over budget today; `make check-fork STRICT=1`
  is what holds it there.
- **Add to the protocol, never change it.** New payloads go into new files
  or anypb sidecars; upstream messages stay as they are.
- **State travels through the extension.** Pass it with `Provide`/`Use` on
  the scope, keep it on the extension instance, and clear it when the
  extension closes.
- **Compose 4z behaviour in the product root.** Today only the scan command
  passes the 4z blocks, through its assembly in `pkg/assembly`; `cmd/agent`
  and `cmd/audit` compose none.
- **Before pushing, run the full `go test ./...`** and compare the result
  with the failures listed under "Tests": those predate the work, anything
  else is a regression. A change to fence admission also passes
  `scripts/acceptance/fence-parity.sh` in the 4zrcin checkout, every verdict
  identical to the baseline.
