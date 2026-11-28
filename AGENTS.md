# Structural Simplification

Prefer deletion over new abstractions. Review the producer, consumers, serialization tags, and tests before changing a type or forwarding function.

## Decision rule

- Remove a private type or function when it only copies fields or forwards one call, has no independent invariant, and its callers can use an existing type or function directly.
- Count the whole change: types, conversions, call sites, imports, branches, and tests. A smaller line count alone is not evidence of a simpler design.
- Keep a boundary when its two sides have different schemas, defaults, validation, ownership, lifetime, concurrency behavior, or external contracts. Examples include config versus runtime options, wire versus domain messages, raw responses versus cached content, and indexed database columns versus stored protobuf JSON.
- Keep adapters required by a dependency's callback signature or a public compatibility contract. A short implementation can still be necessary.
- Keep a small projection when passing the source type directly would expose unrelated fields or create an import dependency in the wrong direction.
- Do not replace deleted layers with generic helpers, aliases, configuration switches, or new DTOs unless they reduce the total concepts and transformations.
- If a helper is used only by tests and has no production contract, test the real path and remove the helper. Preserve behavior tests at the actual boundary.

## Review procedure

1. State what each candidate owns and identify every production caller, including build-tagged code and method values passed as callbacks.
2. Compare field types, tags, zero values, errors, side effects, and ordering before treating two structures as duplicates.
3. Make the smallest deletion that preserves those contracts. Prefer direct calls at the existing composition point.
4. Run focused tests for affected packages and build tags. Record any environment-only test blockers separately from regressions.

## 4z fork (c1ayooo/cyber-harness)

This repository is the 4zrcin fork of cyber-harness. It is upstream plus pure
additions; the rules below keep it that way. Upstream is
[chainreactors/cyber-harness](https://github.com/chainreactors/cyber-harness);
the maintained branch is `tianwu/fixes`. Before changing code, read the patch
registry in `FORK.md` — its "Local patches" section says whether an upstream
file already carries a fork hook — the extension mechanism in
`docs/developer/extensions.md`, which is how the 4z blocks are assembled, and
the product side in
[4zrcin's AGENTS.md](https://github.com/c1ayooo/4zrcin/blob/main/AGENTS.md).

Hard rules (the full list is `FORK.md` under "Rule"):

- Upstream files carry registered hooks only: at most 20 added lines per file,
  with the logic in fork-owned files (`exts/4z*`, `pkg/assembly`,
  `aop/payloads`). Register every changed upstream file by exact path under
  "Local patches".
- Add to the protocol; never change it.
- Pass state through extensions (`Provide`/`Use`), not package-level
  registries.
- Compose 4z behavior only in the product root.
- Before pushing, run the full `go test ./...` and compare against the
  "Tests" section of `FORK.md`. A change to fence admission also runs
  4zrcin's `scripts/acceptance/fence-parity.sh`.
