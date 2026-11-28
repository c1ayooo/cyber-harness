#!/usr/bin/env bash
# Red line 1's machine check (4zdesign/19 §1, appendix E4): every change to an
# upstream-preexisting file must be registered in FORK.md, and every
# registered hook stays within the per-file added-line budget.
#
# Registration is read from every section between "## Local patches" and
# "## Superseded patches" (exclusive): the dated sections below Local patches
# carry tonight's registrations too.
#
# Files are judged in three classes (已决 24):
#   hook      upstream *.go that is not a test  — registered, and the added
#             lines stay within BUDGET
#   test/doc  *_test.go, or .md/.golden/.yaml/.yml — registered, no budget
#   manifest  go.mod / go.sum / Makefile / .gitmodules / .gitignore /
#             .goreleaser.yml / editions.env (any directory) — registered per
#             entry, no budget
#   generated a regenerated data file (tools/*/resources/data/*.bin, written
#             by make resources from the rules repo) — registered, no budget
#   moved     an upstream file that is deleted or renamed in the fork (a whole
#             file moved into a fork-owned package, 4zrcin 4zdesign/19 P6) — its
#             upstream path must be registered, no budget. A rename is found
#             by similarity, the way a merge follows it
#
# Default mode is report: it prints the verdict table and always exits 0, so
# the current overages surface without breaking the gate while E3/E4 are
# pending. --strict fails on unregistered files or over-budget hooks.
set -uo pipefail

UPSTREAM=${UPSTREAM:-upstream/master}
BUDGET=${BUDGET:-20}
STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

cd "$(git rev-parse --show-toplevel)"

if ! git rev-parse --verify --quiet "$UPSTREAM" >/dev/null; then
  echo "check-fork: $UPSTREAM 不存在，先 git fetch upstream" >&2
  exit 2
fi

# Registered upstream files: every backticked path in any registration section
# from "## Local patches" up to (not including) "## Superseded patches".
# Additions (A status) are new files and never need registration.
registered=$(sed -n '/^## Local patches/,/^## Superseded patches/p' FORK.md |
  grep -oE '`[a-zA-Z0-9_/.-]+`' | tr -d '`' | sort -u)

is_manifest() {
  case "$(basename "$1")" in
    go.mod|go.sum|Makefile|.gitmodules|.gitignore|.goreleaser.yml|editions.env) return 0 ;;
  esac
  return 1
}

fail=0
hook_ok=0 hook_over=0 hook_unreg=0 test_unreg=0 manifest_unreg=0 generated_unreg=0 moved=0 moved_unreg=0
printf '%-8s %-8s %-6s %s\n' added deleted status path
while IFS=$'\t' read -r added deleted path; do
  [[ "$path" == *.pb.go ]] && continue
  if is_manifest "$path"; then
    if grep -qxFe "$path" <<<"$registered"; then
      state="manifest ok"
    else
      state="manifest UNREGISTERED"
      (( manifest_unreg++ ))
      (( STRICT )) && fail=1
    fi
  elif [[ "$path" == */resources/data/*.bin ]]; then
    if grep -qxFe "$path" <<<"$registered"; then
      state="generated ok"
    else
      state="generated UNREGISTERED"
      (( generated_unreg++ ))
      (( STRICT )) && fail=1
    fi
  elif [[ "$path" == *_test.go || "$path" == *.md || "$path" == *.golden || "$path" == *.yaml || "$path" == *.yml ]]; then
    if grep -qxFe "$path" <<<"$registered"; then
      state="test ok"
    else
      state="test UNREGISTERED"
      (( test_unreg++ ))
      (( STRICT )) && fail=1
    fi
  else
    if grep -qxFe "$path" <<<"$registered"; then
      if (( added > BUDGET )); then
        state="hook OVER BUDGET (${added} > ${BUDGET})"
        (( hook_over++ ))
        (( STRICT )) && fail=1
      else
        state="hook ok"
        (( hook_ok++ ))
      fi
    else
      state="hook UNREGISTERED"
      (( hook_unreg++ ))
      (( STRICT )) && fail=1
    fi
  fi
  printf '%-8s %-8s %-6s %s\n' "$added" "$deleted" M "$path  [$state]"
done < <(git diff --numstat "$UPSTREAM...HEAD" --diff-filter=M | sort -rn)

# Upstream files deleted or renamed in the fork: registered by their upstream
# path (4zdesign/19 P6 — the scan command moved into pkg/assembly as whole files).
while IFS=$'\t' read -r status from to; do
  [[ "$from" == *.pb.go ]] && continue
  [[ -n "$to" ]] || to="(deleted)"
  if grep -qxFe "$from" <<<"$registered"; then
    state="moved ok"
    (( moved++ ))
  else
    state="moved UNREGISTERED"
    (( moved_unreg++ ))
    (( STRICT )) && fail=1
  fi
  printf '%-8s %-8s %-6s %s  [%s -> %s]\n' "-" "$status" "$status" "$from" "$state" "$to"
done < <(git diff --name-status -M "$UPSTREAM...HEAD" --diff-filter=DR | sort -k2)

printf 'hooks ok: %d | hooks over budget: %d | hooks unregistered: %d | tests/docs unregistered: %d | manifests unregistered: %d | generated data unregistered: %d | upstream files moved: %d, unregistered: %d\n' \
  "$hook_ok" "$hook_over" "$hook_unreg" "$test_unreg" "$manifest_unreg" "$moved" "$moved_unreg" "$generated_unreg"

if (( STRICT )); then
  exit "$fail"
fi
echo "check-fork: report mode (exit 0). --strict enforces registration and the ${BUDGET}-line budget."
