#!/usr/bin/env bash
# Red line 1's machine check (docs/19 §1, appendix E4): every change to an
# upstream-preexisting file must be registered in FORK.md, and every
# registered hook stays within the per-file added-line budget.
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

# Registered upstream files: every backticked path under FORK.md's Local
# patches heading. Additions (A status) are new files and never need
# registration; go.mod / Makefile changes are accounted separately (§1).
registered=$(sed -n '/^## Local patches/,/^## [^L]/p' FORK.md |
  grep -oE '`[a-zA-Z0-9_/.-]+`' | tr -d '`' | sort -u)

fail=0
printf '%-8s %-8s %-6s %s\n' added deleted status path
while IFS=$'\t' read -r added deleted path; do
  [[ "$path" == *.pb.go ]] && continue
  [[ "$path" == "go.mod" || "$path" == "Makefile" ]] && continue
  if grep -qxFe "$path" <<<"$registered"; then
    state=ok
    if (( added > BUDGET )); then
      state="OVER BUDGET (${added} > ${BUDGET})"
      (( STRICT )) && fail=1
    fi
  else
    state="UNREGISTERED"
    (( STRICT )) && fail=1
  fi
  printf '%-8s %-8s %-6s %s\n' "$added" "$deleted" M "$path  [$state]"
done < <(git diff --numstat "$UPSTREAM...HEAD" --diff-filter=M | sort -rn)

if (( STRICT )); then
  exit "$fail"
fi
echo "check-fork: report mode (exit 0). --strict enforces registration and the ${BUDGET}-line budget."
