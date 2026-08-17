#!/usr/bin/env bash
#
# check-sibling-drift.sh — is the rfed you are running built from current code?
#
#   ./scripts/check-sibling-drift.sh                       # check the local debug binary
#   ./scripts/check-sibling-drift.sh --binary /path/to/rfed
#   ./scripts/check-sibling-drift.sh --stamp "rfed=abc123 reticulum=def456 lxmf=... app_links=..."
#
# WHAT THIS EXISTS TO DETECT
# ==========================
# rfed depends on Reticulum-rust, LXMF-rust and app-links as path dependencies
# cloned at build time, and `.github/workflows/build-rfed.yml` triggers only on
# pushes under `rfed/**`. So:
#
#   - a fix committed to Reticulum-rust or LXMF-rust does not rebuild rfed, and
#     never reaches the node, while `git log` in that repo says it is done;
#   - a rebuild triggered by an unrelated rfed change picks up whatever is on
#     those repos' main branches at that moment, sweeping in work nobody was
#     deploying.
#
# The workflow admits the first half in a comment and asks you to remember to
# dispatch a rebuild. The commit history shows how that goes: "ci: pick up
# reticulum_rust d54bb61", "ci: trigger rebuild for reticulum_rust log fix",
# "ci: rebuild for reticulum_rust write-amplification fix" — each one a rebuild
# that had to be remembered, and no way to tell how many were not.
#
# Remembering is not a mechanism. This script turns the question into a number:
# how many commits behind is each dependency in the binary you are actually
# running. Run it before concluding a fix did not work.
#
# To ask a live node instead of a local binary, take its stamp from the startup
# banner (`build: ...`), from `docker run --rm <image> --build`, or from the
# `build` key in its CAPABILITIES response, and pass it with --stamp.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS_ROOT="$(cd "$REPO_DIR/.." && pwd)"

BINARY=""
STAMP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="${2:-}"; shift 2 ;;
    --stamp)  STAMP="${2:-}";  shift 2 ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'

if [[ -z "$STAMP" ]]; then
  if [[ -z "$BINARY" ]]; then
    for candidate in "$REPO_DIR/target/debug/rfed" "$REPO_DIR/target/release/rfed"; do
      [[ -x "$candidate" ]] && BINARY="$candidate" && break
    done
  fi
  if [[ -z "$BINARY" || ! -x "$BINARY" ]]; then
    echo "${RED}✗ no rfed binary found — build one, or pass --binary/--stamp${NC}" >&2
    exit 2
  fi
  STAMP="$("$BINARY" --build 2>/dev/null | tail -1)"
  if [[ -z "$STAMP" ]]; then
    echo "${RED}✗ ${BINARY} does not support --build — it predates the build stamp,${NC}" >&2
    echo "${RED}  which means it is old enough that you cannot tell what is in it.${NC}" >&2
    exit 1
  fi
  echo "${DIM}stamp from ${BINARY}${NC}"
fi

echo "${CYAN}▸ ${STAMP}${NC}"
echo

# component name → repo directory
declare -a NAMES=(rfed reticulum lxmf app_links)
declare -a DIRS=("$REPO_DIR" "$DEPS_ROOT/Reticulum-rust" "$DEPS_ROOT/LXMF-rust" "$DEPS_ROOT/app-links")

BEHIND_TOTAL=0
UNKNOWN=0
DIRTY=0

for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  dir="${DIRS[$i]}"

  built="$(grep -o -E "(^| )${name}=[^ ]+" <<< "$STAMP" | tail -1 | cut -d= -f2)"
  if [[ -z "$built" ]]; then
    printf '  %-12s %s\n' "$name" "${YELLOW}not in the stamp${NC}"
    UNKNOWN=$((UNKNOWN + 1))
    continue
  fi

  was_dirty=0
  if [[ "$built" == *"+dirty" ]]; then
    was_dirty=1
    DIRTY=$((DIRTY + 1))
    built="${built%+dirty}"
  fi

  if [[ "$built" == "unknown" ]]; then
    printf '  %-12s %s\n' "$name" "${YELLOW}unknown — built outside a git checkout${NC}"
    UNKNOWN=$((UNKNOWN + 1))
    continue
  fi

  if [[ ! -d "$dir/.git" ]]; then
    printf '  %-12s %s\n' "$name" "${YELLOW}${built} — no local checkout at ${dir}${NC}"
    UNKNOWN=$((UNKNOWN + 1))
    continue
  fi

  if ! git -C "$dir" cat-file -e "${built}^{commit}" 2>/dev/null; then
    printf '  %-12s %s\n' "$name" "${YELLOW}${built} — not a commit in the local checkout (fetch?)${NC}"
    UNKNOWN=$((UNKNOWN + 1))
    continue
  fi

  head_sha="$(git -C "$dir" rev-parse --short=12 HEAD)"
  behind="$(git -C "$dir" rev-list --count "${built}..HEAD" 2>/dev/null || echo '?')"

  if [[ "$behind" == "0" ]]; then
    printf '  %-12s %s\n' "$name" "${GREEN}${built} — current${NC}"
  else
    printf '  %-12s %s\n' "$name" "${RED}${built} — ${behind} commit(s) behind ${head_sha}${NC}"
    git -C "$dir" log --oneline "${built}..HEAD" | head -8 | sed 's/^/                 /'
    [[ "$behind" -gt 8 ]] && echo "                 ${DIM}… and $((behind - 8)) more${NC}"
    BEHIND_TOTAL=$((BEHIND_TOTAL + behind))
  fi
  if [[ "$was_dirty" -eq 1 ]]; then
    printf '               %s\n' "${RED}built from a dirty tree — this binary matches no commit,${NC}"
    printf '               %s\n' "${RED}so it cannot be reproduced, diffed or rolled back${NC}"
  fi
done

echo
if [[ $BEHIND_TOTAL -eq 0 && $UNKNOWN -eq 0 && $DIRTY -eq 0 ]]; then
  echo "${GREEN}✓ this build contains every local commit${NC}"
  exit 0
fi

if [[ $BEHIND_TOTAL -gt 0 ]]; then
  echo "${DIM}${BEHIND_TOTAL} commit(s) are committed locally but not in this binary. A fix listed"
  echo "above is not running, however finished it looks in git.${NC}"
  echo "${DIM}Rebuild: run the 'Build rfed (Linux)' workflow by hand (workflow_dispatch),"
  echo "since pushes to the sibling repos do not trigger it.${NC}"
fi
[[ $DIRTY -gt 0 ]] && echo "${DIM}A dirty component means the binary matches no commit at all — rebuild from a clean tree.${NC}"
exit 1
