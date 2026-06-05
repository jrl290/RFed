#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Bootstrap RFed sibling dependencies into the path layout expected by Cargo.

Usage:
  ./scripts/bootstrap-sibling-deps.sh [options]

Options:
  --deps-root DIR   Clone dependencies under DIR. Defaults to the parent of RFed-rust.
  --update          Fetch and fast-forward existing clones to the requested ref.
  --dry-run         Print planned actions without changing anything.
  --disable-lxmf-reticulum-default-features
                    Patch LXMF-rust/Cargo.toml to disable Reticulum default features.
                    This matches CI and avoids pulling optional BLE/DBus stacks.
  --help            Show this help.

Environment overrides:
  RETICULUM_RUST_REPO_URL   (default: https://github.com/jrl290/Rusticulum.git)
  LXMF_RUST_REPO_URL        (default: https://github.com/jrl290/LXMF-rust.git)
  APP_LINKS_REPO_URL        (default: https://github.com/jrl290/app-links.git)
  RETICULUM_RUST_REF        Optional branch, tag, or commit.
  LXMF_RUST_REF             Optional branch, tag, or commit.
  APP_LINKS_REF             Optional branch, tag, or commit.
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
deps_root="$(cd -- "${repo_root}/.." && pwd)"
update_existing=0
dry_run=0
patch_lxmf_manifest=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deps-root)
      [[ $# -ge 2 ]] || { echo "Missing value for --deps-root" >&2; exit 1; }
      deps_root="$2"
      shift 2
      ;;
    --update)
      update_existing=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --disable-lxmf-reticulum-default-features)
      patch_lxmf_manifest=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

RETICULUM_RUST_REPO_URL="${RETICULUM_RUST_REPO_URL:-https://github.com/jrl290/Rusticulum.git}"
LXMF_RUST_REPO_URL="${LXMF_RUST_REPO_URL:-https://github.com/jrl290/LXMF-rust.git}"
APP_LINKS_REPO_URL="${APP_LINKS_REPO_URL:-https://github.com/jrl290/app-links.git}"

RETICULUM_RUST_REF="${RETICULUM_RUST_REF:-}"
LXMF_RUST_REF="${LXMF_RUST_REF:-}"
APP_LINKS_REF="${APP_LINKS_REF:-}"

run_cmd() {
  if [[ ${dry_run} -eq 1 ]]; then
    printf '+'
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
  else
    "$@"
  fi
}

checkout_ref() {
  local target="$1"
  local ref="$2"

  [[ -n "${ref}" ]] || return 0

  run_cmd git -C "${target}" fetch --depth 1 origin "${ref}"
  run_cmd git -C "${target}" checkout --detach FETCH_HEAD
}

ensure_clone() {
  local name="$1"
  local repo_url="$2"
  local target="$3"
  local ref="$4"

  if [[ -d "${target}/.git" ]]; then
    echo "[bootstrap] ${name}: already present at ${target}"
    if [[ ${update_existing} -eq 1 ]]; then
      run_cmd git -C "${target}" fetch --depth 1 origin
      if [[ -n "${ref}" ]]; then
        checkout_ref "${target}" "${ref}"
      else
        local current_branch
        current_branch="$(git -C "${target}" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
        if [[ -n "${current_branch}" ]]; then
          run_cmd git -C "${target}" pull --ff-only origin "${current_branch}"
        else
          echo "[bootstrap] ${name}: detached HEAD, skipping pull without an explicit *_REF"
        fi
      fi
    fi
    return 0
  fi

  if [[ -e "${target}" ]]; then
    echo "[bootstrap] ${name}: ${target} exists but is not a git clone" >&2
    exit 1
  fi

  run_cmd git clone --depth 1 "${repo_url}" "${target}"
  checkout_ref "${target}" "${ref}"
}

patch_lxmf_dependency() {
  local manifest="$1"
  local needle='reticulum_rust = { path = "../Reticulum-rust" }'
  local replacement='reticulum_rust = { path = "../Reticulum-rust", default-features = false }'

  [[ -f "${manifest}" ]] || return 0

  if grep -Fq "${replacement}" "${manifest}"; then
    echo "[bootstrap] LXMF-rust manifest already disables Reticulum default features"
    return 0
  fi

  if ! grep -Fq "${needle}" "${manifest}"; then
    echo "[bootstrap] LXMF-rust manifest did not contain the expected dependency line; leaving it unchanged"
    return 0
  fi

  if [[ ${dry_run} -eq 1 ]]; then
    echo "[bootstrap] would patch ${manifest} to disable Reticulum default features in LXMF-rust"
    return 0
  fi

  perl -0pi -e 's|reticulum_rust = \{ path = "\.\./Reticulum-rust" \}|reticulum_rust = { path = "../Reticulum-rust", default-features = false }|' "${manifest}"
  echo "[bootstrap] patched ${manifest} to disable Reticulum default features in LXMF-rust"
}

mkdir_cmd=(mkdir -p "${deps_root}")
run_cmd "${mkdir_cmd[@]}"

ensure_clone "Reticulum-rust" "${RETICULUM_RUST_REPO_URL}" "${deps_root}/Reticulum-rust" "${RETICULUM_RUST_REF}"
ensure_clone "LXMF-rust" "${LXMF_RUST_REPO_URL}" "${deps_root}/LXMF-rust" "${LXMF_RUST_REF}"
ensure_clone "app-links" "${APP_LINKS_REPO_URL}" "${deps_root}/app-links" "${APP_LINKS_REF}"

if [[ ${patch_lxmf_manifest} -eq 1 ]]; then
  patch_lxmf_dependency "${deps_root}/LXMF-rust/Cargo.toml"
fi

echo "[bootstrap] dependency layout ready under ${deps_root}"
echo "[bootstrap] next: cargo build --release -p rfed"