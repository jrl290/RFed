#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Build and package local RFed release archives for one or more targets.

Usage:
  ./scripts/build-rfed-release-set.sh --version VERSION [--target ASSET_TARGET ...] [--output-dir DIR]

Targets:
  darwin-arm64
  linux-x86_64
  linux-arm64

Examples:
  ./scripts/build-rfed-release-set.sh --version v0.1.0 --target darwin-arm64
  ./scripts/build-rfed-release-set.sh --version v0.1.0 --target linux-x86_64 --target linux-arm64
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

version=""
output_dir="${repo_root}/dist"
declare -a asset_targets=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "Missing value for --version" >&2; exit 1; }
      version="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || { echo "Missing value for --target" >&2; exit 1; }
      asset_targets+=("$2")
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --output-dir" >&2; exit 1; }
      output_dir="$2"
      shift 2
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

[[ -n "${version}" ]] || { echo "--version is required" >&2; exit 1; }

if [[ ${#asset_targets[@]} -eq 0 ]]; then
  case "$(uname -s):$(uname -m)" in
    Darwin:arm64)
      asset_targets=(darwin-arm64)
      ;;
    Linux:x86_64)
      asset_targets=(linux-x86_64)
      ;;
    Linux:aarch64|Linux:arm64)
      asset_targets=(linux-arm64)
      ;;
    *)
      echo "Cannot infer a default release target for host $(uname -s):$(uname -m); pass --target explicitly" >&2
      exit 1
      ;;
  esac
fi

ensure_target_installed() {
  local rust_target="$1"
  if ! rustup target list --installed | grep -Fxq "${rust_target}"; then
    echo "Rust target ${rust_target} is not installed. Run: rustup target add ${rust_target}" >&2
    exit 1
  fi
}

build_and_package() {
  local asset_target="$1"
  local rust_target=""
  local binary_path=""

  case "${asset_target}" in
    darwin-arm64)
      rust_target="aarch64-apple-darwin"
      binary_path="target/${rust_target}/release/rfed"
      ;;
    linux-x86_64)
      rust_target="x86_64-unknown-linux-musl"
      binary_path="target/${rust_target}/release/rfed"
      ;;
    linux-arm64)
      rust_target="aarch64-unknown-linux-musl"
      binary_path="target/${rust_target}/release/rfed"
      ;;
    *)
      echo "Unsupported asset target: ${asset_target}" >&2
      exit 1
      ;;
  esac

  ensure_target_installed "${rust_target}"

  if [[ "${asset_target}" == linux-* ]]; then
    if ! command -v musl-gcc >/dev/null 2>&1; then
      echo "musl-gcc is required to build ${asset_target} locally" >&2
      exit 1
    fi

    local target_env_key
    target_env_key="$(printf '%s' "${rust_target}" | tr '[:lower:]-' '[:upper:]_')"
    env "CARGO_TARGET_${target_env_key}_LINKER=musl-gcc" \
      cargo build --release --target "${rust_target}" -p rfed
  else
    cargo build --release --target "${rust_target}" -p rfed
  fi

  "${script_dir}/package-rfed-release.sh" \
    --binary "${repo_root}/${binary_path}" \
    --version "${version}" \
    --target "${asset_target}" \
    --output-dir "${output_dir}"
}

mkdir -p "${output_dir}"
cd "${repo_root}"

for asset_target in "${asset_targets[@]}"; do
  echo "[release-set] building ${asset_target}"
  build_and_package "${asset_target}"
done

echo "[release-set] archives available in ${output_dir}"