#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Package an rfed binary into a release archive.

Usage:
  ./scripts/package-rfed-release.sh \
    --binary PATH \
    --version VERSION \
    --target TARGET_NAME \
    [--output-dir DIR]

Example:
  ./scripts/package-rfed-release.sh \
    --binary target/release/rfed \
    --version v0.1.0 \
    --target darwin-arm64
EOF
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

binary_path=""
version=""
target_name=""
output_dir="${repo_root}/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || { echo "Missing value for --binary" >&2; exit 1; }
      binary_path="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "Missing value for --version" >&2; exit 1; }
      version="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || { echo "Missing value for --target" >&2; exit 1; }
      target_name="$2"
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

[[ -n "${binary_path}" ]] || { echo "--binary is required" >&2; exit 1; }
[[ -n "${version}" ]] || { echo "--version is required" >&2; exit 1; }
[[ -n "${target_name}" ]] || { echo "--target is required" >&2; exit 1; }

if [[ ! -f "${binary_path}" ]]; then
  echo "Binary not found: ${binary_path}" >&2
  exit 1
fi

mkdir -p "${output_dir}"

package_basename="rfed-${version}-${target_name}"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/rfed-release.XXXXXX")"
package_dir="${staging_root}/${package_basename}"

cleanup() {
  rm -rf "${staging_root}"
}
trap cleanup EXIT

mkdir -p "${package_dir}"
install -m 755 "${binary_path}" "${package_dir}/rfed"
cp "${repo_root}/config.txt.example" "${package_dir}/config.txt.example"
cp "${repo_root}/README.md" "${package_dir}/README.md"

archive_path="${output_dir}/${package_basename}.tar.gz"
checksum_path="${archive_path}.sha256"

tar -C "${staging_root}" -czf "${archive_path}" "${package_basename}"
(
  cd "${output_dir}"
  shasum -a 256 "${package_basename}.tar.gz" > "${package_basename}.tar.gz.sha256"
)

echo "Created ${archive_path}"
echo "Created ${checksum_path}"