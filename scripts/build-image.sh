#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
variant="${1:-static}"
arch="${2:-x86_64}"
output="${3:-${repo_root}/dist/baseless-${variant}-${arch}.tar}"
apko_bin="${APKO_BIN:-${repo_root}/.tools/bin/apko}"

case "${variant}" in
  static|glibc|debug) ;;
  *)
    echo "unknown image variant: ${variant}" >&2
    exit 1
    ;;
esac

test -x "${apko_bin}"
mkdir -p "$(dirname "${output}")"
mkdir -p "${repo_root}/dist/sbom/${variant}-${arch}"

build_date="${BUILD_DATE:-}"
if [[ -z "${build_date}" ]]; then
  build_date="$(git -C "${repo_root}" show -s --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

args=(
  -C "${repo_root}"
  build "apko/${variant}.yaml"
  "baseless:${variant}"
  "${output}"
  --arch "${arch}"
  --build-date "${build_date}"
  --sbom-path "${repo_root}/dist/sbom/${variant}-${arch}"
)

if [[ -n "${APKO_EXTRA_KEYRING:-}" ]]; then
  args+=(--keyring-append "${APKO_EXTRA_KEYRING}")
fi

"${apko_bin}" "${args[@]}"
