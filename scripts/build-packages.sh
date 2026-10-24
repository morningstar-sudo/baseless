#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
arch="${1:-x86_64}"
melange_bin="${MELANGE_BIN:-${repo_root}/.tools/bin/melange}"
signing_key="${MELANGE_SIGNING_KEY:-${repo_root}/keys/baseless.rsa}"

case "${arch}" in
  x86_64|aarch64) ;;
  *)
    echo "unsupported package architecture: ${arch}" >&2
    exit 1
    ;;
esac

test -x "${melange_bin}"
test -s "${signing_key}"
mkdir -p "${repo_root}/packages"

recipes=(
  baseless-baselayout.yaml
  baseless-ca-certificates.yaml
  baseless-tzdata.yaml
  baseless-glibc.yaml
  baseless-debug-tools.yaml
)

for recipe in "${recipes[@]}"; do
  "${melange_bin}" build "${repo_root}/melange/${recipe}" \
    --arch "${arch}" \
    --runner docker \
    --signing-key "${signing_key}" \
    --out-dir "${repo_root}/packages" \
    --log-level "${MELANGE_LOG_LEVEL:-warn}"
done
