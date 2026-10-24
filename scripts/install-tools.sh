#!/usr/bin/env bash
set -euo pipefail

APKO_VERSION="1.4.4"
MELANGE_VERSION="0.59.1"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir="${1:-${repo_root}/.tools/bin}"
machine="$(uname -m)"

case "${machine}" in
  x86_64)
    release_arch="amd64"
    apko_sha256="dbd9e8f416903b2d896497c51f3217259d03ecb45c997254cedca5274e8671db"
    melange_sha256="90f76f3e5fcb90ddc4c932ad352982bda98d58001d2bcccb982dd7fb2e608a1f"
    ;;
  aarch64|arm64)
    release_arch="arm64"
    apko_sha256="0b4fb47d3b0622e69407d1e5c2db6dc4eca174feced596f0101c62c845e9b0cd"
    melange_sha256="aa5d221f92a248ba9aa490d1441c733417ad4c02f32fa9a13b8800acb42946f9"
    ;;
  *)
    echo "unsupported host architecture: ${machine}" >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
mkdir -p "${install_dir}"

install_release() {
  local project="$1"
  local version="$2"
  local expected_sha256="$3"
  local archive="${project}_${version}_linux_${release_arch}.tar.gz"
  local url="https://github.com/chainguard-dev/${project}/releases/download/v${version}/${archive}"

  curl --fail --location --silent --show-error "${url}" --output "${tmp_dir}/${archive}"
  printf '%s  %s\n' "${expected_sha256}" "${tmp_dir}/${archive}" | sha256sum --check --status
  tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"
  install -m 0755 "${tmp_dir}/${project}_${version}_linux_${release_arch}/${project}" "${install_dir}/${project}"
}

install_release apko "${APKO_VERSION}" "${apko_sha256}"
install_release melange "${MELANGE_VERSION}" "${melange_sha256}"

"${install_dir}/apko" version
"${install_dir}/melange" version
