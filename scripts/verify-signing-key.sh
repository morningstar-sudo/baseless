#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
private_key="${1:-${repo_root}/keys/baseless.rsa}"
public_key="${2:-${repo_root}/keys/baseless.rsa.pub}"
tmp_public="$(mktemp)"
trap 'rm -f "${tmp_public}"' EXIT

test -s "${private_key}"
test -s "${public_key}"
openssl rsa -in "${private_key}" -pubout -out "${tmp_public}" 2>/dev/null
cmp --silent "${tmp_public}" "${public_key}"

echo "signing key matches keys/baseless.rsa.pub"
