#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grype_bin="${GRYPE_BIN:-${repo_root}/.tools/bin/grype}"
report_dir="${REPORT_DIR:-${repo_root}/dist/security}"

test -x "${grype_bin}"
mkdir -p "${report_dir}"

"${grype_bin}" \
  "purl:${repo_root}/security/alpine-runtime.purls" \
  --distro alpine:3.24 \
  --fail-on negligible \
  --output json > "${report_dir}/alpine-components.json"

"${grype_bin}" \
  "sbom:${repo_root}/security/glibc.cdx.json" \
  --vex "${repo_root}/security/glibc.openvex.json" \
  --fail-on negligible \
  --output json > "${report_dir}/glibc.json"

python3 - "${report_dir}/glibc.json" <<'PY'
import json
import sys

expected = {
    "CVE-2010-4756",
    "CVE-2019-1010022",
    "CVE-2019-1010023",
    "CVE-2019-1010024",
    "CVE-2019-1010025",
    "CVE-2026-0861",
    "CVE-2026-18374",
    "CVE-2026-19499",
    "CVE-2026-19542",
    "CVE-2026-77117",
    "CVE-2026-80489",
    "CVE-2026-8674",
    "CVE-2026-86805",
    "CVE-2026-89092",
    "CVE-2026-95818",
    "CVE-2026-97399",
}

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)

active = {match["vulnerability"]["id"] for match in report.get("matches", [])}
suppressed = {
    match["vulnerability"]["id"] for match in report.get("ignoredMatches", [])
}

if active:
    raise SystemExit(f"active glibc vulnerabilities: {sorted(active)}")
if not expected.issubset(suppressed):
    missing = sorted(expected - suppressed)
    raise SystemExit(f"glibc VEX was not applied to: {missing}")

print(f"glibc scan passed; {len(suppressed)} findings have explicit VEX statements")
PY

