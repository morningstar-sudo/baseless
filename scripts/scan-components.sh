#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grype_bin="${GRYPE_BIN:-${repo_root}/.tools/bin/grype}"
report_dir="${REPORT_DIR:-${repo_root}/dist/security}"

test -x "${grype_bin}"
mkdir -p "${report_dir}"

# Keep JSON evidence, but also show the findings in the Actions log on failure.
scan_report() {
  local report="$1"
  shift
  local status=0
  "${grype_bin}" "$@" --output json > "${report}" || status=$?
  if [ "${status}" -ne 0 ]; then
    echo "Grype failed (exit ${status}); report: ${report}" >&2
    if [ -s "${report}" ]; then
      jq -r '
        ["PACKAGE", "VERSION", "VULNERABILITY", "SEVERITY", "FIX"],
        (.matches[]? | [
          .artifact.name, .artifact.version, .vulnerability.id,
          .vulnerability.severity,
          ((.vulnerability.fix.versions // []) | join(","))
        ]) | @tsv
      ' "${report}" >&2 || true
    fi
  fi
  return "${status}"
}

scan_report "${report_dir}/alpine-components.json" \
  "purl:${repo_root}/security/alpine-runtime.purls" \
  --distro alpine:3.24 \
  --fail-on negligible

scan_report "${report_dir}/glibc.json" \
  "sbom:${repo_root}/security/glibc.cdx.json" \
  --vex "${repo_root}/security/glibc.openvex.json" \
  --fail-on negligible

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
    "CVE-2026-84243",
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

