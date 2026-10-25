# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not include secrets or private signing keys in a public issue.

Baseless release images are promoted only after the pinned security gates pass at every severity. Trivy scans the candidate image contents for secrets. Baseless owns an OSV namespace rather than pretending to be Alpine or Wolfi: `security/distro.json` is the package/provenance registry, `security/osv/` is the authoritative advisory feed, and `scripts/baseless_security.py` fails closed when an image contains an unknown Baseless package, a version not covered by the registry, malformed advisory data, or an affected package version.

The stable machine identity is `ID=baseless`, `VERSION_ID=2026.10`, ecosystem `Baseless`, and CPE vendor/product `morningstar-sudo:baseless`. These identifiers are release API: changing one requires a migration plan for the advisory feed, scanner integrations, and downstream policy. `scan/action.yml` exposes the same fail-closed policy to downstream image workflows.

Package registry entries retain all supported historical releases and mark retired releases `eol`; they are never silently deleted. Release CI requires `current_version`, while downstream scans accept any registered `supported` release and reject EOL versions. This lets old image digests remain scannable after a package update without weakening new-release policy.

The Baseless feed is only one layer of the gate. Grype also scans `security/alpine-runtime.purls` using the Alpine 3.24 namespace and `security/glibc.cdx.json` using CPE fallback matching. This continuously discovers upstream findings before they have been triaged into a Baseless advisory. Baseless intentionally omits `ID_LIKE`: upstream provenance is tracked per component and is not a license to scan renamed Baseless packages as though they belonged to another distribution.

Every suppressed glibc finding must have a machine-readable statement in `security/glibc.openvex.json`. Statements identify either the exact stable-branch backport present in the pinned glibc commit or a concrete reason the affected component/code path is absent. New unsuppressed findings fail the build. Downstream applications must reassess contextual VEX statements after adding their own executable code. A clean scan is not proof that an image has no exploitable defect.

The Melange private key is stored only as the Base64-encoded GitHub Environment secret `BASELESS_MELANGE_RSA_KEY_B64` in the `keys` environment. The repository contains only `keys/baseless.rsa.pub`. OCI images are signed keylessly with Cosign through GitHub OIDC.
