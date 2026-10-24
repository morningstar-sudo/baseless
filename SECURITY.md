# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not include secrets or private signing keys in a public issue.

Baseless release images are promoted only after the pinned security gates pass at every severity. Trivy scans the candidate image contents for secrets. Because `ID=baseless` is intentionally a custom and unsupported distro namespace, vulnerability decisions do not rely on Trivy's OS database: Grype instead scans `security/alpine-runtime.purls` using the Alpine 3.24 namespace and `security/glibc.cdx.json` using CPE fallback matching.

Every suppressed glibc finding must have a machine-readable statement in `security/glibc.openvex.json`. Statements identify either the exact stable-branch backport present in the pinned glibc commit or a concrete reason the affected component/code path is absent. New unsuppressed findings fail the build. Downstream applications must reassess contextual VEX statements after adding their own executable code. A clean scan is not proof that an image has no exploitable defect.

The Melange private key is stored only as the Base64-encoded GitHub Environment secret `BASELESS_MELANGE_RSA_KEY_B64` in the `keys` environment. The repository contains only `keys/baseless.rsa.pub`. OCI images are signed keylessly with Cosign through GitHub OIDC.
