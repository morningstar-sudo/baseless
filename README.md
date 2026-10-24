# Baseless

Baseless is a small, auditable distroless base built with Melange packages and assembled by apko. Runtime images contain no package-manager executable and no shell. They run as UID/GID `65532` by default.

## Images

| Tag | Intended workload | Runtime contents |
| --- | --- | --- |
| `static` | Fully static application binaries | filesystem layout, CA bundle, timezone data |
| `glibc` / `latest` | Dynamically linked GNU/Linux application binaries | `static` plus glibc |
| `debug` | Interactive diagnosis only | `glibc` plus BusyBox, curl, jq, OpenSSL, procps-ng; runs as root |

The APK database is intentionally retained as read-only inventory for SBOM generation and vulnerability scanners. It does not make `apk` available inside any image. The production `static` and `glibc` variants have no shell; only the explicitly non-production `debug` variant has one.

Alpine 3.24 is used as a disposable Melange build environment. `baseless-ca-certificates`, `baseless-tzdata`, and the debug tools currently repackage files from pinned Alpine packages; runtime images consume only APKs signed by the Baseless key. glibc is compiled from its pinned upstream Git commit.

## Signing key

Only the public key belongs in Git:

```text
keys/baseless.rsa.pub
```

The private key must be Base64-encoded and stored in the GitHub Environment named `keys` as:

```text
BASELESS_MELANGE_RSA_KEY_B64
```

The workflow derives the public key from that secret and compares it byte-for-byte with the committed public key before building packages. OCI manifests are additionally signed with keyless Cosign after all scan gates pass.

## Local build

Linux, Docker with BuildKit, `bash`, `curl`, `openssl`, and `sha256sum` are required. On Windows, run these commands inside WSL Ubuntu.

```sh
make tools
./.tools/bin/melange keygen keys/local-test.rsa
MELANGE_SIGNING_KEY="$PWD/keys/local-test.rsa" make packages
APKO_EXTRA_KEYRING="$PWD/keys/local-test.rsa.pub" make static
bash scripts/smoke-test.sh dist/baseless-static-x86_64.tar static
```

Private keys under `keys/` are ignored by Git; never reuse a local test key for releases.

## Release policy

CI builds and signs the `x86_64` and `aarch64` APKs, runs the shared `abxst/actions/strict@v3` gate against Dockerfile reconstructions of both production variants, publishes apko candidates to an ephemeral local registry, and scans the explicit upstream component inventory with pinned Grype. Only the exact apko-built multi-platform manifests are promoted to GHCR and signed by digest with Cosign using legacy signature tags. glibc is represented by a CycloneDX component and an auditable OpenVEX document tied to the pinned stable-branch commit. Floating tags are updated last, so a failed nightly build leaves the previous clean release in place.
