# Baseless OSV advisory feed

This directory is the authoritative vulnerability-advisory namespace for
packages whose OSV ecosystem is `Baseless`.

Each advisory is one OSV JSON document named `<id>.json`. Baseless deliberately
uses an explicit `affected[].versions` list instead of ecosystem ranges: APK
versions are not SemVer, and enumerating released vulnerable versions keeps the
scanner fail-closed without inventing version-ordering rules.

An empty directory means no released Baseless package version is currently
known to be affected. It does not replace upstream monitoring. CI separately
scans every source component listed in `security/distro.json`; a newly detected
upstream finding blocks the release until it is fixed or covered by reviewed
OpenVEX evidence.

Minimal advisory shape:

```json
{
  "schema_version": "1.9.0",
  "id": "BLSA-2026-0001",
  "modified": "2026-10-25T00:00:00Z",
  "published": "2026-10-25T00:00:00Z",
  "summary": "Example only",
  "affected": [
    {
      "package": {
        "ecosystem": "Baseless",
        "name": "baseless-example",
        "purl": "pkg:apk/baseless/baseless-example"
      },
      "versions": ["1.0-r0"]
    }
  ]
}
```

Use identifiers in the form `BLSA-YYYY-NNNN`. An advisory must include
`schema_version`, `published`, `modified`, `summary`, and at least one affected
package in ecosystem `Baseless`. When a fix is backported, bump the Melange
epoch, keep all historical affected versions in the advisory, and release the
new package version outside the advisory's affected list.

Before the feed is advertised as natively supported by general OSV clients,
the `Baseless` ecosystem and `BLSA` identifier prefix must be registered in the
upstream OSV schema. Until that lands, this repository's scanner is the
authoritative consumer; the records deliberately retain the final OSV shape so
the upstream transition does not require a data migration.
