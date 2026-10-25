import json
import copy
import pathlib
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import baseless_security as security


class BaselessSecurityTests(unittest.TestCase):
    def setUp(self):
        self.distro, self.registry = security.load_registry(REPO_ROOT / "security/distro.json")

    def test_apk_database_parser(self):
        packages = security.parse_apk_database(
            "P:baseless-glibc\nV:2.44-r4\nA:x86_64\n\nP:foreign\nV:1-r0\n"
        )
        self.assertEqual(packages[0], security.Package("baseless-glibc", "2.44-r4", "x86_64"))
        self.assertEqual(len(packages), 2)

    def test_registered_inventory_passes(self):
        report = security.scan(
            [security.Package("baseless-glibc", "2.44-r4", "x86_64")],
            self.distro,
            self.registry,
            [],
        )
        self.assertTrue(report["distro"]["recognized"])
        self.assertEqual(report["vulnerabilities"], [])

    def test_os_release_contract_passes(self):
        os_release = security.parse_os_release(
            """ID=baseless
VERSION_ID="2026.10"
CPE_NAME="cpe:2.3:o:morningstar-sudo:baseless:2026.10:*:*:*:*:*:*:*"
"""
        )
        report = security.scan(
            [security.Package("baseless-baselayout", "20261024-r1")],
            self.distro,
            self.registry,
            [],
            os_release,
        )
        self.assertTrue(report["distro"]["recognized"])

    def test_registry_provenance_is_valid(self):
        security.validate_registry_sources(self.registry, REPO_ROOT)

    def test_spdx_requires_baseless_purl_namespace(self):
        document = {
            "packages": [
                {
                    "name": "baseless-glibc",
                    "versionInfo": "2.44-r4",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": (
                                "pkg:apk/baseless/baseless-glibc@2.44-r4"
                                "?arch=x86_64&distro=baseless"
                            ),
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "sbom.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(
                security.parse_spdx(path),
                [security.Package("baseless-glibc", "2.44-r4", "x86_64")],
            )
            document["packages"][0]["externalRefs"][0]["referenceLocator"] = (
                "pkg:apk/unknown/baseless-glibc@2.44-r4?arch=x86_64"
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(security.SecurityMetadataError, "Baseless APK namespace"):
                security.parse_spdx(path)

    def test_stale_registry_fails_closed(self):
        with self.assertRaisesRegex(security.SecurityMetadataError, "unregistered Baseless release"):
            security.validate_inventory(
                [security.Package("baseless-glibc", "2.44-r99")], self.registry
            )

    def test_supported_history_and_current_release_policy(self):
        registry = copy.deepcopy(self.registry)
        registry["baseless-glibc"]["releases"].append(
            {
                "version": "2.44-r3",
                "status": "supported",
                "source": {"type": "upstream"},
            }
        )
        package = security.Package("baseless-glibc", "2.44-r3")
        self.assertEqual(security.validate_inventory([package], registry), [package])
        with self.assertRaisesRegex(security.SecurityMetadataError, "release build is not current"):
            security.validate_inventory([package], registry, require_current=True)

    def test_eol_release_fails_closed(self):
        registry = copy.deepcopy(self.registry)
        registry["baseless-glibc"]["releases"].append(
            {
                "version": "2.44-r3",
                "status": "eol",
                "source": {"type": "upstream"},
            }
        )
        with self.assertRaisesRegex(security.SecurityMetadataError, "unsupported EOL release"):
            security.validate_inventory(
                [security.Package("baseless-glibc", "2.44-r3")], registry
            )

    def test_exact_osv_version_is_blocked(self):
        advisory = {
            "id": "BLSA-TEST-0001",
            "affected": [
                {
                    "package": {"ecosystem": "Baseless", "name": "baseless-glibc"},
                    "versions": ["2.44-r4"],
                }
            ],
        }
        findings = security.find_vulnerabilities(
            [security.Package("baseless-glibc", "2.44-r4")], [advisory]
        )
        self.assertEqual(findings[0]["id"], "BLSA-TEST-0001")

    def test_ranges_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            advisory_path = pathlib.Path(temporary) / "BLSA-TEST-0002.json"
            advisory_path.write_text(
                json.dumps(
                    {
                        "id": "BLSA-2026-0002",
                        "schema_version": "1.6.0",
                        "modified": "2026-10-25T00:00:00Z",
                        "published": "2026-10-25T00:00:00Z",
                        "summary": "test advisory",
                        "affected": [
                            {
                                "package": {
                                    "ecosystem": "Baseless",
                                    "name": "baseless-glibc",
                                    "purl": "pkg:apk/baseless/baseless-glibc",
                                },
                                "versions": ["2.44-r4"],
                                "ranges": [{"type": "ECOSYSTEM", "events": []}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(security.SecurityMetadataError, "ranges are not accepted"):
                security.load_advisories(
                    pathlib.Path(temporary), self.distro["ecosystem"], set(self.registry)
                )


if __name__ == "__main__":
    unittest.main()
