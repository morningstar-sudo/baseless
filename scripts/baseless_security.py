#!/usr/bin/env python3
"""Fail-closed Baseless package inventory and OSV advisory scanner."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable


class SecurityMetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    architecture: str = "unknown"


def read_json(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SecurityMetadataError(f"cannot read JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise SecurityMetadataError(f"expected a JSON object in {path}")
    return value


def parse_os_release(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        try:
            values = shlex.split(raw_value, posix=True)
        except ValueError as error:
            raise SecurityMetadataError(f"invalid os-release value for {key}: {error}") from error
        result[key] = values[0] if values else ""
    return result


def parse_apk_database(text: str) -> list[Package]:
    packages: list[Package] = []
    for record in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in record.splitlines():
            if len(line) >= 3 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        if "P" in fields and "V" in fields:
            packages.append(Package(fields["P"], fields["V"], fields.get("A", "unknown")))
    return packages


def parse_spdx(path: pathlib.Path) -> list[Package]:
    document = read_json(path)
    packages: list[Package] = []
    for item in document.get("packages", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("versionInfo")
        if isinstance(name, str) and isinstance(version, str) and name.startswith("baseless-"):
            architecture = "unknown"
            package_purl = ""
            for ref in item.get("externalRefs", []):
                locator = ref.get("referenceLocator", "") if isinstance(ref, dict) else ""
                if isinstance(ref, dict) and ref.get("referenceType") == "purl" and locator.startswith("pkg:apk/"):
                    package_purl = locator
                marker = "arch="
                if marker in locator:
                    architecture = locator.split(marker, 1)[1].split("&", 1)[0]
            expected_prefix = f"pkg:apk/baseless/{name}@{version}?"
            if not package_purl.startswith(expected_prefix) or "distro=baseless" not in package_purl:
                raise SecurityMetadataError(
                    f"{name}@{version}: SBOM must use the Baseless APK namespace"
                )
            packages.append(Package(name, version, architecture))
    return packages


def load_registry(path: pathlib.Path) -> tuple[dict, dict[str, dict]]:
    registry = read_json(path)
    if registry.get("schema_version") != 1:
        raise SecurityMetadataError("unsupported security/distro.json schema_version")
    distro = registry.get("distro")
    entries = registry.get("packages")
    if not isinstance(distro, dict) or not isinstance(entries, list):
        raise SecurityMetadataError("distro.json must contain distro and packages")
    for field in ("id", "version", "ecosystem", "cpe"):
        if not isinstance(distro.get(field), str) or not distro[field]:
            raise SecurityMetadataError(f"distro.json requires distro.{field}")
    if distro["id"] != "baseless" or distro["ecosystem"] != "Baseless":
        raise SecurityMetadataError("the Baseless distro identity and ecosystem are immutable")
    packages: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SecurityMetadataError("invalid package registry entry")
        name = entry.get("name")
        current_version = entry.get("current_version")
        releases = entry.get("releases")
        if not isinstance(name, str) or not isinstance(current_version, str) or not isinstance(releases, list):
            raise SecurityMetadataError(
                "package registry entries require name, current_version and releases"
            )
        if not name.startswith("baseless-") or not current_version:
            raise SecurityMetadataError(f"invalid Baseless package identity: {name}@{current_version}")
        if name in packages:
            raise SecurityMetadataError(f"duplicate package registry entry: {name}")
        release_versions: set[str] = set()
        for release in releases:
            if not isinstance(release, dict):
                raise SecurityMetadataError(f"{name}: invalid release entry")
            version = release.get("version")
            status = release.get("status")
            source = release.get("source")
            if (
                not isinstance(version, str)
                or not version
                or status not in {"supported", "eol"}
                or not isinstance(source, dict)
            ):
                raise SecurityMetadataError(
                    f"{name}: releases require version, supported/eol status and source"
                )
            if version in release_versions:
                raise SecurityMetadataError(f"{name}: duplicate release {version}")
            release_versions.add(version)
        if current_version not in release_versions:
            raise SecurityMetadataError(f"{name}: current_version is absent from releases")
        current_release = next(
            release for release in releases if release["version"] == current_version
        )
        if current_release["status"] != "supported":
            raise SecurityMetadataError(f"{name}: current_version must be supported")
        packages[name] = entry
    return distro, packages


def validate_registry_sources(registry: dict[str, dict], repo_root: pathlib.Path) -> None:
    allowed_types = {"internal", "apk", "upstream", "subpackage", "aggregate"}
    for name, entry in registry.items():
        for release in entry["releases"]:
            validate_registry_source(
                name,
                release["version"],
                release["source"],
                registry,
                repo_root,
                allowed_types,
            )


def validate_registry_source(
    name: str,
    version: str,
    source: dict,
    registry: dict[str, dict],
    repo_root: pathlib.Path,
    allowed_types: set[str],
) -> None:
    source_type = source.get("type")
    if source_type not in allowed_types:
        raise SecurityMetadataError(f"{name}@{version}: unsupported source type {source_type}")
    if source_type == "internal":
        if not isinstance(source.get("repository"), str):
            raise SecurityMetadataError(f"{name}@{version}: internal source requires repository")
    elif source_type == "apk":
        if not all(isinstance(source.get(field), str) for field in ("distro", "purl")):
            raise SecurityMetadataError(f"{name}@{version}: apk source requires distro and purl")
        if not source["purl"].startswith("pkg:apk/"):
            raise SecurityMetadataError(f"{name}@{version}: invalid APK purl")
    elif source_type == "upstream":
        if not all(isinstance(source.get(field), str) for field in ("purl", "cpe")):
            raise SecurityMetadataError(f"{name}@{version}: upstream source requires purl and cpe")
        vex = source.get("vex")
        if vex and not (repo_root / vex).is_file():
            raise SecurityMetadataError(f"{name}@{version}: VEX document does not exist: {vex}")
    elif source_type == "subpackage":
        parent = source.get("parent")
        if parent not in registry:
            raise SecurityMetadataError(f"{name}@{version}: unknown parent package {parent}")
        parent_versions = {release["version"] for release in registry[parent]["releases"]}
        if version not in parent_versions:
            raise SecurityMetadataError(f"{name}@{version}: version is absent from parent {parent}")
    elif source_type == "aggregate":
        components = source.get("components")
        if not isinstance(components, str) or not (repo_root / components).is_file():
            raise SecurityMetadataError(
                f"{name}@{version}: component inventory does not exist: {components}"
            )


def load_advisories(directory: pathlib.Path, ecosystem: str, known_packages: set[str]) -> list[dict]:
    advisories: list[dict] = []
    seen_ids: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        advisory = read_json(path)
        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not re.fullmatch(r"BLSA-\d{4}-\d{4}", advisory_id):
            raise SecurityMetadataError(f"OSV advisory id must use BLSA-YYYY-NNNN: {path}")
        schema_version = advisory.get("schema_version")
        if not isinstance(schema_version, str) or not re.fullmatch(r"1\.\d+\.\d+", schema_version):
            raise SecurityMetadataError(f"{advisory_id}: a supported OSV 1.x schema_version is required")
        if not all(isinstance(advisory.get(field), str) for field in ("modified", "published", "summary")):
            raise SecurityMetadataError(
                f"{advisory_id}: modified, published and summary are required"
            )
        if advisory_id in seen_ids:
            raise SecurityMetadataError(f"duplicate OSV advisory id: {advisory_id}")
        seen_ids.add(advisory_id)
        affected = advisory.get("affected")
        if not isinstance(affected, list) or not affected:
            raise SecurityMetadataError(f"OSV advisory has no affected packages: {path}")
        for item in affected:
            package = item.get("package", {}) if isinstance(item, dict) else {}
            if package.get("ecosystem") != ecosystem:
                raise SecurityMetadataError(f"{advisory_id}: ecosystem must be {ecosystem}")
            name = package.get("name")
            if name not in known_packages:
                raise SecurityMetadataError(f"{advisory_id}: unknown package {name}")
            expected_purl = f"pkg:apk/baseless/{name}"
            if package.get("purl") != expected_purl:
                raise SecurityMetadataError(
                    f"{advisory_id}: package purl must be versionless {expected_purl}"
                )
            versions = item.get("versions")
            if not isinstance(versions, list) or not versions or not all(isinstance(v, str) for v in versions):
                raise SecurityMetadataError(f"{advisory_id}: enumerate affected versions explicitly")
            if item.get("ranges"):
                raise SecurityMetadataError(f"{advisory_id}: APK version ranges are not accepted")
        advisories.append(advisory)
    return advisories


def validate_inventory(
    packages: Iterable[Package],
    registry: dict[str, dict],
    require_current: bool = False,
) -> list[Package]:
    baseless_packages = sorted(
        (package for package in packages if package.name.startswith("baseless-")),
        key=lambda package: (package.name, package.architecture),
    )
    if not baseless_packages:
        raise SecurityMetadataError("no Baseless packages found in inventory")
    seen: set[tuple[str, str, str]] = set()
    validated: list[Package] = []
    for package in baseless_packages:
        key = (package.name, package.version, package.architecture)
        if key in seen:
            continue
        seen.add(key)
        registered = registry.get(package.name)
        if registered is None:
            raise SecurityMetadataError(f"unregistered Baseless package: {package.name}")
        releases = {release["version"]: release for release in registered["releases"]}
        release = releases.get(package.version)
        if release is None:
            raise SecurityMetadataError(
                f"unregistered Baseless release: {package.name}@{package.version}"
            )
        if release["status"] != "supported":
            raise SecurityMetadataError(f"unsupported EOL release: {package.name}@{package.version}")
        if require_current and registered["current_version"] != package.version:
            raise SecurityMetadataError(
                f"release build is not current for {package.name}: "
                f"inventory={package.version}, current={registered['current_version']}"
            )
        validated.append(package)
    return validated


def find_vulnerabilities(packages: Iterable[Package], advisories: Iterable[dict]) -> list[dict]:
    installed = {(package.name, package.version) for package in packages}
    findings: list[dict] = []
    for advisory in advisories:
        for item in advisory["affected"]:
            name = item["package"]["name"]
            for version in item["versions"]:
                if (name, version) in installed:
                    findings.append(
                        {
                            "id": advisory["id"],
                            "package": name,
                            "installed_version": version,
                            "summary": advisory.get("summary", ""),
                        }
                    )
    return findings


def copy_from_image(image: str, container_path: str, destination: pathlib.Path) -> None:
    container_id = subprocess.run(
        ["docker", "create", image, "/__baseless_security_scan__"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        subprocess.run(
            ["docker", "cp", f"{container_id}:{container_path}", str(destination)],
            check=True,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", container_id], check=False, capture_output=True)


def scan(
    packages: list[Package],
    distro: dict,
    registry: dict[str, dict],
    advisories: list[dict],
    os_release: dict[str, str] | None = None,
    require_current: bool = False,
) -> dict:
    if os_release is not None:
        if os_release.get("ID") != distro.get("id"):
            raise SecurityMetadataError(f"expected ID={distro.get('id')}, got {os_release.get('ID')}")
        if os_release.get("VERSION_ID") != distro.get("version"):
            raise SecurityMetadataError(
                f"expected VERSION_ID={distro.get('version')}, got {os_release.get('VERSION_ID')}"
            )
        if os_release.get("CPE_NAME") != distro.get("cpe"):
            raise SecurityMetadataError("os-release CPE_NAME does not match distro registry")
    baseless_packages = validate_inventory(packages, registry, require_current)
    findings = find_vulnerabilities(baseless_packages, advisories)
    return {
        "distro": {"id": distro["id"], "version": distro["version"], "recognized": True},
        "packages": [package.__dict__ for package in baseless_packages],
        "foreign_package_count": len(packages) - len(baseless_packages),
        "advisories_checked": len(advisories),
        "vulnerabilities": findings,
    }


def main() -> int:
    script_dir = pathlib.Path(__file__).resolve().parent
    repo_root = script_dir.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=pathlib.Path, default=repo_root / "security/distro.json")
    parser.add_argument("--advisories", type=pathlib.Path, default=repo_root / "security/osv")
    parser.add_argument("--output", type=pathlib.Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate distro registry and OSV advisory metadata")
    image_parser = subparsers.add_parser("image", help="scan an image through its retained APK inventory")
    image_parser.add_argument("reference")
    image_parser.add_argument(
        "--require-current",
        action="store_true",
        help="require every installed package to be the registry's current release",
    )
    sbom_parser = subparsers.add_parser("sbom", help="scan an apko SPDX JSON document")
    sbom_parser.add_argument("path", type=pathlib.Path)
    args = parser.parse_args()

    try:
        distro, registry = load_registry(args.registry)
        validate_registry_sources(registry, repo_root)
        advisories = load_advisories(args.advisories, distro["ecosystem"], set(registry))
        if args.command == "validate":
            report = {
                "distro": {
                    "id": distro["id"],
                    "version": distro["version"],
                    "ecosystem": distro["ecosystem"],
                    "cpe": distro["cpe"],
                },
                "registered_packages": len(registry),
                "published_advisories": len(advisories),
                "valid": True,
            }
        elif args.command == "image":
            with tempfile.TemporaryDirectory(prefix="baseless-scan-") as temporary:
                directory = pathlib.Path(temporary)
                apk_database = directory / "installed"
                os_release_path = directory / "os-release"
                copy_from_image(args.reference, "/lib/apk/db/installed", apk_database)
                copy_from_image(args.reference, "/etc/os-release", os_release_path)
                packages = parse_apk_database(apk_database.read_text(encoding="utf-8"))
                os_release = parse_os_release(os_release_path.read_text(encoding="utf-8"))
                report = scan(
                    packages,
                    distro,
                    registry,
                    advisories,
                    os_release,
                    args.require_current,
                )
        else:
            report = scan(
                parse_spdx(args.path),
                distro,
                registry,
                advisories,
                require_current=True,
            )
    except (SecurityMetadataError, OSError, subprocess.CalledProcessError) as error:
        print(f"baseless-security: {error}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 1 if report.get("vulnerabilities") else 0


if __name__ == "__main__":
    raise SystemExit(main())
