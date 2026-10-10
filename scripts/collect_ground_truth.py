#!/usr/bin/env python3
"""Collect a reproducible installed-package baseline from image package databases.

This intentionally does not use any of the SBOM generators being evaluated.
The initial ground-truth scope is OS packages recorded by dpkg or apk.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGES = ROOT / "data" / "images.csv"
TRUTH = ROOT / "data" / "ground_truth.csv"


def docker(*args: str, check: bool = True, stdout=None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, stdout=subprocess.PIPE if stdout is None else stdout, stderr=subprocess.PIPE)


def parse_dpkg(text: str, image_id: str, evidence: str) -> list[dict[str, str]]:
    result = []
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        if fields.get("Status") != "install ok installed" or not fields.get("Package") or not fields.get("Version"):
            continue
        name, version = fields["Package"], fields["Version"]
        source_match = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?$", fields.get("Source", ""))
        source_name = source_match.group(1) if source_match else ""
        source_version = (source_match.group(2) or version) if source_match else ""
        result.append({
            "image_id": image_id, "component_type": "operating-system", "ecosystem": "deb",
            "name": name, "version": version, "purl": f"pkg:deb/debian/{name}@{version}",
            "source_name": source_name, "source_version": source_version,
            "declared": "false", "installed": "true", "present": "true", "used": "",
            "evidence": evidence, "reviewer": "", "notes": "Independent dpkg status database inventory; architecture=" + fields.get("Architecture", "unknown"),
        })
    return result


def parse_apk(text: str, image_id: str, evidence: str) -> list[dict[str, str]]:
    result = []
    for stanza in text.strip().split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        if not fields.get("P") or not fields.get("V"):
            continue
        name, version = fields["P"], fields["V"]
        result.append({
            "image_id": image_id, "component_type": "operating-system", "ecosystem": "apk",
            "name": name, "version": version, "purl": f"pkg:apk/alpine/{name}@{version}",
            "source_name": fields.get("o", ""), "source_version": version if fields.get("o") else "",
            "declared": "false", "installed": "true", "present": "true", "used": "",
            "evidence": evidence, "reviewer": "", "notes": "Independent apk installed database inventory",
        })
    return result


def parse_npm_package(
    data: bytes, image_id: str, path: str, declared: str = "",
    installed: str = "true", present: str = "true", component_type: str = "library",
) -> dict[str, str] | None:
    try:
        package = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    name, version = package.get("name"), package.get("version")
    if not name or not isinstance(name, str) or (version and not isinstance(version, str)):
        return None
    from urllib.parse import quote
    version_part = "@" + quote(version, safe=".+-") if version else ""
    return {
        "image_id": image_id, "component_type": component_type, "ecosystem": "npm",
        "name": name, "version": version,
        "purl": f"pkg:npm/{quote(name, safe='@/-._~')}{version_part}",
        "declared": declared, "installed": installed, "present": present, "used": "",
        "evidence": "image filesystem: " + path,
        "reviewer": "", "notes": "npm package metadata from image filesystem; presence is not a usage claim",
    }


def npm_metadata_is_installed_package(path: str) -> bool:
    parts = path.split("/")
    try:
        marker = len(parts) - 1 - parts[::-1].index("node_modules")
    except ValueError:
        return path.startswith("opt/yarn-v")
    package_parts = parts[marker + 1:-1]
    return len(package_parts) == 1 or (len(package_parts) == 2 and package_parts[0].startswith("@"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", nargs="*", help="Optional image_id filter")
    args = parser.parse_args()
    with IMAGES.open(newline="", encoding="utf-8") as handle:
        images = [row for row in csv.DictReader(handle) if row.get("enabled", "").lower() == "true"]
    if args.images:
        images = [row for row in images if row["image_id"] in set(args.images)]

    existing = []
    if TRUTH.exists():
        with TRUTH.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            existing = list(reader)
    # Replace only rows for selected images; preserve hand-entered rows for others.
    selected = {row["image_id"] for row in images}
    rows = [row for row in existing if row.get("image_id") not in selected]
    fields = ["image_id", "component_type", "ecosystem", "name", "version", "purl", "source_name", "source_version", "declared", "installed", "present", "used", "evidence", "reviewer", "notes"]
    for row in rows:
        row.setdefault("source_name", "")
        row.setdefault("source_version", "")

    for image in images:
        image_id, ref = image["image_id"], image["image_ref"]
        created = docker("create", "--platform", image["platform"], ref, check=True)
        container = created.stdout.decode().strip()
        try:
            with tempfile.TemporaryFile() as archive_file:
                docker("export", container, check=True, stdout=archive_file)
                archive_file.seek(0)
                archive = tarfile.open(fileobj=archive_file, mode="r:")
                with archive:
                    members = {member.name.lstrip("./"): member for member in archive.getmembers() if member.isfile()}
                    manifests: dict[str, set[str]] = {}
                    external_manifests = []
                    for name, member in members.items():
                        if not name.endswith("/package.json"):
                            continue
                        stream = archive.extractfile(member)
                        if not stream:
                            continue
                        manifest_data = stream.read()
                        try:
                            manifest = json.loads(manifest_data)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        dependencies = set()
                        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                            values = manifest.get(section, {})
                            if isinstance(values, dict):
                                dependencies.update(values)
                        if "/node_modules/" in "/" + name:
                            manifests[name.rsplit("/", 1)[0]] = dependencies
                        else:
                            external_manifests.append((name, manifest_data))
                    dpkg = members.get("var/lib/dpkg/status")
                    apk = members.get("lib/apk/db/installed")
                    if dpkg:
                        stream = archive.extractfile(dpkg)
                        if stream:
                            rows.extend(parse_dpkg(stream.read().decode("utf-8", "replace"), image_id, "image filesystem: /var/lib/dpkg/status"))
                    elif apk:
                        stream = archive.extractfile(apk)
                        if stream:
                            rows.extend(parse_apk(stream.read().decode("utf-8", "replace"), image_id, "image filesystem: /lib/apk/db/installed"))
                    else:
                        print(f"WARNING: no supported OS package database in {image_id}", file=sys.stderr)
                    # Inventory npm package metadata. Nested test fixtures and
                    # subpath manifests are present files, but not installed packages.
                    for name, member in members.items():
                        if "/node_modules/" not in "/" + name or not name.endswith("/package.json"):
                            continue
                        stream = archive.extractfile(member)
                        if stream:
                            install_root = name.split("/node_modules/", 1)[0]
                            package_data = stream.read()
                            package_probe = parse_npm_package(package_data, image_id, name)
                            direct_dependencies = manifests.get(install_root)
                            declared = "true" if direct_dependencies is not None and package_probe and package_probe["name"] in direct_dependencies else "false" if direct_dependencies is not None else ""
                            installed = "true" if npm_metadata_is_installed_package(name) else "false"
                            record = parse_npm_package(package_data, image_id, name, declared, installed)
                            if record:
                                rows.append(record)
                    # Manifests outside node_modules describe either the
                    # application itself (present) or a standalone global tool
                    # such as Yarn (installed and present).
                    for name, package_data in external_manifests:
                        is_global_tool = name.startswith("opt/yarn-v")
                        record = parse_npm_package(
                            package_data, image_id, name,
                            installed="true" if is_global_tool else "false",
                            component_type="library" if is_global_tool else "application",
                        )
                        if record:
                            rows.append(record)
        finally:
            docker("rm", container, check=False)
        print(f"{image_id}: independent installed OS package inventory collected")

    TRUTH.parent.mkdir(parents=True, exist_ok=True)
    with TRUTH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} ground-truth rows to {TRUTH.relative_to(ROOT)} ({dt.date.today().isoformat()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
