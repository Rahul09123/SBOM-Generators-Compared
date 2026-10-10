#!/usr/bin/env python3
"""Pull candidate images and write immutable digest references to data/images.csv."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "images.csv"


def call(command: list[str], timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", action="append", help="Resolve only this image_id; may be repeated")
    args = parser.parse_args()
    if shutil.which("docker") is None:
        print("Docker executable not found.", file=sys.stderr)
        return 2

    with CSV_PATH.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)
    if fields is None or "candidate_ref" not in fields or "image_ref" not in fields:
        print("Expected candidate_ref and image_ref columns in data/images.csv.", file=sys.stderr)
        return 2

    requested = set(args.image_id or [])
    known = {row["image_id"] for row in rows}
    if requested - known:
        print("Unknown image_id(s): " + ", ".join(sorted(requested - known)), file=sys.stderr)
        return 2
    selected = [row for row in rows if (not requested or row["image_id"] in requested) and row.get("candidate_ref", "").strip()]
    if not selected:
        print("No candidate images selected.")
        return 0

    failures = 0
    for row in selected:
        ref = row["candidate_ref"].strip()
        platform = row.get("platform", "").strip()
        image_id = row["image_id"]
        print("Pulling " + image_id + ": " + ref + " (" + platform + ")")
        pulled = call(["docker", "pull", "--platform", platform, ref])
        if pulled.returncode:
            print(pulled.stderr.strip() or pulled.stdout.strip(), file=sys.stderr)
            failures += 1
            continue
        inspected = call(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", ref], timeout=60)
        if inspected.returncode:
            print(inspected.stderr.strip(), file=sys.stderr)
            failures += 1
            continue
        try:
            repo_digests = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            repo_digests = []
        candidates = [value for value in (repo_digests or []) if re.search(r"@sha256:[0-9a-fA-F]{64}$", value)]
        if not candidates:
            print("No registry RepoDigest found for " + ref + "; image_ref left unchanged.", file=sys.stderr)
            failures += 1
            continue
        row["image_ref"] = candidates[0]
        row["retrieved_at"] = dt.datetime.now(dt.timezone.utc).date().isoformat()
        print("  pinned: " + row["image_ref"])

    if "retrieved_at" not in fields:
        fields.append("retrieved_at")
    temporary = CSV_PATH.with_suffix(".csv.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(CSV_PATH)
    print("Updated data/images.csv. Review resolved references before enabling images.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
