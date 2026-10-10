#!/usr/bin/env python3
"""Generate and archive CycloneDX JSON SBOMs for enabled, digest-pinned images."""

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
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGES_CSV = ROOT / "data" / "images.csv"
RAW_ROOT = ROOT / "artifacts" / "raw"
RUNS_ROOT = ROOT / "artifacts" / "runs"
LOCAL_CDXGEN = ROOT / ".tools" / "cdxgen" / "node_modules" / ".bin" / "cdxgen"
TOOLS = ("syft", "trivy", "cdxgen")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def executable(tool: str) -> str:
    if tool == "cdxgen" and LOCAL_CDXGEN.exists():
        return str(LOCAL_CDXGEN)
    return shutil.which(tool) or tool


def tool_version(tool: str) -> str:
    command = {
        "syft": [executable(tool), "version"],
        "trivy": [executable(tool), "--version"],
        "cdxgen": [executable(tool), "--version"],
    }[tool]
    result = run(command, 60)
    if result.returncode:
        return "ERROR: " + (result.stderr.strip() or result.stdout.strip())
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout or result.stderr).strip()
    if tool in {"syft", "trivy"}:
        match = re.search(r"^Version:\s*([^\s]+)", output, re.MULTILINE)
        if match:
            return match.group(1)
    if tool == "cdxgen":
        match = re.search(r"CycloneDX Generator\s+([^\s]+)", output)
        if match:
            return match.group(1)
    return output.splitlines()[0]


def load_images() -> list[dict[str, str]]:
    with IMAGES_CSV.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def validate_enabled(rows: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if row.get("enabled", "").strip().lower() != "true":
            continue
        image_id = row.get("image_id", "").strip()
        ref = row.get("image_ref", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", image_id):
            errors.append("Invalid image_id: " + repr(image_id))
        if image_id in seen:
            errors.append("Duplicate image_id: " + image_id)
        seen.add(image_id)
        if not re.search(r"@sha256:[0-9a-fA-F]{64}$", ref):
            errors.append(image_id + ": image_ref must end with an immutable @sha256 digest")
    return errors


def command_for(tool: str, image_ref: str, output: pathlib.Path) -> list[str]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if tool == "syft":
        return [executable(tool), image_ref, "-o", "cyclonedx-json=" + str(output)]
    if tool == "trivy":
        return [executable(tool), "image", "--format", "cyclonedx", "--output", str(output), image_ref]
    return [executable(tool), image_ref, "-t", "docker", "-o", str(output)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=1, help="Runs per tool and image")
    parser.add_argument("--timeout", type=int, default=1800, help="Per-scan timeout in seconds")
    parser.add_argument("--tools", nargs="+", choices=TOOLS, default=list(TOOLS))
    parser.add_argument("--images", nargs="*", help="Optional image_id filter")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")

    rows = load_images()
    enabled = [row for row in rows if row.get("enabled", "").strip().lower() == "true"]
    if args.images:
        selected = set(args.images)
        unknown = selected - {row["image_id"] for row in enabled}
        if unknown:
            parser.error("unknown or disabled image_id(s): " + ", ".join(sorted(unknown)))
        enabled = [row for row in enabled if row["image_id"] in selected]
    if not enabled:
        print("No enabled images. Pin image_ref by digest and set enabled=true in data/images.csv.", file=sys.stderr)
        return 2
    errors = validate_enabled(rows)
    if errors:
        print("\n".join("ERROR: " + item for item in errors), file=sys.stderr)
        return 2
    missing = [tool for tool in args.tools if shutil.which(tool) is None and not (tool == "cdxgen" and LOCAL_CDXGEN.exists())]
    if missing:
        print("Missing executables: " + ", ".join(missing), file=sys.stderr)
        return 2

    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    versions = {tool: tool_version(tool) for tool in args.tools}
    manifest: dict[str, object] = {
        "run_id": run_id,
        "started_at": utc_now(),
        "host_platform": sys.platform,
        "python_version": sys.version.split()[0],
        "tool_versions": versions,
        "repeat": args.repeat,
        "images": [],
    }
    print("Run " + run_id + ": " + str(len(enabled)) + " image(s)")

    for image in enabled:
        image_entry: dict[str, object] = {
            "image_id": image["image_id"],
            "image_ref": image["image_ref"],
            "category": image.get("category", ""),
            "platform": image.get("platform", ""),
            "runs": [],
        }
        for repeat_index in range(1, args.repeat + 1):
            for tool in args.tools:
                output = RAW_ROOT / tool / image["image_id"] / (run_id + "-repeat-" + str(repeat_index) + ".cdx.json")
                command = command_for(tool, image["image_ref"], output)
                record: dict[str, object] = {
                    "tool": tool,
                    "repeat": repeat_index,
                    "command": command,
                    "started_at": utc_now(),
                    "output": str(output.relative_to(ROOT)),
                }
                print("[" + image["image_id"] + "] " + tool + " repeat " + str(repeat_index))
                try:
                    result = run(command, args.timeout)
                    record["return_code"] = result.returncode
                    record["stdout"] = result.stdout[-12000:]
                    record["stderr"] = result.stderr[-12000:]
                    if result.returncode != 0 or not output.exists():
                        record["status"] = "failed"
                    else:
                        try:
                            document = json.loads(output.read_text(encoding="utf-8"))
                            if document.get("bomFormat") != "CycloneDX":
                                record["status"] = "invalid_output_format"
                            else:
                                record["status"] = "success"
                                record["component_count"] = len(document.get("components", []))
                        except (OSError, json.JSONDecodeError) as exc:
                            record["status"] = "invalid_output_json"
                            record["error"] = str(exc)
                except subprocess.TimeoutExpired:
                    record["status"] = "timeout"
                    record["error"] = "Exceeded " + str(args.timeout) + " seconds"
                record["finished_at"] = utc_now()
                image_entry["runs"].append(record)  # type: ignore[union-attr]
                print("  " + str(record["status"]) + ": " + str(output.relative_to(ROOT)))
        manifest["images"].append(image_entry)  # type: ignore[union-attr]

    manifest["finished_at"] = utc_now()
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    manifest_path = RUNS_ROOT / (run_id + ".json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Manifest: " + str(manifest_path.relative_to(ROOT)))
    failures = sum(
        record.get("status") != "success"
        for image in manifest["images"]  # type: ignore[union-attr]
        for record in image["runs"]
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
