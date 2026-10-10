#!/usr/bin/env python3
"""Compare the latest archived CycloneDX SBOMs with the independent ground-truth CSV."""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import pathlib
import re
import sys
import urllib.parse
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW_ROOT = ROOT / "artifacts" / "raw"
TRUTH_CSV = ROOT / "data" / "ground_truth.csv"
REPORT_ROOT = ROOT / "artifacts" / "reports"
TOOLS = ("syft", "trivy", "cdxgen")


def clean(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


def purl_parts(purl: str) -> tuple[str, str, str]:
    if not purl.startswith("pkg:"):
        return "", "", ""
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    package_type, separator, remainder = body.partition("/")
    if not separator:
        return clean(package_type), "", ""
    path, at, version = remainder.rpartition("@")
    if not at:
        path, version = remainder, ""
    decoded = urllib.parse.unquote(path).strip("/")
    return clean(package_type), clean(decoded), clean(urllib.parse.unquote(version))


def component_identity(row: dict[str, object]) -> tuple[str, str, str]:
    purl = str(row.get("purl") or "")
    ptype, pname, pversion = purl_parts(purl)
    ecosystem = clean(row.get("ecosystem")) or ptype
    name = clean(row.get("name")) or pname
    version = clean(row.get("version")) or pversion
    if version in {"unknown", "unspecified", "(unknown)"}:
        version = ""
    group = clean(row.get("group"))
    if ecosystem == "npm" and group and name and not name.startswith(group + "/"):
        name = group + "/" + name
    if not ecosystem and row.get("type") == "library":
        ecosystem = group
    if not name:
        group = clean(row.get("group"))
        name = (group + "/" if group else "") + clean(row.get("name"))
    return ecosystem, name, version


def load_truth(state: str) -> dict[str, list[dict[str, object]]]:
    truth: dict[str, list[dict[str, object]]] = defaultdict(list)
    with TRUTH_CSV.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get(state, "").strip().lower() not in {"true", "1", "yes", "y"}:
                continue
            identity = component_identity(row)
            if not identity[1]:
                continue
            row["_identity"] = identity
            row["_purl"] = row.get("purl", "").strip()
            row["_source_identity"] = (
                clean(row.get("ecosystem")), clean(row.get("source_name")),
                clean(row.get("source_version")),
            ) if row.get("source_name", "").strip() else None
            truth[row.get("image_id", "").strip()].append(row)
    # The study's component-level metric counts unique ecosystem/name/version
    # identities. Multiple installed copies at different paths are occurrences,
    # not separate component identities; raw locations remain in the CSV.
    for image_id, rows in truth.items():
        unique: dict[tuple[str, str, str], dict[str, object]] = {}
        for row in rows:
            unique.setdefault(row["_identity"], row)
        truth[image_id] = list(unique.values())
    return truth


def load_components(path: pathlib.Path) -> list[dict[str, object]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("not CycloneDX JSON")
    components: list[dict[str, object]] = []
    for component in document.get("components", []):
        record: dict[str, object] = {
            "name": component.get("name", ""),
            "version": component.get("version", ""),
            "group": component.get("group", ""),
            "type": component.get("type", ""),
            "purl": component.get("purl", ""),
            "ecosystem": "",
        }
        record["_identity"] = component_identity(record)
        record["_purl"] = str(record["purl"]).strip()
        components.append(record)
    unique: dict[tuple[str, str, str], dict[str, object]] = {}
    for component in components:
        identity = component.get("_identity")
        unique.setdefault(identity, component)
    return list(unique.values())


def latest_sbom(tool: str, image_id: str) -> pathlib.Path | None:
    folder = RAW_ROOT / tool / image_id
    candidates = sorted(folder.glob("*.cdx.json"), key=lambda item: item.stat().st_mtime, reverse=True) if folder.exists() else []
    for candidate in candidates:
        try:
            load_components(candidate)
            return candidate
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return None


def match_components(
    predicted: list[dict[str, object]], expected: list[dict[str, object]]
) -> tuple[list[tuple[dict[str, object], dict[str, object], str]], list[dict[str, object]], list[dict[str, object]]]:
    unmatched_expected = set(range(len(expected)))
    unmatched_predicted: list[dict[str, object]] = []
    matches: list[tuple[dict[str, object], dict[str, object], str]] = []

    for component in predicted:
        purl = str(component.get("_purl", ""))
        identity = component.get("_identity")
        chosen: int | None = None
        match_type = ""
        if purl:
            exact = [i for i in unmatched_expected if purl == str(expected[i].get("_purl", ""))]
            if exact:
                chosen, match_type = exact[0], "exact_purl"
        if chosen is None:
            same_identity = [i for i in unmatched_expected if identity == expected[i].get("_identity")]
            if same_identity and identity and identity[1]:
                chosen = same_identity[0]
                match_type = "normalized_identity" if identity[2] else "normalized_identity_unversioned"
        if chosen is None and identity and identity[1] and identity[2]:
            name_version = [i for i in unmatched_expected if identity[1:] == expected[i].get("_identity", (None, None, None))[1:]]
            if name_version:
                chosen, match_type = name_version[0], "name_version"
        if chosen is None:
            name_only = [i for i in unmatched_expected if identity and identity[1] and identity[1] == expected[i].get("_identity", (None, None, None))[1]]
            if name_only:
                unmatched_predicted.append({**component, "_weak_match": expected[name_only[0]]})
            else:
                unmatched_predicted.append(component)
            continue
        unmatched_expected.remove(chosen)
        matches.append((component, expected[chosen], match_type))
    return matches, unmatched_predicted, [expected[i] for i in sorted(unmatched_expected)]


def csv_write(path: pathlib.Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--truth-state", choices=("declared", "installed", "present", "used"), default="present")
    parser.add_argument("--images", nargs="*", help="Optional image_id filter")
    args = parser.parse_args()
    if not TRUTH_CSV.exists():
        print("Ground-truth file not found: " + str(TRUTH_CSV), file=sys.stderr)
        return 2
    truth = load_truth(args.truth_state)
    image_ids = sorted(set(truth) | {path.name for tool in TOOLS for path in (RAW_ROOT / tool).glob("*") if path.is_dir()})
    if args.images:
        image_ids = [image_id for image_id in image_ids if image_id in set(args.images)]
    if not image_ids:
        print("No images found in ground truth or raw SBOM directories.", file=sys.stderr)
        return 2

    metrics: list[dict[str, object]] = []
    mismatches: list[dict[str, object]] = []
    agreements: list[dict[str, object]] = []
    for image_id in image_ids:
        per_tool: dict[str, set[tuple[str, str, str]]] = {}
        for tool in TOOLS:
            path = latest_sbom(tool, image_id)
            expected = truth.get(image_id, [])
            if path is None:
                metrics.append({
                    "image_id": image_id, "tool": tool, "truth_state": args.truth_state,
                    "status": "missing_sbom", "sbom_path": "", "tp": "", "fp": "", "fn": "",
                    "source_aliases": "", "other_unmatched": "",
                    "unversioned_matches": "",
                    "precision": "", "recall": "", "f1": "",
                })
                per_tool[tool] = set()
                continue
            predicted = load_components(path)
            # Restrict this first evaluation to package ecosystems represented in
            # the independent truth set (currently dpkg/apk). File records and
            # other ungrounded component classes are not accuracy false-positives.
            expected_ecosystems = {row.get("ecosystem", "") for row in expected}
            predicted = [component for component in predicted
                         if purl_parts(str(component.get("purl", "")))[0] in expected_ecosystems]
            matches, extras, missed = match_components(predicted, expected)
            tp, fp, fn = len(matches), len(extras), len(missed)
            unversioned_matches = sum(
                not expected_component.get("_identity", ("", "", ""))[2]
                for _, expected_component, _ in matches
            )
            source_aliases = sum(
                1 for component in extras
                if any(component.get("_identity") == row.get("_source_identity") for row in expected)
            )
            precision = tp / (tp + fp) if tp + fp else (1.0 if fn == 0 else 0.0)
            recall = tp / (tp + fn) if tp + fn else (1.0 if fp == 0 else 0.0)
            f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
            metrics.append({
                "image_id": image_id, "tool": tool, "truth_state": args.truth_state,
                "status": "ok" if expected else "no_ground_truth",
                "sbom_path": str(path.relative_to(ROOT)), "tp": tp, "fp": fp, "fn": fn,
                "source_aliases": source_aliases, "other_unmatched": fp - source_aliases,
                "unversioned_matches": unversioned_matches,
                "precision": round(precision, 6), "recall": round(recall, 6), "f1": round(f1, 6),
            })
            per_tool[tool] = {component["_identity"] for component in predicted if component.get("_identity")}
            for component in extras:
                weak = component.get("_weak_match")
                source_identity = component.get("_identity")
                source_match = next((row for row in expected
                                     if source_identity and row.get("_source_identity") == source_identity), None)
                mismatches.append({
                    "image_id": image_id, "tool": tool,
                    "kind": "source_package_alias" if source_match else "extra_or_weak_match",
                    "name": component.get("name", ""), "version": component.get("version", ""),
                    "ecosystem": component.get("ecosystem", ""), "purl": component.get("purl", ""),
                    "weak_ground_truth_candidate": weak.get("name", "") if isinstance(weak, dict) else "",
                    "source_ground_truth_candidate": source_match.get("name", "") if source_match else "",
                    "evidence": source_match.get("evidence", "") if source_match else "",
                })
            for component in missed:
                mismatches.append({
                    "image_id": image_id, "tool": tool, "kind": "missing",
                    "name": component.get("name", ""), "version": component.get("version", ""),
                    "ecosystem": component.get("ecosystem", ""), "purl": component.get("purl", ""),
                    "weak_ground_truth_candidate": "", "source_ground_truth_candidate": "",
                    "evidence": component.get("evidence", ""),
                })
        for left, right in itertools.combinations(TOOLS, 2):
            a, b = per_tool[left], per_tool[right]
            union = a | b
            agreements.append({
                "image_id": image_id, "tool_a": left, "tool_b": right,
                "components_a": len(a), "components_b": len(b), "intersection": len(a & b),
                "union": len(union), "jaccard": round(len(a & b) / len(union), 6) if union else 1.0,
            })

    report_root = REPORT_ROOT / args.truth_state
    report_root.mkdir(parents=True, exist_ok=True)
    csv_write(report_root / "accuracy_by_image.csv", metrics, [
        "image_id", "tool", "truth_state", "status", "sbom_path", "tp", "fp", "fn",
        "source_aliases", "other_unmatched", "unversioned_matches", "precision", "recall", "f1",
    ])
    csv_write(report_root / "mismatches.csv", mismatches, [
        "image_id", "tool", "kind", "name", "version", "ecosystem", "purl", "weak_ground_truth_candidate", "evidence",
        "source_ground_truth_candidate",
    ])
    csv_write(report_root / "pairwise_agreement.csv", agreements, [
        "image_id", "tool_a", "tool_b", "components_a", "components_b", "intersection", "union", "jaccard",
    ])
    print("Reports written to " + str(report_root.relative_to(ROOT)))
    if any(row["status"] == "no_ground_truth" for row in metrics):
        print("Some images have SBOMs but no ground-truth rows for state '" + args.truth_state + "'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
