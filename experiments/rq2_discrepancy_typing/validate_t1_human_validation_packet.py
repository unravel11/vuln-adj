#!/usr/bin/env python3
"""Independently validate JSS T1 baseline-blinded preparation packets."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKET_DIR = "data/annotations/rq2/t1_human_validation_v2"
EXPECTED_PROTOCOL_ID = "vuln-adj-jss-t1-human-validation-v2"
EXPECTED_PACKET_SCHEMA = "t1_human_review_packet_v1"
EXPECTED_MANIFEST_SCHEMA = "t1_packet_manifest_v1"
EXPECTED_FIELDS = {
    "severity",
    "published",
    "references",
    "affected_versions",
    "cwe_ids",
}
EXPECTED_PHASE_COUNTS = {"calibration": 50, "evaluation": 250}
EXPECTED_PER_FIELD = {"calibration": 10, "evaluation": 50}

TOP_LEVEL_KEYS = {
    "schema_version",
    "protocol_id",
    "phase",
    "packet_position",
    "case_id",
    "cve_id",
    "field",
    "left",
    "right",
    "annotation",
}
SIDE_KEYS = {
    "value",
    "field_context",
    "package_names",
    "reference_urls",
    "reference_hosts",
}
ANNOTATION_KEYS = {
    "label",
    "rationale",
    "uncertainty_reason",
    "reviewer_notes",
}
BANNED_KEY_FRAGMENTS = (
    "baseline",
    "nvd",
    "ghsa",
    "nvd_source",
    "ghsa_source",
    "ai_label",
    "codex",
    "consensus",
    "prior_review",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate prepare-only T1 reviewer packets and their seals."
    )
    parser.add_argument("--packet-dir", default=DEFAULT_PACKET_DIR)
    parser.add_argument(
        "--require-distribution-ready",
        action="store_true",
        help="Fail unless the manifest explicitly allows distribution.",
    )
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
    return rows


def find_banned_keys(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(fragment in lowered for fragment in BANNED_KEY_FRAGMENTS):
                found.append(path)
            found.extend(find_banned_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_banned_keys(child, f"{prefix}[{index}]"))
    return found


def validate_packet_row(
    row: dict[str, Any],
    phase: str,
    expected_position: int,
    path: Path,
    errors: list[str],
) -> None:
    label = f"{path.name}:{expected_position}"
    if set(row) != TOP_LEVEL_KEYS:
        errors.append(f"{label}: unexpected top-level keys {sorted(set(row))}")
        return
    if row["schema_version"] != EXPECTED_PACKET_SCHEMA:
        errors.append(f"{label}: invalid packet schema")
    if row["protocol_id"] != EXPECTED_PROTOCOL_ID:
        errors.append(f"{label}: invalid protocol ID")
    if row["phase"] != phase:
        errors.append(f"{label}: phase mismatch")
    if row["packet_position"] != expected_position:
        errors.append(f"{label}: packet_position mismatch")
    if row["field"] not in EXPECTED_FIELDS:
        errors.append(f"{label}: unexpected field {row['field']}")
    if not isinstance(row["case_id"], str) or not row["case_id"]:
        errors.append(f"{label}: missing case_id")
    if not isinstance(row["cve_id"], str) or not row["cve_id"].startswith("CVE-"):
        errors.append(f"{label}: invalid cve_id")
    for side in ("left", "right"):
        if not isinstance(row[side], dict) or set(row[side]) != SIDE_KEYS:
            errors.append(f"{label}: invalid {side} side keys")
    annotation = row["annotation"]
    if not isinstance(annotation, dict) or set(annotation) != ANNOTATION_KEYS:
        errors.append(f"{label}: invalid annotation template")
    elif any(value != "" for value in annotation.values()):
        errors.append(f"{label}: preparation packet contains a non-blank annotation")
    banned = find_banned_keys(row)
    if banned:
        errors.append(f"{label}: reviewer packet exposes banned keys {banned[:5]}")


def resolve_input_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def side_payload(frame_row: dict[str, Any], source: str) -> dict[str, Any]:
    field_context = frame_row.get("field_context")
    if isinstance(field_context, dict) and source in field_context:
        field_context = field_context[source]
    elif isinstance(field_context, dict):
        prefixed_keys = [
            key
            for key in field_context
            if str(key).startswith("nvd_") or str(key).startswith("ghsa_")
        ]
        if prefixed_keys:
            neutral_context = {
                str(key)[len(source) + 1 :]: value
                for key, value in field_context.items()
                if str(key).startswith(f"{source}_")
            }
            neutral_context.update(
                {
                    key: value
                    for key, value in field_context.items()
                    if not str(key).startswith("nvd_")
                    and not str(key).startswith("ghsa_")
                }
            )
            field_context = neutral_context
    package_names = frame_row.get("package_names") or {}
    references = frame_row.get("reference_context") or {}
    return {
        "value": frame_row[f"{source}_value"],
        "field_context": field_context,
        "package_names": package_names.get(source, []),
        "reference_urls": references.get(f"{source}_urls", []),
        "reference_hosts": references.get(f"{source}_hosts", []),
    }


def validate_packet_dir(
    packet_dir: Path, require_distribution_ready: bool = False
) -> list[str]:
    errors: list[str] = []
    manifest_path = packet_dir / "manifest.json"
    if not manifest_path.is_file():
        return [f"Missing manifest: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"Invalid manifest JSON: {exc}"]

    if manifest.get("schema_version") != EXPECTED_MANIFEST_SCHEMA:
        errors.append("Invalid manifest schema")
    if manifest.get("protocol_id") != EXPECTED_PROTOCOL_ID:
        errors.append("Invalid manifest protocol ID")
    if manifest.get("status") != "PREPARATION_ONLY_NOT_FOR_DISTRIBUTION":
        errors.append("Unexpected preparation status")
    if manifest.get("distribution_allowed") is not False:
        errors.append("Preparation manifest must keep distribution_allowed=false")
    if require_distribution_ready and not manifest.get("distribution_allowed"):
        errors.append("Distribution is blocked by the current manifest")

    for path_text, expected in manifest.get("input_files", {}).items():
        path = resolve_input_path(path_text)
        if not path.is_file():
            errors.append(f"Missing bound input file: {path_text}")
        elif sha256_file(path) != expected:
            errors.append(f"Bound input hash mismatch: {path_text}")

    for relative_path, expected in manifest.get("output_sha256", {}).items():
        path = packet_dir / relative_path
        if not path.is_file():
            errors.append(f"Missing sealed output: {relative_path}")
        elif sha256_file(path) != expected:
            errors.append(f"Sealed output hash mismatch: {relative_path}")

    packets: dict[str, dict[str, list[dict[str, Any]]]] = {
        "reviewer_a": {},
        "reviewer_b": {},
    }
    for reviewer in ("reviewer_a", "reviewer_b"):
        for phase in ("calibration", "evaluation"):
            path = packet_dir / reviewer / f"{phase}_packet.jsonl"
            if not path.is_file():
                errors.append(f"Missing reviewer packet: {path}")
                continue
            try:
                rows = load_jsonl(path)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            packets[reviewer][phase] = rows
            if len(rows) != EXPECTED_PHASE_COUNTS[phase]:
                errors.append(
                    f"{reviewer}/{phase}: expected {EXPECTED_PHASE_COUNTS[phase]} "
                    f"rows, observed {len(rows)}"
                )
            field_counts = Counter(row.get("field") for row in rows)
            expected_field_counts = {
                field: EXPECTED_PER_FIELD[phase] for field in EXPECTED_FIELDS
            }
            if dict(field_counts) != expected_field_counts:
                errors.append(
                    f"{reviewer}/{phase}: unexpected field counts "
                    f"{dict(field_counts)}"
                )
            case_ids = [row.get("case_id") for row in rows]
            if len(set(case_ids)) != len(case_ids):
                errors.append(f"{reviewer}/{phase}: duplicate case IDs")
            for position, row in enumerate(rows, start=1):
                validate_packet_row(row, phase, position, path, errors)

    for phase in ("calibration", "evaluation"):
        rows_a = packets["reviewer_a"].get(phase, [])
        rows_b = packets["reviewer_b"].get(phase, [])
        ids_a = [row.get("case_id") for row in rows_a]
        ids_b = [row.get("case_id") for row in rows_b]
        if set(ids_a) != set(ids_b):
            errors.append(f"{phase}: reviewer A/B case sets differ")
        if ids_a == ids_b:
            errors.append(f"{phase}: reviewer A/B orders are identical")
        by_id_a = {row.get("case_id"): row for row in rows_a}
        by_id_b = {row.get("case_id"): row for row in rows_b}
        for case_id in set(by_id_a) & set(by_id_b):
            normalized_a = dict(by_id_a[case_id])
            normalized_b = dict(by_id_b[case_id])
            normalized_a["packet_position"] = 0
            normalized_b["packet_position"] = 0
            if normalized_a != normalized_b:
                errors.append(f"{phase}/{case_id}: reviewer packet content differs")
                break

    frame_path = packet_dir / str(manifest.get("internal_sampling_frame", ""))
    if not frame_path.is_file():
        errors.append("Missing internal frozen sampling frame")
        frame_rows: list[dict[str, Any]] = []
    else:
        try:
            frame_rows = load_jsonl(frame_path)
        except ValueError as exc:
            errors.append(str(exc))
            frame_rows = []

    if len(frame_rows) != 300:
        errors.append(
            f"Frozen sampling frame must contain 300 rows, observed {len(frame_rows)}"
        )
    frame_sample_ids = [row.get("sample_id") for row in frame_rows]
    if len(set(frame_sample_ids)) != len(frame_sample_ids):
        errors.append("Frozen sampling-frame IDs are not unique")
    frame_field_counts = Counter(row.get("field") for row in frame_rows)
    if dict(frame_field_counts) != {field: 60 for field in EXPECTED_FIELDS}:
        errors.append(
            f"Unexpected frozen sampling-frame field counts: {dict(frame_field_counts)}"
        )

    field_view_path = PROJECT_ROOT / (
        "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
    )
    try:
        source_rows = load_jsonl(field_view_path)
    except (OSError, ValueError) as exc:
        errors.append(f"Cannot load frozen field view: {exc}")
        source_rows = []

    full_context_keys = (
        "cve_id",
        "nvd_source_id",
        "ghsa_source_id",
        "baseline_status",
        "baseline_note",
        "nvd_value",
        "ghsa_value",
        "field_context",
        "package_names",
        "reference_context",
    )
    for frame_row in frame_rows:
        source_line_number = int(frame_row.get("source_line_number", 0))
        field = frame_row.get("field")
        if not 1 <= source_line_number <= len(source_rows) or field not in EXPECTED_FIELDS:
            errors.append(
                f"{frame_row.get('sample_id')}: invalid source-line or field binding"
            )
            continue
        source_row = source_rows[source_line_number - 1]
        discrepancy = source_row["field_discrepancies"][field]
        unified_view = source_row["unified_view"]
        current = {
            "cve_id": source_row.get("cve_id"),
            "nvd_source_id": source_row.get("nvd_source_id"),
            "ghsa_source_id": source_row.get("ghsa_source_id"),
            "baseline_status": discrepancy.get("status"),
            "baseline_note": discrepancy.get("note"),
            "nvd_value": discrepancy.get("nvd_value"),
            "ghsa_value": discrepancy.get("ghsa_value"),
            "field_context": unified_view.get(field),
            "package_names": unified_view.get("package_names"),
            "reference_context": unified_view.get("references"),
        }
        if any(frame_row.get(key) != current[key] for key in full_context_keys):
            errors.append(
                f"{frame_row.get('sample_id')}: frozen frame does not match current input"
            )
            break

    mapping_path = packet_dir / str(manifest.get("internal_mapping", ""))
    if not mapping_path.is_file():
        errors.append("Missing internal sealed mapping")
        mapping_rows: list[dict[str, Any]] = []
    else:
        try:
            mapping_rows = load_jsonl(mapping_path)
        except ValueError as exc:
            errors.append(str(exc))
            mapping_rows = []

    if len(mapping_rows) != 300:
        errors.append(f"Internal mapping must contain 300 rows, observed {len(mapping_rows)}")
    mapping_case_ids = [row.get("case_id") for row in mapping_rows]
    mapping_sample_ids = [row.get("source_sample_id") for row in mapping_rows]
    if len(set(mapping_case_ids)) != len(mapping_case_ids):
        errors.append("Internal mapping case IDs are not unique")
    if len(set(mapping_sample_ids)) != len(mapping_sample_ids):
        errors.append("Internal mapping source sample IDs are not unique")
    if set(mapping_sample_ids) != set(frame_sample_ids):
        errors.append("Internal mapping and frozen sampling-frame IDs differ")

    phase_counts = Counter(row.get("phase") for row in mapping_rows)
    if dict(phase_counts) != EXPECTED_PHASE_COUNTS:
        errors.append(f"Unexpected internal phase counts: {dict(phase_counts)}")
    for row in mapping_rows:
        if {row.get("left_source"), row.get("right_source")} != {"nvd", "ghsa"}:
            errors.append(f"{row.get('case_id')}: invalid internal side mapping")
            break
        positions = row.get("reviewer_positions")
        if not isinstance(positions, dict) or set(positions) != {
            "reviewer_a",
            "reviewer_b",
        }:
            errors.append(f"{row.get('case_id')}: invalid reviewer positions")
            break

    packet_case_ids = {
        row.get("case_id")
        for reviewer_packets in packets.values()
        for rows in reviewer_packets.values()
        for row in rows
    }
    if set(mapping_case_ids) != packet_case_ids:
        errors.append("Internal mapping and reviewer packet case sets differ")

    frame_by_sample_id = {row.get("sample_id"): row for row in frame_rows}
    packet_by_case_id = {
        row.get("case_id"): row
        for phase_rows in packets["reviewer_a"].values()
        for row in phase_rows
    }
    for mapping_row in mapping_rows:
        frame_row = frame_by_sample_id.get(mapping_row.get("source_sample_id"))
        packet_row = packet_by_case_id.get(mapping_row.get("case_id"))
        if not frame_row or not packet_row:
            continue
        left_source = mapping_row.get("left_source")
        right_source = mapping_row.get("right_source")
        if {left_source, right_source} != {"nvd", "ghsa"}:
            continue
        if (
            packet_row.get("cve_id") != frame_row.get("cve_id")
            or packet_row.get("field") != frame_row.get("field")
            or packet_row.get("phase") != mapping_row.get("phase")
            or packet_row.get("left")
            != side_payload(frame_row, left_source)
            or packet_row.get("right")
            != side_payload(frame_row, right_source)
        ):
            errors.append(
                f"{mapping_row.get('case_id')}: packet content does not match sealed mapping"
            )
            break

    population_counts: Counter[tuple[str, str]] = Counter()
    for source_row in source_rows:
        for field in EXPECTED_FIELDS:
            population_counts[
                (field, source_row["field_discrepancies"][field]["status"])
            ] += 1
    sample_counts = Counter(
        (row.get("field"), row.get("baseline_status")) for row in frame_rows
    )
    for stratum in manifest.get("strata", []):
        if int(stratum.get("evaluation_count", 0)) <= 0:
            errors.append(
                "A sampled stratum has no evaluation row: "
                f"{stratum.get('field')}/{stratum.get('baseline_status')}"
            )
        population_count = int(stratum.get("population_count", 0))
        sample_count = int(stratum.get("seed_count", 0))
        evaluation_count = int(stratum.get("evaluation_count", 0))
        observed_weight = float(stratum.get("evaluation_weight", 0))
        key = (stratum.get("field"), stratum.get("baseline_status"))
        if population_counts[key] != population_count:
            errors.append(
                f"Population count mismatch for {key}: "
                f"{population_count} != {population_counts[key]}"
            )
        if sample_counts[key] != sample_count:
            errors.append(
                f"Sample count mismatch for {key}: "
                f"{sample_count} != {sample_counts[key]}"
            )
        if evaluation_count > 0:
            expected_weight = population_count / evaluation_count
            if abs(observed_weight - expected_weight) > 1e-12:
                errors.append(
                    "Invalid evaluation weight: "
                    f"{stratum.get('field')}/{stratum.get('baseline_status')}"
                )

    return errors


def main() -> int:
    args = parse_args()
    packet_dir = resolve_path(args.packet_dir)
    errors = validate_packet_dir(
        packet_dir, require_distribution_ready=args.require_distribution_ready
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    print(
        "PASS: T1 prepare-only packets are internally consistent; "
        "distribution_allowed=false; human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
