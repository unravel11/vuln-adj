#!/usr/bin/env python3
"""Independently validate prepare-only JSS T1/T2 V3.1 packets."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import build_t1_human_validation_packet_v3 as v3
import build_t1_human_validation_packet_v3_1 as builder
from analyze_t1_routing_precheck import (
    ACTIONS,
    FIELDS,
    MAIN_FIRST,
    MAIN_SECOND,
    MANUAL_REVIEW_ACTIONS,
    policy_actions,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKET_DIR = builder.DEFAULT_OUTPUT_DIR
EXPECTED_PROTOCOL_ID = builder.PROTOCOL_ID
EXPECTED_PACKET_SCHEMA = builder.PACKET_SCHEMA_VERSION
EXPECTED_MANIFEST_SCHEMA = builder.MANIFEST_SCHEMA_VERSION
EXPECTED_FIELD_VIEW = PROJECT_ROOT / builder.DEFAULT_FIELD_VIEW
EXPECTED_FIELD_VIEW_SHA256 = builder.EXPECTED_FIELD_VIEW_SHA256
EXPECTED_PHASE_COUNTS = builder.EXPECTED_PHASE_COUNTS
EXPECTED_FIELD_COUNTS = {
    "calibration_1": {field: 5 for field in FIELDS},
    "calibration_2": {field: 5 for field in FIELDS},
    "evaluation": {
        "severity": 50,
        "affected_versions": 50,
        "published": 10,
        "references": 10,
    },
}
EXPECTED_EVALUATION_TARGETS = builder.EVALUATION_TARGETS
EXPECTED_CALIBRATION_OBJECTIVES = {
    str(spec["id"]): int(spec["count"]) for spec in builder.CALIBRATION_SPECS
}
REASONS = set(builder.REASONS)
MAIN_POLICIES = set(builder.MAIN_POLICIES)

TOP_LEVEL_KEYS = builder.TOP_LEVEL_KEYS
SIDE_KEYS = builder.SIDE_KEYS
ACTION_ANNOTATION_KEYS = set(builder.ACTION_ANNOTATION)
REASON_ANNOTATION_KEYS = set(builder.REASON_ANNOTATION)
SEVERITY_CONTEXT_KEYS = {"canonical_label", "label", "score", "vector"}
VERSION_RANGE_KEYS = {
    "fixed",
    "introduced",
    "version",
    "version_end_excluding",
    "version_end_including",
    "version_start_excluding",
    "version_start_including",
}
REFERENCE_CONTEXT_KEYS = {"hosts", "urls"}
BANNED_KEY_FRAGMENTS = (
    "baseline",
    "policy",
    "nvd",
    "ghsa",
    "source_id",
    "ai_candidate",
    "ai_label",
    "model_output",
    "codex",
    "deterministic",
    "discrepancy_type",
    "consensus",
    "prior_review",
    "evaluation_weight",
    "selection_cell",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=DEFAULT_PACKET_DIR)
    parser.add_argument(
        "--require-distribution-ready",
        action="store_true",
        help="Fail unless a later approved manifest explicitly permits distribution.",
    )
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_values(values: list[str]) -> str:
    payload = "\n".join(sorted(values)) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"non-object JSON row at {path}:{line_number}")
            rows.append(row)
    return rows


def resolve_input(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def find_banned_keys(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if any(fragment in lowered for fragment in BANNED_KEY_FRAGMENTS):
                found.append(path)
            found.extend(find_banned_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(find_banned_keys(child, f"{prefix}[{index}]"))
    return found


def exact_keys(
    value: Any,
    expected: set[str],
    label: str,
    errors: list[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected object")
        return False
    observed = set(value)
    if observed != expected:
        errors.append(
            f"{label}: keys must equal allowlist; "
            f"unexpected={sorted(observed - expected)} "
            f"missing={sorted(expected - observed)}"
        )
        return False
    return True


def is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def validate_version_ranges(
    value: Any,
    label: str,
    errors: list[str],
) -> None:
    if not isinstance(value, list):
        errors.append(f"{label}: expected version-range list")
        return
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not exact_keys(item, VERSION_RANGE_KEYS, item_label, errors):
            continue
        for key, child in item.items():
            if child is not None and not isinstance(child, str):
                errors.append(f"{item_label}.{key}: expected string or null")


def validate_field_payload(
    field: str,
    side: dict[str, Any],
    label: str,
    errors: list[str],
) -> None:
    value = side["value"]
    context = side["field_context"]
    if field == "severity":
        if value is not None and not isinstance(value, str):
            errors.append(f"{label}.value: expected string or null")
        if exact_keys(
            context, SEVERITY_CONTEXT_KEYS, f"{label}.field_context", errors
        ):
            for key in ("canonical_label", "label", "vector"):
                child = context[key]
                if child is not None and not isinstance(child, str):
                    errors.append(
                        f"{label}.field_context.{key}: expected string or null"
                    )
            score = context["score"]
            if score is not None and (
                isinstance(score, bool) or not isinstance(score, (int, float))
            ):
                errors.append(
                    f"{label}.field_context.score: expected number or null"
                )
    elif field == "affected_versions":
        validate_version_ranges(value, f"{label}.value", errors)
        validate_version_ranges(context, f"{label}.field_context", errors)
    elif field == "published":
        if value is not None and not isinstance(value, str):
            errors.append(f"{label}.value: expected string or null")
        if context is not None and not isinstance(context, str):
            errors.append(f"{label}.field_context: expected string or null")
    elif field == "references":
        if not is_string_list(value):
            errors.append(f"{label}.value: expected string list")
        if exact_keys(
            context, REFERENCE_CONTEXT_KEYS, f"{label}.field_context", errors
        ):
            for key in REFERENCE_CONTEXT_KEYS:
                if not is_string_list(context[key]):
                    errors.append(
                        f"{label}.field_context.{key}: expected string list"
                    )
    else:
        errors.append(f"{label}: unsupported field {field}")
    for key in ("package_names", "reference_urls", "reference_hosts"):
        if not is_string_list(side[key]):
            errors.append(f"{label}.{key}: expected string list")


def validate_packet_row(
    row: dict[str, Any],
    phase: str,
    stage: str,
    position: int,
    label: str,
    errors: list[str],
) -> None:
    if not exact_keys(row, TOP_LEVEL_KEYS, label, errors):
        return
    if row["schema_version"] != EXPECTED_PACKET_SCHEMA:
        errors.append(f"{label}: packet schema mismatch")
    if row["protocol_id"] != EXPECTED_PROTOCOL_ID:
        errors.append(f"{label}: protocol ID mismatch")
    if row["phase"] != phase or row["stage"] != stage:
        errors.append(f"{label}: phase or stage mismatch")
    if row["packet_position"] != position:
        errors.append(f"{label}: packet position mismatch")
    if row["field"] not in FIELDS:
        errors.append(f"{label}: unexpected field")
    if not str(row["cve_id"]).startswith("CVE-"):
        errors.append(f"{label}: invalid CVE ID")
    if not isinstance(row["case_id"], str) or not row["case_id"]:
        errors.append(f"{label}: missing case ID")
    for side_name in ("left", "right"):
        side = row[side_name]
        if exact_keys(side, SIDE_KEYS, f"{label}.{side_name}", errors):
            validate_field_payload(
                row["field"], side, f"{label}.{side_name}", errors
            )
    expected_annotation = (
        ACTION_ANNOTATION_KEYS if stage == "action" else REASON_ANNOTATION_KEYS
    )
    annotation = row["annotation"]
    if exact_keys(
        annotation,
        expected_annotation,
        f"{label}.annotation",
        errors,
    ) and any(value != "" for value in annotation.values()):
        errors.append(f"{label}: preparation packet has a nonblank annotation")
    banned = find_banned_keys(row)
    if banned:
        errors.append(f"{label}: reviewer packet exposes banned keys {banned[:5]}")


def packet_without_stage(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"stage", "packet_position", "annotation"}
    }


def expected_csv_fields(stage: str) -> list[str]:
    annotation_fields = (
        list(builder.ACTION_ANNOTATION)
        if stage == "action"
        else list(builder.REASON_ANNOTATION)
    )
    return [
        "packet_position",
        "case_id",
        "phase",
        "stage",
        "cve_id",
        "field",
        "left_value_json",
        "left_field_context_json",
        "left_package_names_json",
        "left_reference_urls_json",
        "left_reference_hosts_json",
        "right_value_json",
        "right_field_context_json",
        "right_package_names_json",
        "right_reference_urls_json",
        "right_reference_hosts_json",
        *annotation_fields,
    ]


def validate_csv_view(
    path: Path,
    json_rows: list[dict[str, Any]],
    stage: str,
    errors: list[str],
) -> None:
    if not path.is_file():
        errors.append(f"missing CSV packet: {path}")
        return
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        if reader.fieldnames != expected_csv_fields(stage):
            errors.append(f"{path}: CSV columns do not equal allowlist")
    if len(rows) != len(json_rows):
        errors.append(f"{path}: CSV/JSONL row-count mismatch")
        return
    json_by_id = {row["case_id"]: row for row in json_rows}
    if [row.get("case_id") for row in rows] != [
        row["case_id"] for row in json_rows
    ]:
        errors.append(f"{path}: CSV/JSONL case order mismatch")
        return
    annotation_columns = ACTION_ANNOTATION_KEYS | REASON_ANNOTATION_KEYS
    for index, csv_row in enumerate(rows, start=1):
        if any(csv_row.get(column) not in {None, ""} for column in annotation_columns):
            errors.append(f"{path}:{index}: CSV contains nonblank annotation")
        json_row = json_by_id[csv_row["case_id"]]
        scalar_pairs = {
            "packet_position": str(json_row["packet_position"]),
            "phase": json_row["phase"],
            "stage": json_row["stage"],
            "cve_id": json_row["cve_id"],
            "field": json_row["field"],
        }
        if any(csv_row[key] != value for key, value in scalar_pairs.items()):
            errors.append(f"{path}:{index}: CSV scalar content mismatch")
            continue
        for side in ("left", "right"):
            for key in (
                "value",
                "field_context",
                "package_names",
                "reference_urls",
                "reference_hosts",
            ):
                column = f"{side}_{key}_json"
                try:
                    parsed = json.loads(csv_row[column])
                except json.JSONDecodeError:
                    errors.append(f"{path}:{index}: invalid JSON cell {column}")
                    continue
                if parsed != json_row[side][key]:
                    errors.append(f"{path}:{index}: CSV payload mismatch in {column}")


def calibration_objective_matches(row: dict[str, Any]) -> bool:
    objective = row.get("calibration_objective")
    spec = next(
        (item for item in builder.CALIBRATION_SPECS if item["id"] == objective),
        None,
    )
    return bool(spec and v3.calibration_match(row, spec))


def evaluation_cell(field: str, status: str, pair: str) -> str:
    return v3.evaluation_cell(field, status, pair)


def validate_packet_dir(
    packet_dir: Path,
    require_distribution_ready: bool = False,
) -> list[str]:
    errors: list[str] = []
    manifest_path = packet_dir / "manifest.json"
    if not manifest_path.is_file():
        return [f"missing manifest: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"invalid manifest JSON: {exc}"]

    if manifest.get("schema_version") != EXPECTED_MANIFEST_SCHEMA:
        errors.append("manifest schema mismatch")
    if manifest.get("protocol_id") != EXPECTED_PROTOCOL_ID:
        errors.append("manifest protocol ID mismatch")
    if manifest.get("status") != "PREPARATION_ONLY_NOT_FOR_DISTRIBUTION":
        errors.append("unexpected manifest status")
    if manifest.get("distribution_allowed") is not False:
        errors.append("prepare-only manifest must keep distribution_allowed=false")
    if manifest.get("human_labels") != 0 or manifest.get("human_gold") is not False:
        errors.append("prepare-only manifest overstates human-label status")
    if require_distribution_ready and not manifest.get("distribution_allowed"):
        errors.append("distribution is blocked by the current manifest")

    if sha256_file(EXPECTED_FIELD_VIEW) != EXPECTED_FIELD_VIEW_SHA256:
        errors.append("frozen field-view hash mismatch")
    for path_text, expected_hash in manifest.get("input_files", {}).items():
        path = resolve_input(path_text)
        if not path.is_file():
            errors.append(f"missing bound input: {path_text}")
        elif sha256_file(path) != expected_hash:
            errors.append(f"bound input hash mismatch: {path_text}")
    for relative_path, expected_hash in manifest.get("output_sha256", {}).items():
        path = packet_dir / relative_path
        if not path.is_file():
            errors.append(f"missing sealed output: {relative_path}")
        elif sha256_file(path) != expected_hash:
            errors.append(f"sealed output hash mismatch: {relative_path}")

    allowlist = manifest.get("reviewer_visible_schema_allowlist") or {}
    if set(allowlist.get("top_level_keys", [])) != TOP_LEVEL_KEYS:
        errors.append("manifest top-level schema allowlist drift")
    if set(allowlist.get("side_keys", [])) != SIDE_KEYS:
        errors.append("manifest side schema allowlist drift")
    if allowlist.get("unknown_keys_fail_closed_at_every_object_level") is not True:
        errors.append("manifest does not fail closed on unknown reviewer keys")
    exclusions = (
        manifest.get("distribution_file_policy", {}).get("permanently_excluded", [])
    )
    if not any("rq2_primary.review.jsonl" in item for item in exclusions):
        errors.append("legacy answer-leaking packet is not permanently excluded")
    if (
        manifest.get("distribution_file_policy", {}).get(
            "current_revision_allows_no_files"
        )
        is not True
    ):
        errors.append("prepare-only distribution file policy is not fail-closed")

    packets: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {
        reviewer: defaultdict(dict) for reviewer in builder.REVIEWERS
    }
    for reviewer in builder.REVIEWERS:
        for phase in builder.PHASES:
            for stage in builder.STAGES:
                json_path = packet_dir / reviewer / f"{phase}_{stage}_packet.jsonl"
                if not json_path.is_file():
                    errors.append(f"missing reviewer packet: {json_path}")
                    continue
                try:
                    rows = load_jsonl(json_path)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                packets[reviewer][phase][stage] = rows
                if len(rows) != EXPECTED_PHASE_COUNTS[phase]:
                    errors.append(
                        f"{reviewer}/{phase}/{stage}: expected "
                        f"{EXPECTED_PHASE_COUNTS[phase]}, observed {len(rows)}"
                    )
                counts = Counter(row.get("field") for row in rows)
                if dict(counts) != EXPECTED_FIELD_COUNTS[phase]:
                    errors.append(
                        f"{reviewer}/{phase}/{stage}: field allocation drift"
                    )
                case_ids = [row.get("case_id") for row in rows]
                if len(set(case_ids)) != len(case_ids):
                    errors.append(f"{reviewer}/{phase}/{stage}: duplicate case IDs")
                for position, row in enumerate(rows, start=1):
                    validate_packet_row(
                        row,
                        phase,
                        stage,
                        position,
                        f"{reviewer}/{phase}/{stage}:{position}",
                        errors,
                    )
                validate_csv_view(
                    packet_dir / reviewer / f"{phase}_{stage}_packet.csv",
                    rows,
                    stage,
                    errors,
                )

    for phase in builder.PHASES:
        for reviewer in builder.REVIEWERS:
            action_rows = packets[reviewer][phase].get("action", [])
            reason_rows = packets[reviewer][phase].get("reason", [])
            action_by_id = {row.get("case_id"): row for row in action_rows}
            reason_by_id = {row.get("case_id"): row for row in reason_rows}
            if set(action_by_id) != set(reason_by_id):
                errors.append(f"{reviewer}/{phase}: stage case sets differ")
            for case_id in set(action_by_id) & set(reason_by_id):
                if packet_without_stage(action_by_id[case_id]) != packet_without_stage(
                    reason_by_id[case_id]
                ):
                    errors.append(f"{reviewer}/{phase}/{case_id}: stage content differs")
                    break
        for stage in builder.STAGES:
            rows_a = packets["reviewer_a"][phase].get(stage, [])
            rows_b = packets["reviewer_b"][phase].get(stage, [])
            by_id_a = {row.get("case_id"): row for row in rows_a}
            by_id_b = {row.get("case_id"): row for row in rows_b}
            if set(by_id_a) != set(by_id_b):
                errors.append(f"{phase}/{stage}: reviewer case sets differ")
            if [row.get("case_id") for row in rows_a] == [
                row.get("case_id") for row in rows_b
            ]:
                errors.append(f"{phase}/{stage}: reviewer orders are identical")
            for case_id in set(by_id_a) & set(by_id_b):
                if packet_without_stage(by_id_a[case_id]) != packet_without_stage(
                    by_id_b[case_id]
                ):
                    errors.append(
                        f"{phase}/{stage}/{case_id}: reviewer content differs"
                    )
                    break

    frame_path = packet_dir / str(manifest.get("internal_sampling_frame", ""))
    mapping_path = packet_dir / str(manifest.get("internal_mapping", ""))
    safety_path = packet_dir / str(
        manifest.get("shared_no_manual_route_audit", {}).get("internal_file", "")
    )
    try:
        frame_rows = load_jsonl(frame_path)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot load frozen sampling frame: {exc}")
        frame_rows = []
    try:
        mapping_rows = load_jsonl(mapping_path)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot load sealed mapping: {exc}")
        mapping_rows = []
    try:
        safety_rows = load_jsonl(safety_path)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot load shared-no-manual audit: {exc}")
        safety_rows = []

    if len(frame_rows) != 160:
        errors.append(f"sampling frame must contain 160 rows, observed {len(frame_rows)}")
    if len(mapping_rows) != 160:
        errors.append(f"sealed mapping must contain 160 rows, observed {len(mapping_rows)}")
    sample_ids = [row.get("sample_id") for row in frame_rows]
    if len(set(sample_ids)) != len(sample_ids):
        errors.append("sampling-frame sample IDs are not unique")
    phase_counts = Counter(row.get("phase") for row in frame_rows)
    if dict(phase_counts) != EXPECTED_PHASE_COUNTS:
        errors.append(f"sampling-frame phase counts drifted: {dict(phase_counts)}")
    phase_cves: dict[str, set[str]] = {}
    for phase in builder.PHASES:
        rows = [row for row in frame_rows if row.get("phase") == phase]
        counts = Counter(row.get("field") for row in rows)
        if dict(counts) != EXPECTED_FIELD_COUNTS[phase]:
            errors.append(f"sampling-frame {phase} field counts drifted")
        cves = {str(row.get("cve_id")) for row in rows}
        phase_cves[phase] = cves
        if len(cves) != len(rows):
            errors.append(f"{phase}: CVE IDs are not unique")
        manifest_phase = manifest.get("phase_cve_audit", {}).get(phase, {})
        if manifest_phase.get("cve_id_set_sha256") != sha256_values(list(cves)):
            errors.append(f"{phase}: manifest CVE-set hash mismatch")
    for index, first in enumerate(builder.PHASES):
        for second in builder.PHASES[index + 1 :]:
            if phase_cves.get(first, set()) & phase_cves.get(second, set()):
                errors.append(f"CVE overlap between {first} and {second}")

    try:
        source_rows = v3.load_jsonl(EXPECTED_FIELD_VIEW)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot load frozen source: {exc}")
        source_rows = []
    population_cells: dict[str, Counter[str]] = defaultdict(Counter)
    for source_row in source_rows:
        unified = source_row.get("unified_view") or {}
        discrepancies = source_row.get("field_discrepancies") or {}
        policy_view = dict(unified)
        policy_view["field_discrepancies"] = discrepancies
        for field in FIELDS:
            status = discrepancies[field]["status"]
            actions = policy_actions(policy_view, field)
            pair = f"{actions[MAIN_FIRST]}->{actions[MAIN_SECOND]}"
            population_cells[field][evaluation_cell(field, status, pair)] += 1

    core_keys = (
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
        "policy_actions",
        "main_action_pair",
        "evaluation_cell",
    )
    for frame_row in frame_rows:
        source_line = int(frame_row.get("source_line_number", 0))
        field = frame_row.get("field")
        if not 1 <= source_line <= len(source_rows) or field not in FIELDS:
            errors.append(f"{frame_row.get('sample_id')}: invalid source binding")
            continue
        source = source_rows[source_line - 1]
        unified = source["unified_view"]
        discrepancies = source["field_discrepancies"]
        discrepancy = discrepancies[field]
        policy_view = dict(unified)
        policy_view["field_discrepancies"] = discrepancies
        actions = policy_actions(policy_view, field)
        pair = f"{actions[MAIN_FIRST]}->{actions[MAIN_SECOND]}"
        current = {
            "cve_id": source.get("cve_id"),
            "nvd_source_id": source.get("nvd_source_id"),
            "ghsa_source_id": source.get("ghsa_source_id"),
            "baseline_status": discrepancy.get("status"),
            "baseline_note": discrepancy.get("note"),
            "nvd_value": discrepancy.get("nvd_value"),
            "ghsa_value": discrepancy.get("ghsa_value"),
            "field_context": unified.get(field),
            "package_names": unified.get("package_names"),
            "reference_context": unified.get("references"),
            "policy_actions": actions,
            "main_action_pair": pair,
            "evaluation_cell": evaluation_cell(field, discrepancy["status"], pair),
        }
        if any(frame_row.get(key) != current[key] for key in core_keys):
            errors.append(f"{frame_row.get('sample_id')}: frame/source mismatch")
            break

    evaluation_rows = [
        row for row in frame_rows if row.get("phase") == "evaluation"
    ]
    selected_cells: dict[str, Counter[str]] = defaultdict(Counter)
    for row in evaluation_rows:
        field = row["field"]
        cell = row.get("selection_cell")
        selected_cells[field][cell] += 1
        target = EXPECTED_EVALUATION_TARGETS.get(field, {}).get(cell)
        population_count = population_cells[field][cell]
        if cell != row.get("evaluation_cell") or target is None:
            errors.append(f"{row.get('sample_id')}: invalid evaluation cell")
            continue
        if row.get("population_count") != population_count:
            errors.append(f"{row.get('sample_id')}: population count mismatch")
        if row.get("selection_count") != target:
            errors.append(f"{row.get('sample_id')}: selection count mismatch")
        if abs(float(row.get("evaluation_weight")) - population_count / target) > 1e-12:
            errors.append(f"{row.get('sample_id')}: evaluation weight mismatch")
    for field in FIELDS:
        if dict(selected_cells[field]) != EXPECTED_EVALUATION_TARGETS[field]:
            errors.append(f"{field}: selected evaluation cells drifted")

    for phase in ("calibration_1", "calibration_2"):
        rows = [row for row in frame_rows if row.get("phase") == phase]
        objective_counts = Counter(
            row.get("calibration_objective") for row in rows
        )
        if dict(objective_counts) != EXPECTED_CALIBRATION_OBJECTIVES:
            errors.append(f"{phase}: calibration objectives drifted")
        if any(not calibration_objective_matches(row) for row in rows):
            errors.append(f"{phase}: calibration objective mismatch")
        try:
            v3.calibration_proxy_coverage(rows)
        except ValueError as exc:
            errors.append(f"{phase}: {exc}")

    mapping_case_ids = [row.get("case_id") for row in mapping_rows]
    mapping_sample_ids = [row.get("source_sample_id") for row in mapping_rows]
    if len(set(mapping_case_ids)) != len(mapping_case_ids):
        errors.append("sealed mapping case IDs are not unique")
    if len(set(mapping_sample_ids)) != len(mapping_sample_ids):
        errors.append("sealed mapping sample IDs are not unique")
    if set(mapping_sample_ids) != set(sample_ids):
        errors.append("sealed mapping and sampling-frame IDs differ")
    packet_case_ids = {
        row.get("case_id")
        for phase_packets in packets["reviewer_a"].values()
        for stage_rows in phase_packets.values()
        for row in stage_rows
    }
    if set(mapping_case_ids) != packet_case_ids:
        errors.append("sealed mapping and reviewer packet case sets differ")

    frame_by_id = {row.get("sample_id"): row for row in frame_rows}
    packet_by_id = {
        row.get("case_id"): row
        for phase_packets in packets["reviewer_a"].values()
        for row in phase_packets.get("action", [])
    }
    for mapping in mapping_rows:
        frame = frame_by_id.get(mapping.get("source_sample_id"))
        packet = packet_by_id.get(mapping.get("case_id"))
        if not frame or not packet:
            continue
        left_source = mapping.get("left_source")
        right_source = mapping.get("right_source")
        if {left_source, right_source} != {"nvd", "ghsa"}:
            errors.append(f"{mapping.get('case_id')}: invalid side mapping")
            continue
        if (
            packet.get("cve_id") != frame.get("cve_id")
            or packet.get("field") != frame.get("field")
            or packet.get("phase") != frame.get("phase")
            or packet.get("left") != v3.side_context(frame, left_source)
            or packet.get("right") != v3.side_context(frame, right_source)
        ):
            errors.append(f"{mapping.get('case_id')}: packet/mapping mismatch")
            break

    if len(safety_rows) != 34:
        errors.append(f"shared-no-manual audit must have 34 rows, observed {len(safety_rows)}")
    if Counter(row.get("field") for row in safety_rows) != Counter(
        {"severity": 15, "affected_versions": 19}
    ):
        errors.append("shared-no-manual field counts drifted")
    mapping_by_sample = {
        row["source_sample_id"]: row for row in mapping_rows
    }
    for row in safety_rows:
        if set(row) != {
            "case_id",
            "source_sample_id",
            "cve_id",
            "field",
            "selection_cell",
            "evaluation_weight",
            "field_aware_simple_v1",
            "type_first_abstention_v1",
        }:
            errors.append("shared-no-manual internal schema drifted")
            break
        if (
            row["field_aware_simple_v1"] in MANUAL_REVIEW_ACTIONS
            or row["type_first_abstention_v1"] in MANUAL_REVIEW_ACTIONS
        ):
            errors.append(f"{row['case_id']}: safety audit contains manual route")
        mapping = mapping_by_sample.get(row["source_sample_id"])
        if not mapping or mapping["case_id"] != row["case_id"]:
            errors.append(f"{row['case_id']}: safety audit mapping mismatch")
    safety_manifest = manifest.get("shared_no_manual_route_audit", {})
    if safety_manifest.get("source_sample_id_set_sha256") != sha256_values(
        [row["source_sample_id"] for row in safety_rows]
    ):
        errors.append("shared-no-manual source-case hash mismatch")
    if safety_manifest.get("reviewer_case_id_set_sha256") != sha256_values(
        [row["case_id"] for row in safety_rows]
    ):
        errors.append("shared-no-manual reviewer-case hash mismatch")
    if safety_manifest.get("reviewer_visible_flag_present") is not False:
        errors.append("shared safety stratum must not be flagged to reviewers")
    if safety_manifest.get("population_rate_identified") is not False:
        errors.append("manifest overstates shared-miss population identification")

    if set(manifest.get("actions", [])) != set(ACTIONS):
        errors.append("manifest action vocabulary drifted")
    if set(manifest.get("reasons", [])) != REASONS:
        errors.append("manifest reason vocabulary drifted")
    if any(
        value is not False
        for value in (manifest.get("claim_ceiling") or {}).values()
    ):
        errors.append("prepare-only claim ceiling contains a positive claim")
    return errors


def main() -> int:
    args = parse_args()
    errors = validate_packet_dir(
        resolve(args.packet_dir),
        require_distribution_ready=args.require_distribution_ready,
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2
    print(
        "PASS: V3.1 packets are recursively allowlisted and internally sealed; "
        "calibration_1=20 calibration_2_reserve=20 evaluation=120 "
        "distribution_allowed=false human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
