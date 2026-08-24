#!/usr/bin/env python3
"""Independently validate the prepare-only JSS T1/T2 V3 packet."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from analyze_t1_routing_precheck import ACTIONS, FIELDS, MAIN_FIRST, MAIN_SECOND, policy_actions


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKET_DIR = "data/annotations/rq2/t1_human_validation_v3"
EXPECTED_PROTOCOL_ID = "vuln-adj-jss-t1-human-validation-v3"
EXPECTED_PACKET_SCHEMA = "t1_action_reason_packet_v3"
EXPECTED_MANIFEST_SCHEMA = "t1_action_reason_manifest_v3"
EXPECTED_FIELD_VIEW = (
    PROJECT_ROOT
    / "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
EXPECTED_FIELD_VIEW_SHA256 = (
    "c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2"
)
EXPECTED_PHASE_COUNTS = {"calibration": 20, "evaluation": 120}
EXPECTED_FIELD_COUNTS = {
    "calibration": {field: 5 for field in FIELDS},
    "evaluation": {
        "severity": 50,
        "affected_versions": 50,
        "published": 10,
        "references": 10,
    },
}
EXPECTED_EVALUATION_TARGETS: dict[str, dict[str, int]] = {
    "severity": {
        "disagreement|factual_conflict|conflict_escalation->abstain": 25,
        "disagreement|representation_discrepancy|abstain->no_action": 5,
        "agreement|equivalent": 5,
        "agreement|representation_discrepancy": 5,
        "agreement|incomplete": 5,
        "agreement|factual_conflict": 5,
    },
    "affected_versions": {
        "disagreement|abstain->no_action": 6,
        "disagreement|enrich_record->abstain": 6,
        "disagreement|enrich_record->conflict_escalation": 6,
        "disagreement|enrich_record->no_action": 6,
        "disagreement|no_action->abstain": 6,
        "agreement|equivalent": 5,
        "agreement|representation_discrepancy": 5,
        "agreement|incomplete": 5,
        "agreement|factual_conflict": 5,
    },
    "published": {
        "status|representation_discrepancy": 5,
        "status|temporal_discrepancy": 5,
    },
    "references": {
        "status|factual_conflict": 3,
        "status|representation_discrepancy": 4,
        "status|incomplete": 3,
    },
}
EXPECTED_CALIBRATION_OBJECTIVES = {
    "severity_equivalent_agreement": 2,
    "severity_incomplete_agreement": 1,
    "severity_conflict_agreement": 1,
    "severity_conflict_abstention": 1,
    "affected_abstain_to_no_action": 1,
    "affected_enrich_to_abstain": 1,
    "affected_enrich_to_conflict": 1,
    "affected_enrich_to_no_action": 1,
    "affected_equivalent_no_action_to_abstain": 1,
    "published_representation_control": 2,
    "published_temporal_control": 3,
    "references_representation_control": 2,
    "references_incomplete_control": 3,
}
REASONS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
MAIN_POLICIES = {
    "field_aware_simple_v1",
    "type_first_current_v1",
    "type_first_abstention_v1",
}

TOP_LEVEL_KEYS = {
    "schema_version",
    "protocol_id",
    "phase",
    "stage",
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
ACTION_ANNOTATION_KEYS = {
    "action_label",
    "action_rationale",
    "action_uncertainty",
    "reviewer_notes",
}
REASON_ANNOTATION_KEYS = {
    "reason_label",
    "reason_rationale",
    "reason_uncertainty",
    "reviewer_notes",
}
BANNED_KEY_FRAGMENTS = (
    "baseline",
    "policy",
    "nvd",
    "ghsa",
    "source_id",
    "ai_label",
    "codex",
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
        help="Fail unless an approved manifest explicitly allows distribution.",
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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
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


def evaluation_cell(field: str, status: str, pair: str) -> str:
    left, right = pair.split("->", 1)
    disagreement = left != right
    if field == "severity":
        return (
            f"disagreement|{status}|{pair}"
            if disagreement
            else f"agreement|{status}"
        )
    if field == "affected_versions":
        return f"disagreement|{pair}" if disagreement else f"agreement|{status}"
    if field in {"published", "references"}:
        return f"status|{status}"
    raise ValueError(f"unsupported field: {field}")


def side_payload(frame_row: dict[str, Any], source: str) -> dict[str, Any]:
    field_context = frame_row.get("field_context")
    if isinstance(field_context, dict) and source in field_context:
        field_context = field_context[source]
    elif isinstance(field_context, dict):
        prefixed = [
            key
            for key in field_context
            if str(key).startswith("nvd_") or str(key).startswith("ghsa_")
        ]
        if prefixed:
            neutral = {
                str(key)[len(source) + 1 :]: value
                for key, value in field_context.items()
                if str(key).startswith(f"{source}_")
            }
            neutral.update(
                {
                    key: value
                    for key, value in field_context.items()
                    if not str(key).startswith("nvd_")
                    and not str(key).startswith("ghsa_")
                }
            )
            field_context = neutral
    package_names = frame_row.get("package_names") or {}
    references = frame_row.get("reference_context") or {}
    return {
        "value": frame_row[f"{source}_value"],
        "field_context": field_context,
        "package_names": package_names.get(source, []),
        "reference_urls": references.get(f"{source}_urls", []),
        "reference_hosts": references.get(f"{source}_hosts", []),
    }


def validate_packet_row(
    row: dict[str, Any],
    phase: str,
    stage: str,
    position: int,
    label: str,
    errors: list[str],
) -> None:
    if set(row) != TOP_LEVEL_KEYS:
        errors.append(f"{label}: unexpected top-level keys {sorted(set(row))}")
        return
    if row.get("schema_version") != EXPECTED_PACKET_SCHEMA:
        errors.append(f"{label}: packet schema mismatch")
    if row.get("protocol_id") != EXPECTED_PROTOCOL_ID:
        errors.append(f"{label}: protocol ID mismatch")
    if row.get("phase") != phase or row.get("stage") != stage:
        errors.append(f"{label}: phase or stage mismatch")
    if row.get("packet_position") != position:
        errors.append(f"{label}: packet position mismatch")
    if row.get("field") not in FIELDS:
        errors.append(f"{label}: unexpected field")
    if not str(row.get("cve_id", "")).startswith("CVE-"):
        errors.append(f"{label}: invalid CVE ID")
    if not isinstance(row.get("case_id"), str) or not row["case_id"]:
        errors.append(f"{label}: missing case ID")
    for side in ("left", "right"):
        if not isinstance(row.get(side), dict) or set(row[side]) != SIDE_KEYS:
            errors.append(f"{label}: invalid {side} payload")
    expected_annotation = (
        ACTION_ANNOTATION_KEYS if stage == "action" else REASON_ANNOTATION_KEYS
    )
    annotation = row.get("annotation")
    if not isinstance(annotation, dict) or set(annotation) != expected_annotation:
        errors.append(f"{label}: invalid annotation schema")
    elif any(value != "" for value in annotation.values()):
        errors.append(f"{label}: preparation packet contains a nonblank label")
    banned = find_banned_keys(row)
    if banned:
        errors.append(f"{label}: reviewer packet exposes banned keys {banned[:5]}")


def packet_without_stage(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"stage", "packet_position", "annotation"}
    }


def validate_csv_view(
    path: Path, json_rows: list[dict[str, Any]], errors: list[str]
) -> None:
    if not path.is_file():
        errors.append(f"missing CSV packet: {path}")
        return
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != len(json_rows):
        errors.append(f"{path}: CSV/JSONL row-count mismatch")
        return
    if [row.get("case_id") for row in rows] != [
        row.get("case_id") for row in json_rows
    ]:
        errors.append(f"{path}: CSV/JSONL case order mismatch")
    annotation_columns = ACTION_ANNOTATION_KEYS | REASON_ANNOTATION_KEYS
    for row in rows:
        if any(row.get(column) not in {None, ""} for column in annotation_columns):
            errors.append(f"{path}: CSV contains a nonblank annotation")
            break


def calibration_objective_matches(row: dict[str, Any]) -> bool:
    objective = row.get("calibration_objective")
    field = row.get("field")
    status = row.get("baseline_status")
    pair = row.get("main_action_pair")
    agreement = pair.split("->", 1)[0] == pair.split("->", 1)[1]
    rules: dict[str, tuple[str, str | None, str | None, bool | None]] = {
        "severity_equivalent_agreement": ("severity", "equivalent", None, True),
        "severity_incomplete_agreement": ("severity", "incomplete", None, True),
        "severity_conflict_agreement": (
            "severity",
            "factual_conflict",
            "conflict_escalation->conflict_escalation",
            None,
        ),
        "severity_conflict_abstention": (
            "severity",
            "factual_conflict",
            "conflict_escalation->abstain",
            None,
        ),
        "affected_abstain_to_no_action": (
            "affected_versions",
            None,
            "abstain->no_action",
            None,
        ),
        "affected_enrich_to_abstain": (
            "affected_versions",
            None,
            "enrich_record->abstain",
            None,
        ),
        "affected_enrich_to_conflict": (
            "affected_versions",
            None,
            "enrich_record->conflict_escalation",
            None,
        ),
        "affected_enrich_to_no_action": (
            "affected_versions",
            None,
            "enrich_record->no_action",
            None,
        ),
        "affected_equivalent_no_action_to_abstain": (
            "affected_versions",
            "equivalent",
            "no_action->abstain",
            None,
        ),
        "published_representation_control": (
            "published",
            "representation_discrepancy",
            None,
            None,
        ),
        "published_temporal_control": (
            "published",
            "temporal_discrepancy",
            None,
            None,
        ),
        "references_representation_control": (
            "references",
            "representation_discrepancy",
            None,
            None,
        ),
        "references_incomplete_control": (
            "references",
            "incomplete",
            None,
            None,
        ),
    }
    if objective not in rules:
        return False
    expected_field, expected_status, expected_pair, expected_agreement = rules[objective]
    return (
        field == expected_field
        and (expected_status is None or status == expected_status)
        and (expected_pair is None or pair == expected_pair)
        and (expected_agreement is None or agreement is expected_agreement)
    )


def validate_packet_dir(
    packet_dir: Path, require_distribution_ready: bool = False
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

    packets: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {
        "reviewer_a": defaultdict(dict),
        "reviewer_b": defaultdict(dict),
    }
    for reviewer in ("reviewer_a", "reviewer_b"):
        for phase in ("calibration", "evaluation"):
            for stage in ("action", "reason"):
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
                field_counts = Counter(row.get("field") for row in rows)
                if dict(field_counts) != EXPECTED_FIELD_COUNTS[phase]:
                    errors.append(
                        f"{reviewer}/{phase}/{stage}: field-count mismatch "
                        f"{dict(field_counts)}"
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
                    errors,
                )

    for phase in ("calibration", "evaluation"):
        for reviewer in ("reviewer_a", "reviewer_b"):
            action_rows = packets[reviewer][phase].get("action", [])
            reason_rows = packets[reviewer][phase].get("reason", [])
            action_by_id = {row.get("case_id"): row for row in action_rows}
            reason_by_id = {row.get("case_id"): row for row in reason_rows}
            if set(action_by_id) != set(reason_by_id):
                errors.append(f"{reviewer}/{phase}: action/reason case sets differ")
            if [row.get("case_id") for row in action_rows] == [
                row.get("case_id") for row in reason_rows
            ]:
                errors.append(f"{reviewer}/{phase}: action/reason order is identical")
            for case_id in set(action_by_id) & set(reason_by_id):
                if packet_without_stage(action_by_id[case_id]) != packet_without_stage(
                    reason_by_id[case_id]
                ):
                    errors.append(
                        f"{reviewer}/{phase}/{case_id}: stage content differs"
                    )
                    break
        for stage in ("action", "reason"):
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

    if len(frame_rows) != 140:
        errors.append(f"sampling frame must contain 140 rows, observed {len(frame_rows)}")
    if len(mapping_rows) != 140:
        errors.append(f"sealed mapping must contain 140 rows, observed {len(mapping_rows)}")
    sample_ids = [row.get("sample_id") for row in frame_rows]
    if len(set(sample_ids)) != len(sample_ids):
        errors.append("sampling-frame IDs are not unique")
    phase_counts = Counter(row.get("phase") for row in frame_rows)
    if dict(phase_counts) != EXPECTED_PHASE_COUNTS:
        errors.append(f"sampling-frame phase counts drifted: {dict(phase_counts)}")
    for phase in EXPECTED_PHASE_COUNTS:
        field_counts = Counter(
            row.get("field") for row in frame_rows if row.get("phase") == phase
        )
        if dict(field_counts) != EXPECTED_FIELD_COUNTS[phase]:
            errors.append(f"sampling-frame {phase} field counts drifted")

    try:
        source_rows = load_jsonl(EXPECTED_FIELD_VIEW)
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
        if any(frame_row.get(key) != current[key] for key in full_context_keys):
            errors.append(f"{frame_row.get('sample_id')}: frame/source mismatch")
            break

    evaluation_rows = [row for row in frame_rows if row.get("phase") == "evaluation"]
    selected_cells: dict[str, Counter[str]] = defaultdict(Counter)
    for row in evaluation_rows:
        field = row["field"]
        cell = row.get("selection_cell")
        if cell != row.get("evaluation_cell"):
            errors.append(f"{row.get('sample_id')}: selection-cell mismatch")
        selected_cells[field][cell] += 1
        population_count = population_cells[field][cell]
        target = EXPECTED_EVALUATION_TARGETS.get(field, {}).get(cell)
        if target is None:
            errors.append(f"{row.get('sample_id')}: unexpected evaluation cell")
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
        if set(population_cells[field]) != set(EXPECTED_EVALUATION_TARGETS[field]):
            errors.append(f"{field}: population evaluation cells drifted")

    manifest_strata = {
        (row.get("field"), row.get("cell")): row
        for row in manifest.get("evaluation_strata", [])
    }
    expected_stratum_count = sum(len(rows) for rows in EXPECTED_EVALUATION_TARGETS.values())
    if len(manifest_strata) != expected_stratum_count:
        errors.append("manifest evaluation-stratum count drifted")
    for field, targets in EXPECTED_EVALUATION_TARGETS.items():
        for cell, target in targets.items():
            row = manifest_strata.get((field, cell))
            if not row:
                errors.append(f"manifest missing stratum {field}/{cell}")
                continue
            population_count = population_cells[field][cell]
            if row.get("population_count") != population_count:
                errors.append(f"manifest population mismatch for {field}/{cell}")
            if row.get("evaluation_count") != target:
                errors.append(f"manifest sample mismatch for {field}/{cell}")

    calibration_rows = [row for row in frame_rows if row.get("phase") == "calibration"]
    objective_counts = Counter(row.get("calibration_objective") for row in calibration_rows)
    if dict(objective_counts) != EXPECTED_CALIBRATION_OBJECTIVES:
        errors.append(f"calibration objectives drifted: {dict(objective_counts)}")
    for row in calibration_rows:
        if not calibration_objective_matches(row):
            errors.append(f"{row.get('sample_id')}: calibration objective mismatch")
            break
    status_counts = Counter(row.get("baseline_status") for row in calibration_rows)
    action_case_counts: Counter[str] = Counter()
    for row in calibration_rows:
        actions = row.get("policy_actions") or {}
        if not MAIN_POLICIES <= set(actions):
            errors.append(f"{row.get('sample_id')}: missing main policy action")
            continue
        for action in {actions[policy] for policy in MAIN_POLICIES}:
            action_case_counts[action] += 1
    if any(status_counts[reason] < 2 for reason in REASONS - {"uncertain"}):
        errors.append("calibration reason-proxy coverage is below two cases")
    if any(action_case_counts[action] < 2 for action in ACTIONS):
        errors.append("calibration action-proxy coverage is below two cases")
    if sum(
        row["policy_actions"]["type_first_abstention_v1"] == "abstain"
        for row in calibration_rows
    ) < 2:
        errors.append("calibration abstention-proxy coverage is below two cases")

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
        positions = mapping.get("reviewer_positions")
        if not isinstance(positions, dict) or set(positions) != {
            "reviewer_a",
            "reviewer_b",
        }:
            errors.append(f"{mapping.get('case_id')}: invalid reviewer positions")
        if (
            packet.get("cve_id") != frame.get("cve_id")
            or packet.get("field") != frame.get("field")
            or packet.get("phase") != frame.get("phase")
            or packet.get("left") != side_payload(frame, left_source)
            or packet.get("right") != side_payload(frame, right_source)
        ):
            errors.append(f"{mapping.get('case_id')}: packet/mapping mismatch")
            break

    claim_ceiling = manifest.get("claim_ceiling") or {}
    if any(value is not False for value in claim_ceiling.values()):
        errors.append("prepare-only claim ceiling contains a positive claim")
    if set(manifest.get("actions", [])) != set(ACTIONS):
        errors.append("manifest action vocabulary drifted")
    if set(manifest.get("reasons", [])) != REASONS:
        errors.append("manifest reason vocabulary drifted")
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
        "PASS: V3 prepare-only packets are internally consistent; "
        "calibration=20 evaluation=120 distribution_allowed=false human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
