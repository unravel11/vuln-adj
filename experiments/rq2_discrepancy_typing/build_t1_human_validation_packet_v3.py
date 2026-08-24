#!/usr/bin/env python3
"""Build action-first, reason-second prepare-only packets for JSS T1/T2 V3."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from analyze_t1_routing_precheck import (
    ACTIONS,
    FIELDS,
    MAIN_FIRST,
    MAIN_SECOND,
    policy_actions,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ID = "vuln-adj-jss-t1-human-validation-v3"
PACKET_SCHEMA_VERSION = "t1_action_reason_packet_v3"
MANIFEST_SCHEMA_VERSION = "t1_action_reason_manifest_v3"

DEFAULT_FIELD_VIEW = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_GUIDELINE = "docs/annotation_guidelines/t1_action_reason_v3.md"
DEFAULT_PROTOCOL = (
    "experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL_V3.md"
)
DEFAULT_PRECHECK = "results/jss/t1_routing_precheck_v1/analysis.json"
DEFAULT_ROUTING_CONTRACT = (
    "experiments/rq2_discrepancy_typing/T1_ROUTING_PRECHECK_PROTOCOL_V1.md"
)
DEFAULT_OUTPUT_DIR = "data/annotations/rq2/t1_human_validation_v3"

EXPECTED_FIELD_VIEW_SHA256 = (
    "c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2"
)
EXPECTED_PRECHECK_DECISION = "CONDITIONAL_GO_FOR_V3_PACKET_DESIGN"
REASONS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)
MAIN_POLICIES = (
    "field_aware_simple_v1",
    "type_first_current_v1",
    "type_first_abstention_v1",
)

EVALUATION_SEED = "vuln-adj-t1-v3-evaluation-20260825"
CALIBRATION_SEED = "vuln-adj-t1-v3-calibration-20260825"
SIDE_MASK_SEED = "vuln-adj-t1-v3-side-mask-20260825"
ORDER_SEED = "vuln-adj-t1-v3-order-20260825"

EVALUATION_TARGETS: dict[str, dict[str, int]] = {
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

CALIBRATION_SPECS: tuple[dict[str, Any], ...] = (
    {
        "id": "severity_equivalent_agreement",
        "field": "severity",
        "status": "equivalent",
        "agreement": True,
        "count": 2,
    },
    {
        "id": "severity_incomplete_agreement",
        "field": "severity",
        "status": "incomplete",
        "agreement": True,
        "count": 1,
    },
    {
        "id": "severity_conflict_agreement",
        "field": "severity",
        "status": "factual_conflict",
        "pair": "conflict_escalation->conflict_escalation",
        "count": 1,
    },
    {
        "id": "severity_conflict_abstention",
        "field": "severity",
        "status": "factual_conflict",
        "pair": "conflict_escalation->abstain",
        "count": 1,
    },
    {
        "id": "affected_abstain_to_no_action",
        "field": "affected_versions",
        "pair": "abstain->no_action",
        "count": 1,
    },
    {
        "id": "affected_enrich_to_abstain",
        "field": "affected_versions",
        "pair": "enrich_record->abstain",
        "count": 1,
    },
    {
        "id": "affected_enrich_to_conflict",
        "field": "affected_versions",
        "pair": "enrich_record->conflict_escalation",
        "count": 1,
    },
    {
        "id": "affected_enrich_to_no_action",
        "field": "affected_versions",
        "pair": "enrich_record->no_action",
        "count": 1,
    },
    {
        "id": "affected_equivalent_no_action_to_abstain",
        "field": "affected_versions",
        "status": "equivalent",
        "pair": "no_action->abstain",
        "count": 1,
    },
    {
        "id": "published_representation_control",
        "field": "published",
        "status": "representation_discrepancy",
        "count": 2,
    },
    {
        "id": "published_temporal_control",
        "field": "published",
        "status": "temporal_discrepancy",
        "count": 3,
    },
    {
        "id": "references_representation_control",
        "field": "references",
        "status": "representation_discrepancy",
        "count": 2,
    },
    {
        "id": "references_incomplete_control",
        "field": "references",
        "status": "incomplete",
        "count": 3,
    },
)

ACTION_ANNOTATION = {
    "action_label": "",
    "action_rationale": "",
    "action_uncertainty": "",
    "reviewer_notes": "",
}
REASON_ANNOTATION = {
    "reason_label": "",
    "reason_rationale": "",
    "reason_uncertainty": "",
    "reviewer_notes": "",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-view", default=DEFAULT_FIELD_VIEW)
    parser.add_argument("--guideline", default=DEFAULT_GUIDELINE)
    parser.add_argument("--protocol", default=DEFAULT_PROTOCOL)
    parser.add_argument("--precheck", default=DEFAULT_PRECHECK)
    parser.add_argument("--routing-contract", default=DEFAULT_ROUTING_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_digest(seed: str, *parts: object) -> str:
    text = "|".join((seed, *(str(part) for part in parts)))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def json_cell(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def validate_inputs(field_view_path: Path, precheck_path: Path) -> list[dict[str, Any]]:
    observed_hash = sha256_file(field_view_path)
    if observed_hash != EXPECTED_FIELD_VIEW_SHA256:
        raise ValueError(
            "frozen field-view hash mismatch: "
            f"expected {EXPECTED_FIELD_VIEW_SHA256}, observed {observed_hash}"
        )
    rows = load_jsonl(field_view_path)
    if len(rows) != 8066:
        raise ValueError(f"expected 8,066 source rows, observed {len(rows)}")
    precheck = json.loads(precheck_path.read_text(encoding="utf-8"))
    if precheck.get("decision") != EXPECTED_PRECHECK_DECISION:
        raise ValueError("V3 packet design is not authorized by the frozen precheck")
    if precheck.get("uses_any_labels") is not False:
        raise ValueError("routing precheck unexpectedly uses labels")
    if precheck.get("rows") != 8066:
        raise ValueError("routing precheck population count does not match V3")
    return rows


def evaluation_cell(field: str, status: str, pair: str) -> str:
    disagreement = pair.split("->", 1)[0] != pair.split("->", 1)[1]
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


def project_population(source_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for source_line_number, source_row in enumerate(source_rows, start=1):
        unified = source_row.get("unified_view") or {}
        discrepancies = source_row.get("field_discrepancies") or {}
        policy_view = dict(unified)
        policy_view["field_discrepancies"] = discrepancies
        for field in FIELDS:
            discrepancy = discrepancies.get(field) or {}
            status = discrepancy.get("status")
            actions = policy_actions(policy_view, field)
            pair = f"{actions[MAIN_FIRST]}->{actions[MAIN_SECOND]}"
            projected.append(
                {
                    "sample_id": f"t1_v3:{field}:{source_line_number:05d}",
                    "source_line_number": source_line_number,
                    "field": field,
                    "cve_id": source_row.get("cve_id"),
                    "nvd_source_id": source_row.get("nvd_source_id"),
                    "ghsa_source_id": source_row.get("ghsa_source_id"),
                    "baseline_status": status,
                    "baseline_note": discrepancy.get("note"),
                    "nvd_value": discrepancy.get("nvd_value"),
                    "ghsa_value": discrepancy.get("ghsa_value"),
                    "field_context": unified.get(field),
                    "package_names": unified.get("package_names"),
                    "reference_context": unified.get("references"),
                    "policy_actions": actions,
                    "main_action_pair": pair,
                    "evaluation_cell": evaluation_cell(field, status, pair),
                }
            )
    if len(projected) != 8066 * len(FIELDS):
        raise ValueError("projected field-instance count drift")
    return projected


def stable_select(
    rows: list[dict[str, Any]], count: int, seed: str, scope: str
) -> list[dict[str, Any]]:
    if len(rows) < count:
        raise ValueError(f"{scope}: need {count} rows but only {len(rows)} exist")
    return sorted(
        rows,
        key=lambda row: (
            stable_digest(seed, scope, row["sample_id"], row["cve_id"]),
            row["sample_id"],
        ),
    )[:count]


def select_evaluation(
    population: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {
        field: defaultdict(list) for field in FIELDS
    }
    for row in population:
        grouped[row["field"]][row["evaluation_cell"]].append(row)

    selected: list[dict[str, Any]] = []
    strata: list[dict[str, Any]] = []
    for field in FIELDS:
        expected_cells = set(EVALUATION_TARGETS[field])
        observed_cells = set(grouped[field])
        if observed_cells != expected_cells:
            raise ValueError(
                f"{field}: evaluation-cell drift; expected {sorted(expected_cells)}, "
                f"observed {sorted(observed_cells)}"
            )
        for cell, target in EVALUATION_TARGETS[field].items():
            candidates = grouped[field][cell]
            chosen = stable_select(
                candidates, target, EVALUATION_SEED, f"{field}|{cell}"
            )
            population_count = len(candidates)
            for row in chosen:
                copied = dict(row)
                copied.update(
                    {
                        "phase": "evaluation",
                        "selection_cell": cell,
                        "population_count": population_count,
                        "selection_count": target,
                        "selection_probability": target / population_count,
                        "evaluation_weight": population_count / target,
                        "calibration_objective": None,
                    }
                )
                selected.append(copied)
            strata.append(
                {
                    "field": field,
                    "cell": cell,
                    "population_count": population_count,
                    "evaluation_count": target,
                    "selection_probability": target / population_count,
                    "evaluation_weight": population_count / target,
                }
            )
    if len(selected) != 120:
        raise ValueError(f"expected 120 evaluation rows, observed {len(selected)}")
    return selected, strata


def calibration_match(row: dict[str, Any], spec: dict[str, Any]) -> bool:
    if row["field"] != spec["field"]:
        return False
    if "status" in spec and row["baseline_status"] != spec["status"]:
        return False
    if "pair" in spec and row["main_action_pair"] != spec["pair"]:
        return False
    if "agreement" in spec:
        left, right = row["main_action_pair"].split("->", 1)
        if (left == right) is not spec["agreement"]:
            return False
    return True


def select_calibration(
    population: list[dict[str, Any]], evaluation_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    excluded = {row["sample_id"] for row in evaluation_rows}
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for spec in CALIBRATION_SPECS:
        candidates = [
            row
            for row in population
            if row["sample_id"] not in excluded
            and row["sample_id"] not in selected_ids
            and calibration_match(row, spec)
        ]
        chosen = stable_select(
            candidates,
            int(spec["count"]),
            CALIBRATION_SEED,
            str(spec["id"]),
        )
        for row in chosen:
            copied = dict(row)
            copied.update(
                {
                    "phase": "calibration",
                    "selection_cell": None,
                    "population_count": None,
                    "selection_count": None,
                    "selection_probability": None,
                    "evaluation_weight": None,
                    "calibration_objective": spec["id"],
                }
            )
            selected.append(copied)
            selected_ids.add(row["sample_id"])

    if len(selected) != 20:
        raise ValueError(f"expected 20 calibration rows, observed {len(selected)}")
    field_counts = Counter(row["field"] for row in selected)
    if field_counts != Counter({field: 5 for field in FIELDS}):
        raise ValueError(f"unexpected calibration field counts: {dict(field_counts)}")
    if excluded & selected_ids:
        raise ValueError("calibration and evaluation rows overlap")
    return selected


def calibration_proxy_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(row["baseline_status"] for row in rows)
    action_cases: Counter[str] = Counter()
    for row in rows:
        for action in {
            row["policy_actions"][policy] for policy in MAIN_POLICIES
        }:
            action_cases[action] += 1
    rule_limit_cases = sum(
        row["policy_actions"]["type_first_abstention_v1"] == "abstain"
        for row in rows
    )
    required_statuses = set(REASONS) - {"uncertain"}
    if any(statuses[status] < 2 for status in required_statuses):
        raise ValueError(f"calibration status coverage is too thin: {statuses}")
    if any(action_cases[action] < 2 for action in ACTIONS):
        raise ValueError(f"calibration action-proxy coverage is too thin: {action_cases}")
    if rule_limit_cases < 2:
        raise ValueError("calibration has fewer than two abstention-proxy cases")
    return {
        "deterministic_status_case_counts": dict(sorted(statuses.items())),
        "frozen_policy_action_case_counts": dict(sorted(action_cases.items())),
        "rule_limit_abstention_proxy_cases": rule_limit_cases,
        "proxies_do_not_prescribe_human_labels": True,
    }


def side_context(row: dict[str, Any], source: str) -> dict[str, Any]:
    field_context = row.get("field_context")
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
    package_names = row.get("package_names") or {}
    references = row.get("reference_context") or {}
    return {
        "value": row[f"{source}_value"],
        "field_context": field_context,
        "package_names": package_names.get(source, []),
        "reference_urls": references.get(f"{source}_urls", []),
        "reference_hosts": references.get(f"{source}_hosts", []),
    }


def opaque_case_id(sample_id: str, phase: str) -> str:
    digest = stable_digest(PROTOCOL_ID, phase, sample_id)[:12]
    prefix = "cal" if phase == "calibration" else "eval"
    return f"t1v3-{prefix}-{digest}"


def build_base_cases(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    mapping: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: item["sample_id"]):
        left_source = (
            "nvd"
            if int(stable_digest(SIDE_MASK_SEED, row["sample_id"]), 16) % 2 == 0
            else "ghsa"
        )
        right_source = "ghsa" if left_source == "nvd" else "nvd"
        case_id = opaque_case_id(row["sample_id"], row["phase"])
        cases.append(
            {
                "case_id": case_id,
                "phase": row["phase"],
                "cve_id": row["cve_id"],
                "field": row["field"],
                "left": side_context(row, left_source),
                "right": side_context(row, right_source),
            }
        )
        mapping.append(
            {
                "case_id": case_id,
                "source_sample_id": row["sample_id"],
                "source_line_number": row["source_line_number"],
                "phase": row["phase"],
                "cve_id": row["cve_id"],
                "field": row["field"],
                "baseline_status": row["baseline_status"],
                "baseline_note": row["baseline_note"],
                "policy_actions": row["policy_actions"],
                "main_action_pair": row["main_action_pair"],
                "selection_cell": row["selection_cell"],
                "evaluation_weight": row["evaluation_weight"],
                "calibration_objective": row["calibration_objective"],
                "left_source": left_source,
                "right_source": right_source,
                "reviewer_positions": {},
            }
        )
    return cases, mapping


def packet_row(base: dict[str, Any], stage: str) -> dict[str, Any]:
    annotation = ACTION_ANNOTATION if stage == "action" else REASON_ANNOTATION
    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "phase": base["phase"],
        "stage": stage,
        "packet_position": 0,
        "case_id": base["case_id"],
        "cve_id": base["cve_id"],
        "field": base["field"],
        "left": base["left"],
        "right": base["right"],
        "annotation": dict(annotation),
    }


def ordered_packets(
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, dict[str, list[dict[str, Any]]]]]:
    packets: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {}
    for reviewer in ("reviewer_a", "reviewer_b"):
        packets[reviewer] = {}
        for phase in ("calibration", "evaluation"):
            packets[reviewer][phase] = {}
            phase_cases = [row for row in cases if row["phase"] == phase]
            for stage in ("action", "reason"):
                rows = [packet_row(row, stage) for row in phase_cases]
                rows.sort(
                    key=lambda row: stable_digest(
                        ORDER_SEED,
                        reviewer,
                        phase,
                        stage,
                        row["case_id"],
                    )
                )
                for position, row in enumerate(rows, start=1):
                    row["packet_position"] = position
                packets[reviewer][phase][stage] = rows
    return packets


def attach_positions(
    mapping: list[dict[str, Any]],
    packets: dict[str, dict[str, dict[str, list[dict[str, Any]]]]],
) -> list[dict[str, Any]]:
    positions: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for reviewer, phase_packets in packets.items():
        for phase, stage_packets in phase_packets.items():
            for stage, rows in stage_packets.items():
                positions[reviewer][f"{phase}_{stage}"] = {
                    row["case_id"]: row["packet_position"] for row in rows
                }
    output: list[dict[str, Any]] = []
    for row in mapping:
        copied = dict(row)
        copied["reviewer_positions"] = {
            reviewer: {
                f"{row['phase']}_{stage}": positions[reviewer][
                    f"{row['phase']}_{stage}"
                ][row["case_id"]]
                for stage in ("action", "reason")
            }
            for reviewer in ("reviewer_a", "reviewer_b")
        }
        output.append(copied)
    return sorted(output, key=lambda row: row["case_id"])


def write_packet_csv(path: Path, rows: list[dict[str, Any]], stage: str) -> None:
    annotation_fields = list(
        ACTION_ANNOTATION if stage == "action" else REASON_ANNOTATION
    )
    fieldnames = [
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
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "packet_position": row["packet_position"],
                    "case_id": row["case_id"],
                    "phase": row["phase"],
                    "stage": row["stage"],
                    "cve_id": row["cve_id"],
                    "field": row["field"],
                    "left_value_json": json_cell(row["left"]["value"]),
                    "left_field_context_json": json_cell(
                        row["left"]["field_context"]
                    ),
                    "left_package_names_json": json_cell(
                        row["left"]["package_names"]
                    ),
                    "left_reference_urls_json": json_cell(
                        row["left"]["reference_urls"]
                    ),
                    "left_reference_hosts_json": json_cell(
                        row["left"]["reference_hosts"]
                    ),
                    "right_value_json": json_cell(row["right"]["value"]),
                    "right_field_context_json": json_cell(
                        row["right"]["field_context"]
                    ),
                    "right_package_names_json": json_cell(
                        row["right"]["package_names"]
                    ),
                    "right_reference_urls_json": json_cell(
                        row["right"]["reference_urls"]
                    ),
                    "right_reference_hosts_json": json_cell(
                        row["right"]["reference_hosts"]
                    ),
                    **row["annotation"],
                }
            )


def role_record_text() -> str:
    return """# V3 Human Role and Independence Record

Status: INCOMPLETE_NOT_FOR_DISTRIBUTION

Complete, review, and sign before calibration packets are distributed.

## Reviewer A

- Real name:
- Reviewer ID:
- Advisory/CVSS/version-range experience:
- Practitioner role, if any:
- Affiliation:
- Conflict of interest:
- Compensation:
- Independence statement signed:
- Date:

## Reviewer B

- Real name:
- Reviewer ID:
- Advisory/CVSS/version-range experience:
- Practitioner role, if any:
- Affiliation:
- Conflict of interest:
- Compensation:
- Independence statement signed:
- Date:

## Resolving author

- Real name:
- Author ID:
- Conflict statement:
- Policy-output blinding commitment signed:
- Date:

## Ethics and recruitment

- Institutional determination required:
- Determination identifier or written rationale:
- Recruitment method:
- Consent/information sheet:

## Author distribution approval

- I verified that reviewer A and B are different real people:
- I verified packet hashes and the approved guideline hash:
- I verified that no reviewer received policy, AI, or prior-review labels:
- Approved manifest revision:
- Author name, signature, and date:
"""


def stage_lock_text() -> str:
    return """# V3 Action-to-Reason Stage Lock Record

Status: EMPTY_NOT_FOR_DISTRIBUTION

For each phase, both action returns must be complete and hashed before any
reason packet is released.

## Calibration

- Reviewer A action-return path and SHA-256:
- Reviewer B action-return path and SHA-256:
- Completeness validator result:
- Action stage locked by/date:
- Reason packets released by/date:

## Formal evaluation

- Reviewer A action-return path and SHA-256:
- Reviewer B action-return path and SHA-256:
- Completeness validator result:
- Action stage locked by/date:
- Reason packets released by/date:
"""


def readme_text() -> str:
    return """# T1/T2 Human Validation V3

Status: PREPARATION_ONLY_NOT_FOR_DISTRIBUTION

This directory contains 20 calibration and 120 formal cases for each of two
independent trained analysts. Every phase has a Stage-A action packet and a
Stage-B reason packet. Action returns must be locked before reason packets are
released.

The files contain no human labels and are not human gold. The internal sampling
frame and sealed mapping contain deterministic statuses, policy actions, source
identities, and weights. They must never be distributed to reviewers.

Distribution remains blocked until an approved guideline, signed role record,
ethics/recruitment determination, passing hashes, and a separate author-approved
manifest revision exist.
"""


def git_value(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ("git", *args), cwd=PROJECT_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def build_packet(
    field_view_path: Path,
    guideline_path: Path,
    protocol_path: Path,
    precheck_path: Path,
    routing_contract_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    analyzer_path = Path(__file__).with_name("analyze_t1_routing_precheck.py")
    validator_path = Path(__file__).with_name(
        "validate_t1_human_validation_packet_v3.py"
    )
    required_paths = (
        field_view_path,
        guideline_path,
        protocol_path,
        precheck_path,
        routing_contract_path,
        analyzer_path,
        Path(__file__).resolve(),
        validator_path,
    )
    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(path)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing V3 packet: {output_dir}")

    source_rows = validate_inputs(field_view_path, precheck_path)
    population = project_population(source_rows)
    evaluation_rows, evaluation_strata = select_evaluation(population)
    calibration_rows = select_calibration(population, evaluation_rows)
    calibration_coverage = calibration_proxy_coverage(calibration_rows)
    sampled_rows = calibration_rows + evaluation_rows

    cases, mapping = build_base_cases(sampled_rows)
    packets = ordered_packets(cases)
    mapping = attach_positions(mapping, packets)

    (output_dir / "internal").mkdir(parents=True)
    for reviewer, phase_packets in packets.items():
        (output_dir / reviewer).mkdir()
        for phase, stage_packets in phase_packets.items():
            for stage, rows in stage_packets.items():
                stem = f"{phase}_{stage}_packet"
                write_jsonl(output_dir / reviewer / f"{stem}.jsonl", rows)
                write_packet_csv(
                    output_dir / reviewer / f"{stem}.csv", rows, stage
                )

    write_jsonl(
        output_dir / "internal" / "frozen_sampling_frame.jsonl",
        sorted(sampled_rows, key=lambda row: row["sample_id"]),
    )
    write_jsonl(output_dir / "internal" / "sealed_case_mapping.jsonl", mapping)
    (output_dir / "ROLE_AND_INDEPENDENCE_RECORD.md").write_text(
        role_record_text(), encoding="utf-8"
    )
    (output_dir / "STAGE_LOCK_RECORD.md").write_text(
        stage_lock_text(), encoding="utf-8"
    )
    (output_dir / "README.md").write_text(readme_text(), encoding="utf-8")

    generated_files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "status": "PREPARATION_ONLY_NOT_FOR_DISTRIBUTION",
        "distribution_allowed": False,
        "human_labels": 0,
        "human_gold": False,
        "freeze_date": "2026-08-25",
        "repository": {
            "branch": git_value("branch", "--show-current"),
            "head_before_packet_commit": git_value("rev-parse", "HEAD"),
        },
        "distribution_blockers": [
            "The V3 guideline is draft and lacks author approval.",
            "Reviewer role and independence record is incomplete.",
            "Ethics and recruitment determination is incomplete.",
            "Action-to-reason stage locks have not been executed.",
            "No author-approved distribution manifest revision exists.",
        ],
        "input_files": {
            relative(path): sha256_file(path) for path in required_paths
        },
        "expected_input_hashes": {
            relative(field_view_path): EXPECTED_FIELD_VIEW_SHA256,
        },
        "seeds": {
            "evaluation_rank": EVALUATION_SEED,
            "calibration_rank": CALIBRATION_SEED,
            "side_mask": SIDE_MASK_SEED,
            "reviewer_phase_stage_order": ORDER_SEED,
        },
        "selection_order": "evaluation first; calibration from remaining rows",
        "counts": {
            "unique_cases": 140,
            "calibration": 20,
            "evaluation": 120,
            "per_reviewer": 140,
            "reviewers": 2,
            "reviewer_case_judgments": 280,
            "stages_per_case": 2,
        },
        "field_counts": {
            "calibration": {field: 5 for field in FIELDS},
            "evaluation": {
                "severity": 50,
                "affected_versions": 50,
                "published": 10,
                "references": 10,
            },
        },
        "actions": list(ACTIONS),
        "reasons": list(REASONS),
        "main_policies": list(MAIN_POLICIES),
        "lower_reference_policies": [
            "binary_observed_non_equal",
            "binary_canonical_non_equal",
        ],
        "evaluation_strata": evaluation_strata,
        "calibration_specs": list(CALIBRATION_SPECS),
        "calibration_proxy_coverage": calibration_coverage,
        "reviewer_packet_files": {
            reviewer: {
                phase: {
                    stage: {
                        "jsonl": f"{reviewer}/{phase}_{stage}_packet.jsonl",
                        "csv": f"{reviewer}/{phase}_{stage}_packet.csv",
                    }
                    for stage in ("action", "reason")
                }
                for phase in ("calibration", "evaluation")
            }
            for reviewer in ("reviewer_a", "reviewer_b")
        },
        "internal_sampling_frame": "internal/frozen_sampling_frame.jsonl",
        "internal_mapping": "internal/sealed_case_mapping.jsonl",
        "output_sha256": {
            str(path.relative_to(output_dir)): sha256_file(path)
            for path in generated_files
        },
        "claim_ceiling": {
            "eligible_for_human_gold_claim": False,
            "eligible_for_accuracy_claim": False,
            "eligible_for_policy_superiority_claim": False,
            "eligible_for_workload_reduction_claim": False,
            "eligible_for_submission_readiness_claim": False,
        },
        "cautions": [
            "Packets are blank preparation artifacts, not human labels.",
            "Reviewer packets hide policies and explicit NVD/GHSA side names.",
            "URLs may reveal source identity, so blinding is partial.",
            "Internal files must not be shared with reviewers.",
            "Evaluation weights are sensitivity weights, not primary estimands.",
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    args = parse_args()
    manifest = build_packet(
        field_view_path=resolve(args.field_view),
        guideline_path=resolve(args.guideline),
        protocol_path=resolve(args.protocol),
        precheck_path=resolve(args.precheck),
        routing_contract_path=resolve(args.routing_contract),
        output_dir=resolve(args.output_dir),
    )
    print(
        "Built V3 prepare-only packets: "
        f"calibration={manifest['counts']['calibration']} "
        f"evaluation={manifest['counts']['evaluation']} "
        "distribution_allowed=false human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
