#!/usr/bin/env python3
"""Build the prepare-only, recursively blinded JSS T1/T2 V3.1 packets."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import build_t1_human_validation_packet_v3 as v3
from analyze_t1_routing_precheck import (
    ACTIONS,
    FIELDS,
    MAIN_FIRST,
    MAIN_SECOND,
    MANUAL_REVIEW_ACTIONS,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ID = "vuln-adj-jss-t1-human-validation-v3.1"
PACKET_SCHEMA_VERSION = "t1_action_reason_packet_v3_1"
MANIFEST_SCHEMA_VERSION = "t1_action_reason_manifest_v3_1"

DEFAULT_FIELD_VIEW = v3.DEFAULT_FIELD_VIEW
DEFAULT_GUIDELINE = "docs/annotation_guidelines/t1_action_reason_v3_1.md"
DEFAULT_PROTOCOL = (
    "experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL_V3_1.md"
)
DEFAULT_PRECHECK = v3.DEFAULT_PRECHECK
DEFAULT_ROUTING_CONTRACT = v3.DEFAULT_ROUTING_CONTRACT
DEFAULT_SAFETY_AUDIT = "results/jss/t1_v31_safety_identifiability/analysis.json"
DEFAULT_OUTPUT_DIR = "data/annotations/rq2/t1_human_validation_v3_1"

EXPECTED_FIELD_VIEW_SHA256 = v3.EXPECTED_FIELD_VIEW_SHA256
EXPECTED_PRECHECK_DECISION = v3.EXPECTED_PRECHECK_DECISION
EXPECTED_SAFETY_DECISION = "GO_FREEZE_V3_1_WITH_DELTA_0_10_AND_N29"
REASONS = v3.REASONS
MAIN_POLICIES = v3.MAIN_POLICIES
EVALUATION_TARGETS = v3.EVALUATION_TARGETS
CALIBRATION_SPECS = v3.CALIBRATION_SPECS

CALIBRATION_1_SEED = "vuln-adj-t1-v3.1-calibration-1-20260825"
CALIBRATION_2_SEED = "vuln-adj-t1-v3.1-calibration-2-20260825"
SIDE_MASK_SEED = "vuln-adj-t1-v3.1-side-mask-20260825"
ORDER_SEED = "vuln-adj-t1-v3.1-order-20260825"

PHASES = ("calibration_1", "calibration_2", "evaluation")
REVIEWERS = ("reviewer_a", "reviewer_b")
STAGES = ("action", "reason")
EXPECTED_PHASE_COUNTS = {
    "calibration_1": 20,
    "calibration_2": 20,
    "evaluation": 120,
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
ACTION_ANNOTATION = v3.ACTION_ANNOTATION
REASON_ANNOTATION = v3.REASON_ANNOTATION


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-view", default=DEFAULT_FIELD_VIEW)
    parser.add_argument("--guideline", default=DEFAULT_GUIDELINE)
    parser.add_argument("--protocol", default=DEFAULT_PROTOCOL)
    parser.add_argument("--precheck", default=DEFAULT_PRECHECK)
    parser.add_argument("--routing-contract", default=DEFAULT_ROUTING_CONTRACT)
    parser.add_argument("--safety-audit", default=DEFAULT_SAFETY_AUDIT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256_values(values: list[str]) -> str:
    payload = "\n".join(sorted(values)) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def select_calibration_round(
    population: list[dict[str, Any]],
    excluded_cves: set[str],
    phase: str,
    seed: str,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_cves: set[str] = set()
    for spec in CALIBRATION_SPECS:
        candidates = [
            row
            for row in population
            if row["cve_id"] not in excluded_cves
            and row["cve_id"] not in selected_cves
            and v3.calibration_match(row, spec)
        ]
        chosen = v3.stable_select(
            candidates,
            int(spec["count"]),
            seed,
            str(spec["id"]),
        )
        for row in chosen:
            copied = dict(row)
            copied.update(
                {
                    "phase": phase,
                    "selection_cell": None,
                    "population_count": None,
                    "selection_count": None,
                    "selection_probability": None,
                    "evaluation_weight": None,
                    "calibration_objective": spec["id"],
                }
            )
            selected.append(copied)
            selected_cves.add(str(row["cve_id"]))
    if len(selected) != 20:
        raise ValueError(f"{phase}: expected 20 cases, observed {len(selected)}")
    if Counter(row["field"] for row in selected) != Counter(
        {field: 5 for field in FIELDS}
    ):
        raise ValueError(f"{phase}: field allocation drift")
    if len(selected_cves) != len(selected):
        raise ValueError(f"{phase}: CVE IDs are not unique")
    if excluded_cves & selected_cves:
        raise ValueError(f"{phase}: CVE overlap with an earlier phase")
    v3.calibration_proxy_coverage(selected)
    return selected


def select_all(
    population: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    evaluation, strata = v3.select_evaluation(population)
    evaluation_cves = {str(row["cve_id"]) for row in evaluation}
    if len(evaluation_cves) != len(evaluation):
        raise ValueError("formal evaluation CVE IDs are not unique")
    calibration_1 = select_calibration_round(
        population,
        evaluation_cves,
        "calibration_1",
        CALIBRATION_1_SEED,
    )
    calibration_1_cves = {str(row["cve_id"]) for row in calibration_1}
    calibration_2 = select_calibration_round(
        population,
        evaluation_cves | calibration_1_cves,
        "calibration_2",
        CALIBRATION_2_SEED,
    )
    calibration_2_cves = {str(row["cve_id"]) for row in calibration_2}
    phase_sets = {
        "evaluation": evaluation_cves,
        "calibration_1": calibration_1_cves,
        "calibration_2": calibration_2_cves,
    }
    for first_index, first in enumerate(PHASES):
        for second in PHASES[first_index + 1 :]:
            if phase_sets[first] & phase_sets[second]:
                raise ValueError(f"CVE overlap between {first} and {second}")
    phase_audit = {
        phase: {
            "cases": len(phase_sets[phase]),
            "cve_id_set_sha256": sha256_values(list(phase_sets[phase])),
        }
        for phase in PHASES
    }
    return calibration_1 + calibration_2 + evaluation, strata, phase_audit


def opaque_case_id(sample_id: str, phase: str) -> str:
    digest = v3.stable_digest(PROTOCOL_ID, phase, sample_id)[:12]
    prefixes = {
        "calibration_1": "c1",
        "calibration_2": "c2",
        "evaluation": "eval",
    }
    return f"t1v31-{prefixes[phase]}-{digest}"


def build_base_cases(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    mapping: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: item["sample_id"]):
        left_source = (
            "nvd"
            if int(v3.stable_digest(SIDE_MASK_SEED, row["sample_id"]), 16) % 2 == 0
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
                "left": v3.side_context(row, left_source),
                "right": v3.side_context(row, right_source),
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
    for reviewer in REVIEWERS:
        packets[reviewer] = {}
        for phase in PHASES:
            packets[reviewer][phase] = {}
            phase_cases = [row for row in cases if row["phase"] == phase]
            for stage in STAGES:
                rows = [packet_row(row, stage) for row in phase_cases]
                rows.sort(
                    key=lambda row: v3.stable_digest(
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
    position_maps: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
    for reviewer, phase_packets in packets.items():
        for phase, stage_packets in phase_packets.items():
            for stage, rows in stage_packets.items():
                position_maps[reviewer][f"{phase}_{stage}"] = {
                    row["case_id"]: row["packet_position"] for row in rows
                }
    output = []
    for row in mapping:
        copied = dict(row)
        copied["reviewer_positions"] = {
            reviewer: {
                f"{row['phase']}_{stage}": position_maps[reviewer][
                    f"{row['phase']}_{stage}"
                ][row["case_id"]]
                for stage in STAGES
            }
            for reviewer in REVIEWERS
        }
        output.append(copied)
    return sorted(output, key=lambda row: row["case_id"])


def build_safety_audit(
    sampled_rows: list[dict[str, Any]],
    mapping: list[dict[str, Any]],
    safety_analysis: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    case_by_sample = {
        row["source_sample_id"]: row["case_id"] for row in mapping
    }
    rows = [
        row
        for row in sampled_rows
        if row["phase"] == "evaluation"
        and row["field"] in {"severity", "affected_versions"}
        and row["policy_actions"][MAIN_FIRST] not in MANUAL_REVIEW_ACTIONS
        and row["policy_actions"][MAIN_SECOND] not in MANUAL_REVIEW_ACTIONS
    ]
    if Counter(row["field"] for row in rows) != Counter(
        {"severity": 15, "affected_versions": 19}
    ):
        raise ValueError("shared-no-manual safety audit count drift")
    audit_rows = [
        {
            "case_id": case_by_sample[row["sample_id"]],
            "source_sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "field": row["field"],
            "selection_cell": row["selection_cell"],
            "evaluation_weight": row["evaluation_weight"],
            "field_aware_simple_v1": row["policy_actions"][MAIN_FIRST],
            "type_first_abstention_v1": row["policy_actions"][MAIN_SECOND],
        }
        for row in sorted(rows, key=lambda item: item["sample_id"])
    ]
    source_hash = sha256_values([row["source_sample_id"] for row in audit_rows])
    expected = safety_analysis["shared_no_manual_route_audit"][
        "source_sample_id_set_sha256"
    ]
    if source_hash != expected:
        raise ValueError("V3.1 safety-audit case set differs from label-free audit")
    details = {
        "cases": len(audit_rows),
        "field_counts": dict(Counter(row["field"] for row in audit_rows)),
        "source_sample_id_set_sha256": source_hash,
        "reviewer_case_id_set_sha256": sha256_values(
            [row["case_id"] for row in audit_rows]
        ),
        "internal_file": "internal/shared_no_manual_route_audit.jsonl",
        "reviewer_visible_flag_present": False,
        "population_rate_identified": False,
    }
    return audit_rows, details


def role_record_text() -> str:
    return """# V3.1 Human Role and Independence Record

Status: INCOMPLETE_NOT_FOR_DISTRIBUTION

Complete, review, and sign before calibration-1 action packets are distributed.

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

- Real name and author ID:
- Conflict statement:
- Policy-output blinding commitment signed:
- Date:

## Ethics and recruitment

- Institutional determination required:
- Determination identifier or written rationale:
- Recruitment method:
- Consent/information sheet:

## Author distribution approval

- I verified two different real independent reviewers:
- I verified the exact phase/stage packet and guideline hashes:
- I verified that internal, policy, AI, and prior-review files are excluded:
- Approved reviewer, phase, stage, and manifest revision:
- Author name, signature, and date:
"""


def stage_lock_text() -> str:
    sections = []
    for title in ("Calibration 1", "Calibration 2 reserve", "Formal evaluation"):
        sections.extend(
            [
                f"## {title}",
                "",
                "- Trigger/eligibility decision:",
                "- Reviewer A action-return path and SHA-256:",
                "- Reviewer B action-return path and SHA-256:",
                "- Return-validator result:",
                "- Action stage locked by/date:",
                "- Reason packets released by/date:",
                "- Reviewer A reason-return path and SHA-256:",
                "- Reviewer B reason-return path and SHA-256:",
                "- Reason stage locked by/date:",
                "",
            ]
        )
    return "\n".join(
        [
            "# V3.1 Action-to-Reason Stage Lock Record",
            "",
            "Status: EMPTY_NOT_FOR_DISTRIBUTION",
            "",
            "For each used phase, both action returns must validate and be hashed",
            "before any reason packet is released. Calibration-2 stays sealed unless",
            "the protocol trigger is recorded.",
            "",
            *sections,
        ]
    )


def readme_text() -> str:
    return """# T1/T2 Human Validation V3.1

Status: PREPARATION_ONLY_NOT_FOR_DISTRIBUTION

This directory contains 120 formal cases, 20 calibration-1 cases, and a
presealed 20-case calibration-2 reserve for each of two independent trained
analysts. The ordinary budget is 140 cases per reviewer; the bounded maximum is
160 only when calibration-2 is triggered.

Every phase has action and reason packets. Action returns must be validated,
hashed, and locked before the matching reason packets are released.

Reviewer-visible packets contain no human labels and are not human gold.
Internal files contain deterministic statuses, policy actions, source
identities, selection cells, and weights and must never be distributed.

The current manifest blocks all distribution. A later explicit revision must
allowlist one reviewer, one phase, and one stage after every protocol gate is
satisfied.
"""


def build_packet(
    field_view_path: Path,
    guideline_path: Path,
    protocol_path: Path,
    precheck_path: Path,
    routing_contract_path: Path,
    safety_audit_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    helper_path = Path(v3.__file__).resolve()
    validator_path = Path(__file__).with_name(
        "validate_t1_human_validation_packet_v3_1.py"
    )
    return_validator_path = Path(__file__).with_name(
        "validate_t1_human_validation_return_v3_1.py"
    )
    stage_sealer_path = Path(__file__).with_name(
        "seal_t1_human_validation_stage_v3_1.py"
    )
    evaluator_path = Path(__file__).with_name(
        "evaluate_t1_human_validation_v3_1.py"
    )
    required_paths = (
        field_view_path,
        guideline_path,
        protocol_path,
        precheck_path,
        routing_contract_path,
        safety_audit_path,
        helper_path,
        Path(__file__).resolve(),
        validator_path,
        return_validator_path,
        stage_sealer_path,
        evaluator_path,
    )
    for path in required_paths:
        if not path.is_file():
            raise FileNotFoundError(path)
    if output_dir.exists():
        raise FileExistsError(
            f"refusing to overwrite existing V3.1 packet: {output_dir}"
        )

    safety_analysis = json.loads(safety_audit_path.read_text(encoding="utf-8"))
    if safety_analysis.get("decision") != EXPECTED_SAFETY_DECISION:
        raise ValueError("label-free V3.1 safety audit does not authorize freeze")
    if safety_analysis.get("uses_any_human_labels") is not False:
        raise ValueError("safety design audit unexpectedly uses human labels")

    source_rows = v3.validate_inputs(field_view_path, precheck_path)
    population = v3.project_population(source_rows)
    sampled_rows, evaluation_strata, phase_audit = select_all(population)
    cases, mapping = build_base_cases(sampled_rows)
    packets = ordered_packets(cases)
    mapping = attach_positions(mapping, packets)
    safety_rows, safety_details = build_safety_audit(
        sampled_rows, mapping, safety_analysis
    )

    (output_dir / "internal").mkdir(parents=True)
    for reviewer, phase_packets in packets.items():
        (output_dir / reviewer).mkdir()
        for phase, stage_packets in phase_packets.items():
            for stage, rows in stage_packets.items():
                stem = f"{phase}_{stage}_packet"
                v3.write_jsonl(output_dir / reviewer / f"{stem}.jsonl", rows)
                v3.write_packet_csv(
                    output_dir / reviewer / f"{stem}.csv", rows, stage
                )
    v3.write_jsonl(
        output_dir / "internal" / "frozen_sampling_frame.jsonl",
        sorted(sampled_rows, key=lambda row: row["sample_id"]),
    )
    v3.write_jsonl(output_dir / "internal" / "sealed_case_mapping.jsonl", mapping)
    v3.write_jsonl(
        output_dir / "internal" / "shared_no_manual_route_audit.jsonl",
        safety_rows,
    )
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
    reviewer_packet_files = {
        reviewer: {
            phase: {
                stage: {
                    "jsonl": f"{reviewer}/{phase}_{stage}_packet.jsonl",
                    "csv": f"{reviewer}/{phase}_{stage}_packet.csv",
                }
                for stage in STAGES
            }
            for phase in PHASES
        }
        for reviewer in REVIEWERS
    }
    distribution_candidates = {
        reviewer: {
            phase: {
                stage: [
                    reviewer_packet_files[reviewer][phase][stage]["jsonl"],
                    reviewer_packet_files[reviewer][phase][stage]["csv"],
                    v3.relative(guideline_path),
                ]
                for stage in STAGES
            }
            for phase in PHASES
        }
        for reviewer in REVIEWERS
    }
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "status": "PREPARATION_ONLY_NOT_FOR_DISTRIBUTION",
        "distribution_allowed": False,
        "human_labels": 0,
        "human_gold": False,
        "freeze_date": "2026-08-25",
        "repository": {
            "branch": v3.git_value("branch", "--show-current"),
            "head_before_packet_commit": v3.git_value("rev-parse", "HEAD"),
        },
        "distribution_blockers": [
            "The V3.1 guideline is draft and lacks author approval.",
            "Reviewer role and independence record is incomplete.",
            "Ethics and recruitment determination is incomplete.",
            "Calibration-1 has not been run.",
            "Action-to-reason stage locks have not been executed.",
            "No stage-scoped author-approved distribution revision exists.",
        ],
        "input_files": {
            v3.relative(path): v3.sha256_file(path) for path in required_paths
        },
        "expected_input_hashes": {
            v3.relative(field_view_path): EXPECTED_FIELD_VIEW_SHA256,
        },
        "seeds": {
            "evaluation_rank": v3.EVALUATION_SEED,
            "calibration_1_rank": CALIBRATION_1_SEED,
            "calibration_2_rank": CALIBRATION_2_SEED,
            "side_mask": SIDE_MASK_SEED,
            "reviewer_phase_stage_order": ORDER_SEED,
        },
        "selection_order": (
            "evaluation first; calibration_1 from unused CVEs; "
            "calibration_2 from CVEs unused by both earlier phases"
        ),
        "counts": {
            "unique_cases": 160,
            "calibration_1": 20,
            "calibration_2_reserve": 20,
            "evaluation": 120,
            "ordinary_cases_per_reviewer": 140,
            "maximum_cases_per_reviewer": 160,
            "reviewers": 2,
            "stages_per_used_case": 2,
        },
        "field_counts": {
            "calibration_1": {field: 5 for field in FIELDS},
            "calibration_2": {field: 5 for field in FIELDS},
            "evaluation": {
                "severity": 50,
                "affected_versions": 50,
                "published": 10,
                "references": 10,
            },
        },
        "phase_cve_audit": phase_audit,
        "actions": list(ACTIONS),
        "reasons": list(REASONS),
        "main_policies": list(MAIN_POLICIES),
        "lower_reference_policies": [
            "binary_observed_non_equal",
            "binary_canonical_non_equal",
        ],
        "evaluation_strata": evaluation_strata,
        "calibration_specs_per_round": list(CALIBRATION_SPECS),
        "calibration_proxy_coverage": {
            phase: v3.calibration_proxy_coverage(
                [row for row in sampled_rows if row["phase"] == phase]
            )
            for phase in ("calibration_1", "calibration_2")
        },
        "shared_no_manual_route_audit": safety_details,
        "safety_gate": {
            "simple_only_loss_margin": 0.10,
            "reporting_floor_per_reviewer": 25,
            "positive_framing_floor_per_reviewer": 29,
            "both_reviewers_must_pass": True,
            "failure_route": "BOUNDARY_OR_DECISION_AMBIGUITY_MANUSCRIPT",
        },
        "reviewer_packet_files": reviewer_packet_files,
        "distribution_file_policy": {
            "current_revision_allows_no_files": True,
            "future_revision_must_select_exact_reviewer_phase_stage": True,
            "stage_scoped_candidate_files": distribution_candidates,
            "permanently_excluded": [
                "internal/*",
                "manifest.json",
                "ROLE_AND_INDEPENDENCE_RECORD.md",
                "STAGE_LOCK_RECORD.md",
                "reviewer_other_than_named_reviewer/*",
                "future_stage_packets",
                "data/annotations/expert_candidate/review_packets/"
                "rq2_primary.review.jsonl",
                "data/annotations/rq2/t1_human_validation_v2/*",
                "data/annotations/rq2/t1_human_validation_v3/*",
            ],
        },
        "reviewer_visible_schema_allowlist": {
            "top_level_keys": sorted(TOP_LEVEL_KEYS),
            "side_keys": sorted(SIDE_KEYS),
            "action_annotation_keys": sorted(ACTION_ANNOTATION),
            "reason_annotation_keys": sorted(REASON_ANNOTATION),
            "unknown_keys_fail_closed_at_every_object_level": True,
        },
        "internal_sampling_frame": "internal/frozen_sampling_frame.jsonl",
        "internal_mapping": "internal/sealed_case_mapping.jsonl",
        "output_sha256": {
            str(path.relative_to(output_dir)): v3.sha256_file(path)
            for path in generated_files
        },
        "claim_ceiling": {
            "eligible_for_human_gold_claim": False,
            "eligible_for_accuracy_claim": False,
            "eligible_for_policy_superiority_claim": False,
            "eligible_for_safety_noninferiority_claim": False,
            "eligible_for_workload_reduction_claim": False,
            "eligible_for_submission_readiness_claim": False,
        },
        "cautions": [
            "Packets are blank preparation artifacts, not human labels.",
            "URLs may reveal source identity, so blinding is partial.",
            "Internal files must never be shared with reviewers.",
            "The 34-case safety audit is sample-conditional, not a population bound.",
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
        safety_audit_path=resolve(args.safety_audit),
        output_dir=resolve(args.output_dir),
    )
    print(
        "Built V3.1 prepare-only packets: "
        f"calibration_1={manifest['counts']['calibration_1']} "
        f"calibration_2_reserve={manifest['counts']['calibration_2_reserve']} "
        f"evaluation={manifest['counts']['evaluation']} "
        "distribution_allowed=false human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
