#!/usr/bin/env python3
"""Evaluate sealed V3.1 formal returns before any author adjudication."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

import build_t1_human_validation_packet_v3_1 as builder
import validate_t1_human_validation_packet_v3_1 as packet_validator
import validate_t1_human_validation_return_v3_1 as return_validator
from analyze_t1_routing_precheck import (
    MAIN_FIRST,
    MAIN_SECOND,
    MANUAL_REVIEW_ACTIONS,
    exact_two_sided_mcnemar_p,
)
from analyze_t1_v31_safety_identifiability import (
    kish_effective_sample_size,
    one_sided_cp_upper,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SEED = "vuln-adj-t1-v3.1-cve-bootstrap-20260825"
BOOTSTRAP_REPLICATES = 10000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=builder.DEFAULT_OUTPUT_DIR)
    parser.add_argument("--reviewer-a-action", required=True)
    parser.add_argument("--reviewer-b-action", required=True)
    parser.add_argument("--reviewer-a-reason", required=True)
    parser.add_argument("--reviewer-b-reason", required=True)
    parser.add_argument("--action-lock", required=True)
    parser.add_argument("--reason-lock", required=True)
    parser.add_argument(
        "--adjudicated-case-ids",
        help="Optional newline-delimited case IDs for exclusion sensitivity only.",
    )
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def nominal_alpha(labels_a: list[str], labels_b: list[str]) -> float | None:
    if len(labels_a) != len(labels_b) or not labels_a:
        raise ValueError("two equal non-empty label vectors are required")
    observed_disagreement = sum(
        left != right for left, right in zip(labels_a, labels_b)
    ) / len(labels_a)
    counts = Counter(labels_a + labels_b)
    total = len(labels_a) + len(labels_b)
    if total < 2:
        return None
    expected_disagreement = 1.0 - sum(
        count * (count - 1) for count in counts.values()
    ) / (total * (total - 1))
    if expected_disagreement == 0:
        return 1.0 if observed_disagreement == 0 else None
    return 1.0 - observed_disagreement / expected_disagreement


def confusion_matrix(
    labels_a: list[str],
    labels_b: list[str],
) -> dict[str, dict[str, int]]:
    matrix: dict[str, Counter[str]] = defaultdict(Counter)
    for left, right in zip(labels_a, labels_b):
        matrix[left][right] += 1
    return {
        left: dict(sorted(rights.items()))
        for left, rights in sorted(matrix.items())
    }


def reliability_block(
    rows: list[dict[str, Any]],
    labels_a: dict[str, str],
    labels_b: dict[str, str],
    special_label: str,
) -> dict[str, Any]:
    ids = [row["case_id"] for row in rows]
    vector_a = [labels_a[case_id] for case_id in ids]
    vector_b = [labels_b[case_id] for case_id in ids]
    agreements = sum(a == b for a, b in zip(vector_a, vector_b))
    return {
        "rows": len(ids),
        "agreements": agreements,
        "raw_agreement": agreements / len(ids) if ids else None,
        "nominal_krippendorff_alpha": (
            nominal_alpha(vector_a, vector_b) if ids else None
        ),
        "confusion_matrix_a_rows_b_columns": confusion_matrix(vector_a, vector_b),
        "reviewer_a_special_rate": (
            sum(value == special_label for value in vector_a) / len(ids)
            if ids
            else None
        ),
        "reviewer_b_special_rate": (
            sum(value == special_label for value in vector_b) / len(ids)
            if ids
            else None
        ),
    }


def percentile(values: list[float], probability: float) -> float:
    if not values:
        raise ValueError("cannot take percentile of empty list")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def paired_bootstrap_interval(
    clusters: dict[str, list[float]],
    seed_scope: str,
    replicates: int = BOOTSTRAP_REPLICATES,
) -> list[float]:
    cluster_ids = sorted(clusters)
    if not cluster_ids:
        return [0.0, 0.0]
    seed = int.from_bytes(
        f"{BOOTSTRAP_SEED}|{seed_scope}".encode("utf-8"), "little"
    ) % (2**64)
    rng = random.Random(seed)
    estimates = []
    for _ in range(replicates):
        sampled = [rng.choice(cluster_ids) for _ in cluster_ids]
        values = [
            value
            for cluster_id in sampled
            for value in clusters[cluster_id]
        ]
        estimates.append(sum(values) / len(values))
    return [percentile(estimates, 0.025), percentile(estimates, 0.975)]


def reviewer_policy_result(
    rows: list[dict[str, Any]],
    labels: dict[str, str],
) -> dict[str, Any]:
    simple_matches = 0
    type_matches = 0
    simple_only = 0
    type_only = 0
    differences: dict[str, list[float]] = defaultdict(list)
    by_field: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        human = labels[row["case_id"]]
        simple = row["policy_actions"][MAIN_FIRST]
        type_first = row["policy_actions"][MAIN_SECOND]
        simple_match = simple == human
        type_match = type_first == human
        simple_matches += simple_match
        type_matches += type_match
        simple_only += simple_match and not type_match
        type_only += type_match and not simple_match
        difference = float(type_match) - float(simple_match)
        differences[str(row["cve_id"])].append(difference)
        by_field[row["field"]]["rows"] += 1
        by_field[row["field"]]["simple_matches"] += simple_match
        by_field[row["field"]]["type_matches"] += type_match
        by_field[row["field"]]["simple_only_matches"] += (
            simple_match and not type_match
        )
        by_field[row["field"]]["type_only_matches"] += (
            type_match and not simple_match
        )
    total = len(rows)
    return {
        "rows": total,
        "field_aware_simple_exact_matches": simple_matches,
        "type_first_abstention_exact_matches": type_matches,
        "paired_match_difference_type_minus_simple": (
            (type_matches - simple_matches) / total if total else 0.0
        ),
        "discordant_counts": {
            "simple_only_matches_b": simple_only,
            "type_only_matches_c": type_only,
        },
        "exact_two_sided_mcnemar_p": exact_two_sided_mcnemar_p(
            simple_only, type_only
        ),
        "cve_blocked_bootstrap_95pct_interval": paired_bootstrap_interval(
            differences, "reviewer_policy"
        ),
        "by_field": {
            field: dict(sorted(counts.items()))
            for field, counts in sorted(by_field.items())
        },
    }


def pooled_policy_sensitivity(
    rows: list[dict[str, Any]],
    labels_by_reviewer: dict[str, dict[str, str]],
) -> dict[str, Any]:
    clusters: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        for labels in labels_by_reviewer.values():
            human = labels[row["case_id"]]
            simple_match = row["policy_actions"][MAIN_FIRST] == human
            type_match = row["policy_actions"][MAIN_SECOND] == human
            clusters[str(row["cve_id"])].append(
                float(type_match) - float(simple_match)
            )
    values = [value for cluster in clusters.values() for value in cluster]
    return {
        "reviewer_case_observations": len(values),
        "cve_clusters": len(clusters),
        "paired_match_difference_type_minus_simple": sum(values) / len(values),
        "cve_blocked_bootstrap_95pct_interval": paired_bootstrap_interval(
            clusters, "pooled_reviewers"
        ),
    }


def safety_result(
    rows: list[dict[str, Any]],
    labels: dict[str, str],
    safety_case_ids: set[str],
) -> dict[str, Any]:
    conflicts = [row for row in rows if labels[row["case_id"]] == "conflict_escalation"]
    simple_manual = sum(
        row["policy_actions"][MAIN_FIRST] in MANUAL_REVIEW_ACTIONS
        for row in conflicts
    )
    type_manual = sum(
        row["policy_actions"][MAIN_SECOND] in MANUAL_REVIEW_ACTIONS
        for row in conflicts
    )
    simple_only = [
        row
        for row in conflicts
        if row["policy_actions"][MAIN_FIRST] in MANUAL_REVIEW_ACTIONS
        and row["policy_actions"][MAIN_SECOND] not in MANUAL_REVIEW_ACTIONS
    ]
    type_only = [
        row
        for row in conflicts
        if row["policy_actions"][MAIN_SECOND] in MANUAL_REVIEW_ACTIONS
        and row["policy_actions"][MAIN_FIRST] not in MANUAL_REVIEW_ACTIONS
    ]
    n_conflicts = len(conflicts)
    upper = (
        one_sided_cp_upper(len(simple_only), n_conflicts)
        if n_conflicts
        else None
    )
    shared_misses = [
        row["case_id"]
        for row in conflicts
        if row["case_id"] in safety_case_ids
    ]
    reporting_floor_met = n_conflicts >= 25
    positive_gate = (
        n_conflicts >= 29
        and type_manual >= simple_manual
        and upper is not None
        and upper < 0.10
    )
    return {
        "human_conflict_escalation_actions": n_conflicts,
        "reporting_floor_25_met": reporting_floor_met,
        "positive_framing_floor_29_met": n_conflicts >= 29,
        "field_aware_simple_manual_route_coverage": (
            simple_manual / n_conflicts if n_conflicts else None
        ),
        "type_first_abstention_manual_route_coverage": (
            type_manual / n_conflicts if n_conflicts else None
        ),
        "paired_coverage_difference_type_minus_simple": (
            (type_manual - simple_manual) / n_conflicts if n_conflicts else None
        ),
        "discordant_counts": {
            "simple_only_manual_losses": len(simple_only),
            "type_only_manual_gains": len(type_only),
        },
        "simple_only_loss_one_sided_95pct_exact_upper": upper,
        "selected_margin": 0.10,
        "shared_no_manual_human_conflict_cases": shared_misses,
        "shared_no_manual_human_conflict_count": len(shared_misses),
        "positive_safety_gate_pass": positive_gate,
    }


def contingency(
    rows: list[dict[str, Any]],
    first: dict[str, str],
    second: dict[str, str],
) -> dict[str, dict[str, int]]:
    return confusion_matrix(
        [first[row["case_id"]] for row in rows],
        [second[row["case_id"]] for row in rows],
    )


def systematic_failures(
    rows: list[dict[str, Any]],
    labels_a: dict[str, str],
    labels_b: dict[str, str],
    kind: str,
) -> list[dict[str, Any]]:
    field_totals: Counter[str] = Counter()
    pair_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        left = labels_a[row["case_id"]]
        right = labels_b[row["case_id"]]
        if left == right:
            continue
        pair = " <> ".join(sorted((left, right)))
        field_totals[row["field"]] += 1
        pair_counts[pair][row["field"]] += 1
    findings = []
    for pair, fields in pair_counts.items():
        qualifying = {
            field: {
                "pair_count": count,
                "field_disagreements": field_totals[field],
                "share": count / field_totals[field],
            }
            for field, count in fields.items()
            if field_totals[field] and count / field_totals[field] >= 0.30
        }
        if len(qualifying) >= 2:
            findings.append(
                {"kind": kind, "label_pair": pair, "fields": qualifying}
            )
    return findings


def weighted_sensitivity(
    rows: list[dict[str, Any]],
    labels: dict[str, str],
) -> dict[str, Any]:
    by_field: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_field[row["field"]].append(row)
    output = {}
    for field, field_rows in sorted(by_field.items()):
        weights = [float(row["evaluation_weight"]) for row in field_rows]
        denominator = sum(weights)
        output[field] = {
            "rows": len(field_rows),
            "kish_effective_sample_size": kish_effective_sample_size(weights),
            "field_aware_simple_weighted_action_match": sum(
                weight
                * (
                    row["policy_actions"][MAIN_FIRST]
                    == labels[row["case_id"]]
                )
                for row, weight in zip(field_rows, weights)
            )
            / denominator,
            "type_first_abstention_weighted_action_match": sum(
                weight
                * (
                    row["policy_actions"][MAIN_SECOND]
                    == labels[row["case_id"]]
                )
                for row, weight in zip(field_rows, weights)
            )
            / denominator,
        }
    return output


def label_map(rows: list[dict[str, Any]], stage: str) -> dict[str, str]:
    key = "action_label" if stage == "action" else "reason_label"
    return {row["case_id"]: row["annotation"][key] for row in rows}


def evaluate(
    mapping_rows: list[dict[str, Any]],
    action_labels: dict[str, dict[str, str]],
    reason_labels: dict[str, dict[str, str]],
    safety_case_ids: set[str],
) -> dict[str, Any]:
    rows = [row for row in mapping_rows if row["phase"] == "evaluation"]
    rows_by_field = {
        field: [row for row in rows if row["field"] == field]
        for field in builder.FIELDS
    }
    action_reliability = {
        "overall": reliability_block(
            rows,
            action_labels["reviewer_a"],
            action_labels["reviewer_b"],
            "abstain",
        ),
        "by_field": {
            field: reliability_block(
                field_rows,
                action_labels["reviewer_a"],
                action_labels["reviewer_b"],
                "abstain",
            )
            for field, field_rows in rows_by_field.items()
        },
    }
    reason_reliability = {
        "overall": reliability_block(
            rows,
            reason_labels["reviewer_a"],
            reason_labels["reviewer_b"],
            "uncertain",
        ),
        "by_field": {
            field: reliability_block(
                field_rows,
                reason_labels["reviewer_a"],
                reason_labels["reviewer_b"],
                "uncertain",
            )
            for field, field_rows in rows_by_field.items()
        },
    }
    disagreement_rows = [
        row
        for row in rows
        if row["policy_actions"][MAIN_FIRST]
        != row["policy_actions"][MAIN_SECOND]
    ]
    reviewer_policy = {
        reviewer: reviewer_policy_result(disagreement_rows, labels)
        for reviewer, labels in action_labels.items()
    }
    pooled = pooled_policy_sensitivity(disagreement_rows, action_labels)
    safety = {
        reviewer: safety_result(rows, labels, safety_case_ids)
        for reviewer, labels in action_labels.items()
    }
    failures = systematic_failures(
        rows,
        action_labels["reviewer_a"],
        action_labels["reviewer_b"],
        "action",
    ) + systematic_failures(
        rows,
        reason_labels["reviewer_a"],
        reason_labels["reviewer_b"],
        "reason",
    )
    reliability_pass = (
        action_reliability["overall"]["raw_agreement"] >= 0.60
        and action_reliability["overall"]["nominal_krippendorff_alpha"] is not None
        and action_reliability["overall"]["nominal_krippendorff_alpha"] >= 0.40
    )
    directions = [
        reviewer_policy[reviewer][
            "paired_match_difference_type_minus_simple"
        ]
        for reviewer in builder.REVIEWERS
    ]
    pooled_interval = pooled["cve_blocked_bootstrap_95pct_interval"]
    efficiency_pass = all(value > 0 for value in directions) and pooled_interval[0] > 0
    safety_pass = all(
        safety[reviewer]["positive_safety_gate_pass"]
        for reviewer in builder.REVIEWERS
    )
    positive = reliability_pass and efficiency_pass and safety_pass and not failures
    return {
        "formal_rows": len(rows),
        "pre_adjudication_primary": True,
        "action_reliability": action_reliability,
        "reason_reliability": reason_reliability,
        "policy_disagreement_rows": len(disagreement_rows),
        "reviewer_specific_policy_comparison": reviewer_policy,
        "pooled_cve_blocked_sensitivity": pooled,
        "safety": safety,
        "reason_action_association": {
            "primary_cross_reviewer": {
                "reviewer_a_action_by_reviewer_b_reason": contingency(
                    rows,
                    action_labels["reviewer_a"],
                    reason_labels["reviewer_b"],
                ),
                "reviewer_b_action_by_reviewer_a_reason": contingency(
                    rows,
                    action_labels["reviewer_b"],
                    reason_labels["reviewer_a"],
                ),
            },
            "same_reviewer_upper_bound": {
                reviewer: contingency(
                    rows,
                    action_labels[reviewer],
                    reason_labels[reviewer],
                )
                for reviewer in builder.REVIEWERS
            },
        },
        "systematic_failure_candidates": failures,
        "population_weight_sensitivity": {
            reviewer: weighted_sensitivity(rows, labels)
            for reviewer, labels in action_labels.items()
        },
        "gates": {
            "formal_construct_reliability_pass": reliability_pass,
            "efficiency_endpoint_pass": efficiency_pass,
            "safety_endpoint_both_reviewers_pass": safety_pass,
            "systematic_failure_absent": not failures,
            "positive_efficiency_safety_framing_eligible": positive,
            "manuscript_route": (
                "POSITIVE_EFFICIENCY_SAFETY_CANDIDATE"
                if positive
                else "BOUNDARY_OR_DECISION_AMBIGUITY"
            ),
        },
    }


def validate_lock(
    path: Path,
    phase: str,
    stage: str,
    return_paths: dict[str, Path],
) -> list[str]:
    errors: list[str] = []
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot load {stage} lock: {exc}"]
    if (
        lock.get("schema_version") != "t1_v31_stage_lock_v1"
        or lock.get("protocol_id") != builder.PROTOCOL_ID
        or lock.get("phase") != phase
        or lock.get("stage") != stage
        or lock.get("locked") is not True
    ):
        errors.append(f"invalid {stage} lock identity or state")
        return errors
    for reviewer, return_path in return_paths.items():
        expected = (
            lock.get("reviewer_returns", {}).get(reviewer, {}).get("sha256")
        )
        if expected != packet_validator.sha256_file(return_path):
            errors.append(f"{stage} lock hash mismatch for {reviewer}")
    return errors


def read_excluded_case_ids(path: Path | None) -> set[str]:
    if path is None:
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def result_report(result: dict[str, Any]) -> str:
    gates = result["primary"]["gates"]
    return "\n".join(
        [
            "# T1/T2 V3.1 Pre-Adjudication Evaluation",
            "",
            f"Route: `{gates['manuscript_route']}`",
            "",
            "This report is generated only from two independently sealed formal",
            "action returns and two independently sealed reason returns. Reviewer-",
            "specific results remain separate.",
            "",
            "## Gates",
            "",
            f"- Construct reliability: {gates['formal_construct_reliability_pass']}",
            f"- Efficiency endpoint: {gates['efficiency_endpoint_pass']}",
            (
                "- Safety endpoint, both reviewers: "
                f"{gates['safety_endpoint_both_reviewers_pass']}"
            ),
            f"- Systematic failure absent: {gates['systematic_failure_absent']}",
            (
                "- Positive framing eligible: "
                f"{gates['positive_efficiency_safety_framing_eligible']}"
            ),
            "",
            "See analysis.json for discordant counts, exact McNemar tests,",
            "reviewer-specific safety bounds, reliability matrices, associations,",
            "and weighted sensitivity results.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    packet_dir = resolve(args.packet_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite evaluation output: {output_dir}")
    return_paths = {
        "action": {
            "reviewer_a": resolve(args.reviewer_a_action),
            "reviewer_b": resolve(args.reviewer_b_action),
        },
        "reason": {
            "reviewer_a": resolve(args.reviewer_a_reason),
            "reviewer_b": resolve(args.reviewer_b_reason),
        },
    }
    errors = packet_validator.validate_packet_dir(packet_dir)
    loaded: dict[str, dict[str, list[dict[str, Any]]]] = {
        "action": {},
        "reason": {},
    }
    for stage in builder.STAGES:
        for reviewer in builder.REVIEWERS:
            return_errors, _, rows = return_validator.validate_return_file(
                packet_dir,
                reviewer,
                "evaluation",
                stage,
                return_paths[stage][reviewer],
                validate_packet_seal=False,
            )
            errors.extend(return_errors)
            loaded[stage][reviewer] = rows
    errors.extend(
        validate_lock(
            resolve(args.action_lock),
            "evaluation",
            "action",
            return_paths["action"],
        )
    )
    errors.extend(
        validate_lock(
            resolve(args.reason_lock),
            "evaluation",
            "reason",
            return_paths["reason"],
        )
    )
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 2

    manifest = json.loads(
        (packet_dir / "manifest.json").read_text(encoding="utf-8")
    )
    mapping_rows = packet_validator.load_jsonl(
        packet_dir / manifest["internal_mapping"]
    )
    safety_rows = packet_validator.load_jsonl(
        packet_dir
        / manifest["shared_no_manual_route_audit"]["internal_file"]
    )
    safety_case_ids = {row["case_id"] for row in safety_rows}
    action_labels = {
        reviewer: label_map(loaded["action"][reviewer], "action")
        for reviewer in builder.REVIEWERS
    }
    reason_labels = {
        reviewer: label_map(loaded["reason"][reviewer], "reason")
        for reviewer in builder.REVIEWERS
    }
    primary = evaluate(
        mapping_rows,
        action_labels,
        reason_labels,
        safety_case_ids,
    )
    excluded = read_excluded_case_ids(
        resolve(args.adjudicated_case_ids) if args.adjudicated_case_ids else None
    )
    unknown_exclusions = excluded - {
        row["case_id"] for row in mapping_rows if row["phase"] == "evaluation"
    }
    if unknown_exclusions:
        raise ValueError(
            f"unknown adjudicated case IDs: {sorted(unknown_exclusions)[:5]}"
        )
    exclusion_sensitivity = None
    if excluded:
        reduced_mapping = [
            row for row in mapping_rows if row["case_id"] not in excluded
        ]
        reduced_actions = {
            reviewer: {
                case_id: label
                for case_id, label in labels.items()
                if case_id not in excluded
            }
            for reviewer, labels in action_labels.items()
        }
        reduced_reasons = {
            reviewer: {
                case_id: label
                for case_id, label in labels.items()
                if case_id not in excluded
            }
            for reviewer, labels in reason_labels.items()
        }
        exclusion_sensitivity = evaluate(
            reduced_mapping,
            reduced_actions,
            reduced_reasons,
            safety_case_ids - excluded,
        )
    result = {
        "schema_version": "t1_v31_pre_adjudication_evaluation_v1",
        "protocol_id": builder.PROTOCOL_ID,
        "primary": primary,
        "adjudication_exclusion_sensitivity": exclusion_sensitivity,
        "excluded_adjudicated_case_ids": sorted(excluded),
        "input_hashes": {
            str(path): packet_validator.sha256_file(path)
            for stage_paths in return_paths.values()
            for path in stage_paths.values()
        },
        "claim_boundary": {
            "pre_adjudication_is_primary": True,
            "same_reviewer_reason_action_is_upper_bound": True,
            "population_projection_is_sensitivity_only": True,
            "routing_counts_are_not_labor_savings": True,
        },
    }
    output_dir.mkdir(parents=True)
    (output_dir / "analysis.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(result_report(result), encoding="utf-8")
    print(
        "PASS: V3.1 pre-adjudication evaluation complete; "
        f"route={primary['gates']['manuscript_route']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
