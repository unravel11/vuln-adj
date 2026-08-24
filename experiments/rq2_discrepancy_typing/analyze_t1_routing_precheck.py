#!/usr/bin/env python3
"""Run the label-free routing-policy disagreement and identifiability precheck."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIELD_VIEW = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_CONTRACT = (
    "experiments/rq2_discrepancy_typing/"
    "T1_ROUTING_PRECHECK_PROTOCOL_V1.md"
)
DEFAULT_OUTPUT_DIR = "results/jss/t1_routing_precheck_v1"

FIELDS = ("severity", "affected_versions", "published", "references")
ACTIONS = (
    "no_action",
    "enrich_record",
    "wait_for_sync",
    "conflict_escalation",
    "abstain",
)
POLICIES = (
    "binary_observed_non_equal",
    "binary_canonical_non_equal",
    "field_aware_simple_v1",
    "type_first_current_v1",
    "type_first_abstention_v1",
    "always_manual",
    "abstain_all",
)
MAIN_FIRST = "field_aware_simple_v1"
MAIN_SECOND = "type_first_abstention_v1"
MANUAL_REVIEW_ACTIONS = {"conflict_escalation", "abstain"}
EFFICACY_FIELDS = {"severity", "affected_versions"}
FORMAL_BUDGET = {
    "severity": 50,
    "affected_versions": 50,
    "published": 10,
    "references": 10,
}
ALPHA = 0.05

TYPE_ACTION_MAP = {
    "equivalent": "no_action",
    "representation_discrepancy": "no_action",
    "incomplete": "enrich_record",
    "temporal_discrepancy": "wait_for_sync",
    "factual_conflict": "conflict_escalation",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-view", default=DEFAULT_FIELD_VIEW)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def effective_span(span: dict) -> tuple[str | None, ...]:
    lower_including = span.get("version_start_including") or span.get("introduced")
    lower_excluding = span.get("version_start_excluding")
    upper_including = span.get("version_end_including")
    upper_excluding = span.get("version_end_excluding") or span.get("fixed")
    point = span.get("version")
    if any((lower_including, lower_excluding, upper_including, upper_excluding)):
        point = None
    return (
        lower_including,
        lower_excluding,
        upper_including,
        upper_excluding,
        point,
    )


def normalized_effective_spans(spans: list[dict]) -> tuple[tuple[str | None, ...], ...]:
    return tuple(
        sorted(
            {effective_span(span) for span in spans or []},
            key=lambda item: tuple("" if value is None else value for value in item),
        )
    )


def safe_version(value: str | None) -> Version | None:
    if not value:
        return None
    try:
        return Version(str(value))
    except InvalidVersion:
        return None


def parsed_interval(
    span: dict,
) -> tuple[Version | None, bool, Version | None, bool] | None:
    point_raw = span.get("version")
    has_range = any(
        span.get(key)
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
            "introduced",
            "fixed",
        )
    )
    if point_raw and not has_range:
        point = safe_version(point_raw)
        return None if point is None else (point, True, point, True)

    lower_including_raw = span.get("version_start_including") or span.get("introduced")
    lower_excluding_raw = span.get("version_start_excluding")
    upper_including_raw = span.get("version_end_including")
    upper_excluding_raw = span.get("version_end_excluding") or span.get("fixed")
    raw_values = (
        lower_including_raw,
        lower_excluding_raw,
        upper_including_raw,
        upper_excluding_raw,
    )
    if not any(raw_values):
        return None
    parsed = tuple(safe_version(value) for value in raw_values)
    if any(raw is not None and value is None for raw, value in zip(raw_values, parsed)):
        return None
    lower_including, lower_excluding, upper_including, upper_excluding = parsed
    lower = lower_including or lower_excluding
    upper = upper_including or upper_excluding
    return (
        lower,
        lower_including is not None,
        upper,
        upper_including is not None,
    )


def intervals_overlap(
    first: tuple[Version | None, bool, Version | None, bool],
    second: tuple[Version | None, bool, Version | None, bool],
) -> bool:
    first_lower, first_lower_inc, first_upper, first_upper_inc = first
    second_lower, second_lower_inc, second_upper, second_upper_inc = second
    if first_upper is not None and second_lower is not None:
        if first_upper < second_lower:
            return False
        if first_upper == second_lower and not (first_upper_inc and second_lower_inc):
            return False
    if second_upper is not None and first_lower is not None:
        if second_upper < first_lower:
            return False
        if second_upper == first_lower and not (second_upper_inc and first_lower_inc):
            return False
    return True


def interval_relation(left: list[dict], right: list[dict]) -> str:
    left_intervals = [parsed_interval(span) for span in left or []]
    right_intervals = [parsed_interval(span) for span in right or []]
    if (
        not left_intervals
        or not right_intervals
        or any(value is None for value in left_intervals + right_intervals)
    ):
        return "unknown"
    if any(
        intervals_overlap(first, second)
        for first in left_intervals
        for second in right_intervals
        if first is not None and second is not None
    ):
        return "overlap"
    return "disjoint"


def package_key(value: str) -> str | None:
    normalized = value.strip().lower()
    if not normalized:
        return None
    normalized = normalized.removeprefix("pkg:")
    tail = re.split(r"[:/]", normalized)[-1]
    tail = re.sub(r"[^a-z0-9]+", "-", tail).strip("-")
    return tail or None


def packages_comparable(field_view: dict) -> bool | None:
    packages = field_view.get("package_names") or {}
    left = {key for value in packages.get("nvd") or [] if (key := package_key(value))}
    right = {key for value in packages.get("ghsa") or [] if (key := package_key(value))}
    if not left or not right:
        return None
    return bool(left & right)


def observed_values(field_view: dict, field: str) -> tuple[object, object]:
    value = field_view[field]
    if field == "severity":
        return (value["nvd"].get("label"), value["ghsa"].get("label"))
    if field == "published":
        return (value.get("nvd"), value.get("ghsa"))
    if field == "references":
        return (
            tuple(value.get("nvd_urls") or []),
            tuple(value.get("ghsa_urls") or []),
        )
    if field == "affected_versions":
        return (
            tuple(
                json.dumps(item, sort_keys=True)
                for item in value.get("nvd") or []
            ),
            tuple(
                json.dumps(item, sort_keys=True)
                for item in value.get("ghsa") or []
            ),
        )
    raise ValueError(f"unsupported field: {field}")


def canonical_values(field_view: dict, field: str) -> tuple[object, object]:
    value = field_view[field]
    if field == "severity":
        return (
            value["nvd"].get("canonical_label"),
            value["ghsa"].get("canonical_label"),
        )
    if field == "published":
        left = parse_datetime(value.get("nvd"))
        right = parse_datetime(value.get("ghsa"))
        return (
            left.isoformat() if left else value.get("nvd"),
            right.isoformat() if right else value.get("ghsa"),
        )
    if field == "references":
        return (
            tuple(sorted(set(value.get("nvd_urls") or []))),
            tuple(sorted(set(value.get("ghsa_urls") or []))),
        )
    if field == "affected_versions":
        return (
            normalized_effective_spans(value.get("nvd") or []),
            normalized_effective_spans(value.get("ghsa") or []),
        )
    raise ValueError(f"unsupported field: {field}")


def binary_action(left: object, right: object) -> str:
    return "no_action" if left == right else "conflict_escalation"


def simple_policy_action(field_view: dict, field: str) -> str:
    value = field_view[field]
    if field == "severity":
        left_raw = value["nvd"].get("label")
        right_raw = value["ghsa"].get("label")
        left = value["nvd"].get("canonical_label")
        right = value["ghsa"].get("canonical_label")
        if left_raw is None and right_raw is None:
            return "no_action"
        if left_raw is None or right_raw is None:
            return "enrich_record"
        if left is None or right is None:
            return "abstain"
        return "no_action" if left == right else "conflict_escalation"

    if field == "published":
        left_raw = value.get("nvd")
        right_raw = value.get("ghsa")
        if not left_raw and not right_raw:
            return "no_action"
        if not left_raw or not right_raw:
            return "enrich_record"
        left = parse_datetime(left_raw)
        right = parse_datetime(right_raw)
        if left is None or right is None:
            return "abstain"
        if left.date() == right.date():
            return "no_action"
        return "wait_for_sync"

    if field == "references":
        left = set(value.get("nvd_urls") or [])
        right = set(value.get("ghsa_urls") or [])
        return "no_action" if left == right else "enrich_record"

    if field == "affected_versions":
        left = value.get("nvd") or []
        right = value.get("ghsa") or []
        if not left and not right:
            return "no_action"
        if not left or not right:
            return "enrich_record"
        left_effective = set(normalized_effective_spans(left))
        right_effective = set(normalized_effective_spans(right))
        if left_effective == right_effective:
            return "no_action"
        if left_effective.issubset(right_effective) or right_effective.issubset(
            left_effective
        ):
            return "enrich_record"
        if packages_comparable(field_view) is not True:
            return "abstain"
        relation = interval_relation(left, right)
        if relation == "disjoint":
            return "conflict_escalation"
        if relation == "overlap":
            return "enrich_record"
        return "abstain"

    raise ValueError(f"unsupported field: {field}")


def cvss_version(vector: str | None) -> str | None:
    if not vector:
        return None
    match = re.match(r"^CVSS:([0-9.]+)/", vector)
    return match.group(1) if match else None


def type_first_action(field_view: dict, field: str, *, abstention: bool) -> str:
    discrepancy = field_view["field_discrepancies"][field]
    status = discrepancy.get("status")
    if status not in TYPE_ACTION_MAP:
        raise ValueError(f"{field}: unsupported deterministic status {status!r}")
    if not abstention:
        return TYPE_ACTION_MAP[status]

    value = field_view[field]
    if field == "severity" and status == "factual_conflict":
        left_version = cvss_version(value["nvd"].get("vector"))
        right_version = cvss_version(value["ghsa"].get("vector"))
        if left_version and right_version and left_version != right_version:
            return "abstain"
    elif field == "published" and status == "factual_conflict":
        return "abstain"
    elif field == "references" and status == "factual_conflict":
        return "abstain"
    elif field == "affected_versions":
        left = value.get("nvd") or []
        right = value.get("ghsa") or []
        if left and right and packages_comparable(field_view) is not True:
            return "abstain"
        if status == "factual_conflict" and interval_relation(left, right) == "unknown":
            return "abstain"
    return TYPE_ACTION_MAP[status]


def policy_actions(field_view: dict, field: str) -> dict[str, str]:
    observed_left, observed_right = observed_values(field_view, field)
    canonical_left, canonical_right = canonical_values(field_view, field)
    return {
        "binary_observed_non_equal": binary_action(
            observed_left, observed_right
        ),
        "binary_canonical_non_equal": binary_action(
            canonical_left, canonical_right
        ),
        "field_aware_simple_v1": simple_policy_action(field_view, field),
        "type_first_current_v1": type_first_action(
            field_view, field, abstention=False
        ),
        "type_first_abstention_v1": type_first_action(
            field_view, field, abstention=True
        ),
        "always_manual": "conflict_escalation",
        "abstain_all": "abstain",
    }


def exact_two_sided_mcnemar_p(first_only: int, second_only: int) -> float:
    if first_only < 0 or second_only < 0:
        raise ValueError("discordant counts must be non-negative")
    total = first_only + second_only
    if total == 0:
        return 1.0
    lower = min(first_only, second_only)
    numerator = sum(math.comb(total, value) for value in range(lower + 1))
    return min(1.0, 2.0 * numerator / (2**total))


def minimum_rows_for_any_rejection(alpha: float = ALPHA) -> int:
    for rows in range(1, 10_001):
        if exact_two_sided_mcnemar_p(0, rows) <= alpha:
            return rows
    raise ValueError("no exact-test rejection boundary found")


def conditional_power(rows: int, win_probability: float) -> float:
    if not 0.5 < win_probability < 1.0:
        raise ValueError("win probability must be between 0.5 and 1")
    return sum(
        math.comb(rows, second_only)
        * (win_probability**second_only)
        * ((1.0 - win_probability) ** (rows - second_only))
        for second_only in range(rows + 1)
        if second_only > rows - second_only
        and exact_two_sided_mcnemar_p(rows - second_only, second_only) <= ALPHA
    )


def minimum_rows_for_power(win_probability: float, target: float = 0.80) -> dict:
    for rows in range(1, 10_001):
        power = conditional_power(rows, win_probability)
        if power >= target:
            return {
                "candidate_win_probability_on_effective_discordance": win_probability,
                "target_power": target,
                "minimum_effective_discordant_rows": rows,
                "achieved_exact_power": power,
            }
    raise ValueError("power target not reached")


def nested_counts(counter: dict[str, Counter]) -> dict[str, dict[str, int]]:
    return {
        key: {name: value[name] for name in sorted(value)}
        for key, value in sorted(counter.items())
    }


def compute_analysis(rows: list[dict]) -> dict:
    status_counts: dict[str, Counter] = defaultdict(Counter)
    policy_counts: dict[str, dict[str, Counter]] = {
        policy: defaultdict(Counter) for policy in POLICIES
    }
    pairwise_counts: dict[str, Counter] = defaultdict(Counter)
    main_by_field: dict[str, Counter] = defaultdict(Counter)
    main_by_status: dict[str, Counter] = defaultdict(Counter)
    main_action_pairs: dict[str, Counter] = defaultdict(Counter)
    field_instances = 0

    for row in rows:
        field_view = row.get("unified_view") or {}
        discrepancies = row.get("field_discrepancies") or {}
        if set(FIELDS) - set(field_view):
            raise ValueError(f"{row.get('cve_id')}: missing required field view")
        if set(FIELDS) - set(discrepancies):
            raise ValueError(f"{row.get('cve_id')}: missing field discrepancies")
        policy_view = dict(field_view)
        policy_view["field_discrepancies"] = discrepancies
        for field in FIELDS:
            field_instances += 1
            status = discrepancies[field].get("status")
            status_counts[field][status] += 1
            actions = policy_actions(policy_view, field)
            if set(actions) != set(POLICIES) or set(actions.values()) - set(ACTIONS):
                raise ValueError(f"{row.get('cve_id')}:{field}: invalid policy actions")
            for policy, action in actions.items():
                policy_counts[policy][field][action] += 1
            for first_index, first in enumerate(POLICIES):
                for second in POLICIES[first_index + 1 :]:
                    key = f"{first}__vs__{second}"
                    if actions[first] != actions[second]:
                        pairwise_counts[key][field] += 1

            first_action = actions[MAIN_FIRST]
            second_action = actions[MAIN_SECOND]
            action_diff = first_action != second_action
            conflict_diff = (
                (first_action == "conflict_escalation")
                != (second_action == "conflict_escalation")
            )
            manual_diff = (
                (first_action in MANUAL_REVIEW_ACTIONS)
                != (second_action in MANUAL_REVIEW_ACTIONS)
            )
            if action_diff:
                main_by_field[field]["action_disagreement"] += 1
                main_by_status[f"{field}:{status}"]["action_disagreement"] += 1
                main_action_pairs[field][
                    f"{first_action}__to__{second_action}"
                ] += 1
            if conflict_diff:
                main_by_field[field]["conflict_queue_disagreement"] += 1
                main_by_status[f"{field}:{status}"][
                    "conflict_queue_disagreement"
                ] += 1
            if manual_diff:
                main_by_field[field]["manual_review_disagreement"] += 1
                main_by_status[f"{field}:{status}"][
                    "manual_review_disagreement"
                ] += 1

    if len(rows) != 8066:
        raise ValueError(f"expected 8,066 aligned rows, found {len(rows)}")
    if field_instances != len(rows) * len(FIELDS):
        raise ValueError("field-instance count drift")

    main_fields = {}
    for field in FIELDS:
        counts = main_by_field[field]
        main_fields[field] = {
            "rows": sum(status_counts[field].values()),
            "action_disagreement": counts["action_disagreement"],
            "conflict_queue_disagreement": counts[
                "conflict_queue_disagreement"
            ],
            "manual_review_disagreement": counts[
                "manual_review_disagreement"
            ],
            "action_pairs": {
                key: main_action_pairs[field][key]
                for key in sorted(main_action_pairs[field])
            },
        }

    power_sensitivity = [
        minimum_rows_for_power(probability) for probability in (0.70, 0.80, 0.90)
    ]
    power_target_rows = next(
        item["minimum_effective_discordant_rows"]
        for item in power_sensitivity
        if item["candidate_win_probability_on_effective_discordance"] == 0.80
    )
    sampling_fields = {}
    for field in FIELDS:
        available = main_fields[field]
        budget = FORMAL_BUDGET[field]
        sampled_action_capacity = min(budget, available["action_disagreement"])
        sampled_conflict_capacity = min(
            budget, available["conflict_queue_disagreement"]
        )
        sampled_manual_capacity = min(
            budget, available["manual_review_disagreement"]
        )
        sampling_fields[field] = {
            "formal_budget": budget,
            "available_action_disagreements": available["action_disagreement"],
            "available_conflict_queue_disagreements": available[
                "conflict_queue_disagreement"
            ],
            "available_manual_review_disagreements": available[
                "manual_review_disagreement"
            ],
            "maximum_sampled_action_disagreements": sampled_action_capacity,
            "maximum_sampled_conflict_queue_disagreements": (
                sampled_conflict_capacity
            ),
            "maximum_sampled_manual_review_disagreements": (
                sampled_manual_capacity
            ),
            "minimum_attainable_exact_p_if_all_effective_action_discordance_one_way": (
                exact_two_sided_mcnemar_p(0, sampled_action_capacity)
                if sampled_action_capacity
                else 1.0
            ),
        }

    total_action_capacity = sum(
        item["maximum_sampled_action_disagreements"]
        for item in sampling_fields.values()
    )
    total_conflict_capacity = sum(
        item["maximum_sampled_conflict_queue_disagreements"]
        for item in sampling_fields.values()
    )
    total_manual_capacity = sum(
        item["maximum_sampled_manual_review_disagreements"]
        for item in sampling_fields.values()
    )

    simple_manual = sum(
        policy_counts[MAIN_FIRST][field][action]
        for field in FIELDS
        for action in MANUAL_REVIEW_ACTIONS
    )
    candidate_manual = sum(
        policy_counts[MAIN_SECOND][field][action]
        for field in FIELDS
        for action in MANUAL_REVIEW_ACTIONS
    )
    simple_conflict = sum(
        policy_counts[MAIN_FIRST][field]["conflict_escalation"]
        for field in FIELDS
    )
    candidate_conflict = sum(
        policy_counts[MAIN_SECOND][field]["conflict_escalation"]
        for field in FIELDS
    )

    minimum_rejection_rows = minimum_rows_for_any_rejection()
    fields_with_action_capacity = [
        field
        for field, item in sampling_fields.items()
        if item["maximum_sampled_action_disagreements"] >= minimum_rejection_rows
    ]
    efficacy_with_manual_capacity = [
        field
        for field in FIELDS
        if field in EFFICACY_FIELDS
        and sampling_fields[field]["maximum_sampled_manual_review_disagreements"]
        >= minimum_rejection_rows
    ]
    gates = {
        "input_has_no_human_labels": {
            "status": "PASS",
            "basis": "the frozen field view contains deterministic records only",
        },
        "main_policies_are_distinct": {
            "status": (
                "PASS"
                if sum(item["action_disagreement"] for item in main_fields.values())
                >= minimum_rejection_rows
                else "FAIL"
            ),
            "minimum_required_action_disagreements": minimum_rejection_rows,
        },
        "multi_field_action_identifiability": {
            "status": "PASS" if len(fields_with_action_capacity) >= 2 else "FAIL",
            "fields_meeting_minimum": fields_with_action_capacity,
            "minimum_required_fields": 2,
        },
        "efficacy_field_manual_review_identifiability": {
            "status": "PASS" if efficacy_with_manual_capacity else "FAIL",
            "fields_meeting_minimum": efficacy_with_manual_capacity,
        },
        "planned_sample_conditional_power_capacity": {
            "status": (
                "PASS" if total_action_capacity >= power_target_rows else "FAIL"
            ),
            "maximum_effective_action_discordance_capacity": total_action_capacity,
            "required_if_candidate_wins_80_percent_of_effective_discordance": (
                power_target_rows
            ),
            "capacity_is_not_realized_power": True,
        },
    }
    required_gate_names = (
        "input_has_no_human_labels",
        "main_policies_are_distinct",
        "multi_field_action_identifiability",
        "efficacy_field_manual_review_identifiability",
        "planned_sample_conditional_power_capacity",
    )
    gate_pass = all(gates[name]["status"] == "PASS" for name in required_gate_names)
    decision = (
        "CONDITIONAL_GO_FOR_V3_PACKET_DESIGN"
        if gate_pass
        else "NO_GO_FOR_POSITIVE_ROUTING_V3_UNDER_CURRENT_POLICIES"
    )

    return {
        "artifact_type": "t1_routing_precheck_analysis_v1",
        "label_source": "none_label_free_policy_census",
        "label_is_human": False,
        "uses_any_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_workload_reduction_claim": False,
        "eligible_for_submission_readiness_claim": False,
        "rows": len(rows),
        "field_instances": field_instances,
        "fields": list(FIELDS),
        "actions": list(ACTIONS),
        "policies": list(POLICIES),
        "primary_comparison": {
            "first": MAIN_FIRST,
            "second": MAIN_SECOND,
            "manual_review_actions": sorted(MANUAL_REVIEW_ACTIONS),
            "by_field": main_fields,
            "by_field_and_deterministic_status": nested_counts(main_by_status),
            "corpus_conflict_queue_counts": {
                MAIN_FIRST: simple_conflict,
                MAIN_SECOND: candidate_conflict,
                "candidate_minus_simple": candidate_conflict - simple_conflict,
            },
            "corpus_total_manual_review_counts": {
                MAIN_FIRST: simple_manual,
                MAIN_SECOND: candidate_manual,
                "candidate_minus_simple": candidate_manual - simple_manual,
            },
            "workload_counts_are_policy_outputs_not_human_validated": True,
        },
        "deterministic_status_counts": nested_counts(status_counts),
        "policy_action_counts": {
            policy: nested_counts(policy_counts[policy]) for policy in POLICIES
        },
        "pairwise_action_disagreement_counts": nested_counts(pairwise_counts),
        "sampling_capacity": {
            "planned_formal_rows": sum(FORMAL_BUDGET.values()),
            "planned_budget_by_field": FORMAL_BUDGET,
            "by_field": sampling_fields,
            "maximum_sampled_action_disagreements": total_action_capacity,
            "maximum_sampled_conflict_queue_disagreements": total_conflict_capacity,
            "maximum_sampled_manual_review_disagreements": total_manual_capacity,
            "minimum_rows_for_any_two_sided_exact_rejection": (
                minimum_rejection_rows
            ),
            "conditional_power_sensitivity": power_sensitivity,
            "sampling_capacity_is_not_power_or_expected_effect": True,
        },
        "gates": gates,
        "decision": decision,
        "decision_scope": (
            "whether a V3 dual-human packet can be designed to compare the "
            "frozen policies; not whether either policy is correct or superior"
        ),
    }


def markdown(analysis: dict) -> str:
    lines = [
        "# T1 Routing Precheck V1",
        "",
        f"Decision: {analysis['decision']}",
        "",
        "This is a label-free policy census. It contains no human labels and "
        "cannot establish correctness, superiority, workload reduction, or "
        "submission readiness.",
        "",
        "## Main policy disagreement",
        "",
        "| Field | Rows | Action diff | Conflict-queue diff | Manual-review diff | V3 budget |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    capacity = analysis["sampling_capacity"]["by_field"]
    for field, item in analysis["primary_comparison"]["by_field"].items():
        lines.append(
            f"| {field} | {item['rows']} | {item['action_disagreement']} | "
            f"{item['conflict_queue_disagreement']} | "
            f"{item['manual_review_disagreement']} | "
            f"{capacity[field]['formal_budget']} |"
        )
    lines.extend(
        [
            "",
            "## Corpus policy-output burden",
            "",
            "| Quantity | Field-aware simple | Type-first abstention | Difference |",
            "|---|---:|---:|---:|",
        ]
    )
    conflict = analysis["primary_comparison"]["corpus_conflict_queue_counts"]
    manual = analysis["primary_comparison"]["corpus_total_manual_review_counts"]
    lines.append(
        f"| Conflict-escalation queue | {conflict[MAIN_FIRST]} | "
        f"{conflict[MAIN_SECOND]} | {conflict['candidate_minus_simple']} |"
    )
    lines.append(
        f"| Escalation plus abstention | {manual[MAIN_FIRST]} | "
        f"{manual[MAIN_SECOND]} | {manual['candidate_minus_simple']} |"
    )
    lines.extend(
        [
            "",
            "These are deterministic policy outputs. They are not unnecessary "
            "escalations until independent human actions exist.",
            "",
            "## Label-free gates",
            "",
            "| Gate | Status |",
            "|---|---|",
        ]
    )
    for name, gate in analysis["gates"].items():
        lines.append(f"| {name} | {gate['status']} |")
    lines.extend(
        [
            "",
            "## Next action",
            "",
            (
                "Freeze a V3 sampling and annotation protocol only if the "
                "decision is CONDITIONAL_GO_FOR_V3_PACKET_DESIGN. Retain V2 "
                "as historical prepare-only material and do not distribute it."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def git_value(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ("git", *args), cwd=PROJECT_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def file_entry(path: Path) -> dict:
    return {"path": relative(path), "sha256": sha256(path)}


def main() -> int:
    args = parse_args()
    field_view_path = resolve(args.field_view)
    contract_path = resolve(args.contract)
    output_dir = resolve(args.output_dir)
    analyzer_path = Path(__file__).resolve()
    verifier_path = analyzer_path.with_name("verify_t1_routing_precheck.py")
    for required in (field_view_path, contract_path, verifier_path):
        if not required.is_file():
            raise FileNotFoundError(required)

    rows = list(iter_jsonl(field_view_path))
    analysis = compute_analysis(rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "analysis.md"
    manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(
        json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(markdown(analysis), encoding="utf-8")
    manifest = {
        "artifact_type": "t1_routing_precheck_manifest_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository": {
            "branch": git_value("branch", "--show-current"),
            "head_before_result_commit": git_value("rev-parse", "HEAD"),
        },
        "inputs": {
            "field_view": file_entry(field_view_path),
            "contract": file_entry(contract_path),
            "analyzer": file_entry(analyzer_path),
            "verifier": file_entry(verifier_path),
        },
        "outputs": {
            "analysis": file_entry(analysis_path),
            "markdown": file_entry(markdown_path),
        },
        "claim_boundary": {
            key: analysis[key]
            for key in (
                "label_is_human",
                "uses_any_labels",
                "eligible_for_human_gold_claim",
                "eligible_for_accuracy_claim",
                "eligible_for_policy_superiority_claim",
                "eligible_for_workload_reduction_claim",
                "eligible_for_submission_readiness_claim",
            )
        },
        "decision": analysis["decision"],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"T1 routing precheck: rows={analysis['rows']} "
        f"field_instances={analysis['field_instances']} "
        f"decision={analysis['decision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
