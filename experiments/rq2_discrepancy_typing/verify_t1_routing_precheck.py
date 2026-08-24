#!/usr/bin/env python3
"""Independently verify the label-free T1 routing precheck."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_DIR = "results/jss/t1_routing_precheck_v1"
FIELDS = ("severity", "affected_versions", "published", "references")
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
MANUAL = {"conflict_escalation", "abstain"}
BUDGET = {
    "severity": 50,
    "affected_versions": 50,
    "published": 10,
    "references": 10,
}
TYPE_MAP = {
    "equivalent": "no_action",
    "representation_discrepancy": "no_action",
    "incomplete": "enrich_record",
    "temporal_discrepancy": "wait_for_sync",
    "factual_conflict": "conflict_escalation",
}
ALPHA = 0.05


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", default=DEFAULT_RESULT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def checked(entry: dict, name: str) -> Path:
    path = resolve(entry.get("path", ""))
    if not path.is_file() or digest(path) != entry.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def records(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{number}") from exc


def timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def effective(span: dict) -> tuple[str | None, ...]:
    lower_inc = span.get("version_start_including") or span.get("introduced")
    lower_exc = span.get("version_start_excluding")
    upper_inc = span.get("version_end_including")
    upper_exc = span.get("version_end_excluding") or span.get("fixed")
    point = span.get("version")
    if any((lower_inc, lower_exc, upper_inc, upper_exc)):
        point = None
    return (lower_inc, lower_exc, upper_inc, upper_exc, point)


def effective_set(spans: list[dict]) -> frozenset[tuple[str | None, ...]]:
    return frozenset(effective(item) for item in spans or [])


def version(value: str | None) -> Version | None:
    if not value:
        return None
    try:
        return Version(str(value))
    except InvalidVersion:
        return None


def interval(span: dict):
    point = span.get("version")
    range_keys = (
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
        "introduced",
        "fixed",
    )
    if point and not any(span.get(key) for key in range_keys):
        parsed = version(point)
        return None if parsed is None else (parsed, True, parsed, True)
    raw = (
        span.get("version_start_including") or span.get("introduced"),
        span.get("version_start_excluding"),
        span.get("version_end_including"),
        span.get("version_end_excluding") or span.get("fixed"),
    )
    if not any(raw):
        return None
    parsed = tuple(version(item) for item in raw)
    if any(item is not None and parsed_item is None for item, parsed_item in zip(raw, parsed)):
        return None
    lower_inc, lower_exc, upper_inc, upper_exc = parsed
    return (
        lower_inc or lower_exc,
        lower_inc is not None,
        upper_inc or upper_exc,
        upper_inc is not None,
    )


def overlap(first, second) -> bool:
    first_low, first_low_inc, first_high, first_high_inc = first
    second_low, second_low_inc, second_high, second_high_inc = second
    if first_high is not None and second_low is not None:
        if first_high < second_low:
            return False
        if first_high == second_low and not (first_high_inc and second_low_inc):
            return False
    if second_high is not None and first_low is not None:
        if second_high < first_low:
            return False
        if second_high == first_low and not (second_high_inc and first_low_inc):
            return False
    return True


def range_relation(left: list[dict], right: list[dict]) -> str:
    left_values = [interval(item) for item in left or []]
    right_values = [interval(item) for item in right or []]
    if (
        not left_values
        or not right_values
        or any(item is None for item in left_values + right_values)
    ):
        return "unknown"
    for first in left_values:
        for second in right_values:
            if first is not None and second is not None and overlap(first, second):
                return "overlap"
    return "disjoint"


def pkg_key(value: str) -> str | None:
    cleaned = value.strip().lower().removeprefix("pkg:")
    tail = re.split(r"[:/]", cleaned)[-1]
    tail = re.sub(r"[^a-z0-9]+", "-", tail).strip("-")
    return tail or None


def comparable(view: dict) -> bool | None:
    values = view.get("package_names") or {}
    left = {key for item in values.get("nvd") or [] if (key := pkg_key(item))}
    right = {key for item in values.get("ghsa") or [] if (key := pkg_key(item))}
    if not left or not right:
        return None
    return bool(left & right)


def observed(view: dict, field: str):
    value = view[field]
    if field == "severity":
        return value["nvd"].get("label"), value["ghsa"].get("label")
    if field == "published":
        return value.get("nvd"), value.get("ghsa")
    if field == "references":
        return tuple(value.get("nvd_urls") or []), tuple(value.get("ghsa_urls") or [])
    return (
        tuple(json.dumps(item, sort_keys=True) for item in value.get("nvd") or []),
        tuple(json.dumps(item, sort_keys=True) for item in value.get("ghsa") or []),
    )


def canonical(view: dict, field: str):
    value = view[field]
    if field == "severity":
        return (
            value["nvd"].get("canonical_label"),
            value["ghsa"].get("canonical_label"),
        )
    if field == "published":
        left = timestamp(value.get("nvd"))
        right = timestamp(value.get("ghsa"))
        return (
            left.isoformat() if left else value.get("nvd"),
            right.isoformat() if right else value.get("ghsa"),
        )
    if field == "references":
        return (
            tuple(sorted(set(value.get("nvd_urls") or []))),
            tuple(sorted(set(value.get("ghsa_urls") or []))),
        )
    return effective_set(value.get("nvd") or []), effective_set(value.get("ghsa") or [])


def binary(pair) -> str:
    return "no_action" if pair[0] == pair[1] else "conflict_escalation"


def simple(view: dict, field: str) -> str:
    value = view[field]
    if field == "severity":
        raw_left = value["nvd"].get("label")
        raw_right = value["ghsa"].get("label")
        left = value["nvd"].get("canonical_label")
        right = value["ghsa"].get("canonical_label")
        if raw_left is None and raw_right is None:
            return "no_action"
        if raw_left is None or raw_right is None:
            return "enrich_record"
        if left is None or right is None:
            return "abstain"
        return "no_action" if left == right else "conflict_escalation"
    if field == "published":
        raw_left, raw_right = value.get("nvd"), value.get("ghsa")
        if not raw_left and not raw_right:
            return "no_action"
        if not raw_left or not raw_right:
            return "enrich_record"
        left, right = timestamp(raw_left), timestamp(raw_right)
        if left is None or right is None:
            return "abstain"
        return "no_action" if left.date() == right.date() else "wait_for_sync"
    if field == "references":
        left = set(value.get("nvd_urls") or [])
        right = set(value.get("ghsa_urls") or [])
        return "no_action" if left == right else "enrich_record"
    left = value.get("nvd") or []
    right = value.get("ghsa") or []
    if not left and not right:
        return "no_action"
    if not left or not right:
        return "enrich_record"
    left_effective, right_effective = effective_set(left), effective_set(right)
    if left_effective == right_effective:
        return "no_action"
    if left_effective <= right_effective or right_effective <= left_effective:
        return "enrich_record"
    if comparable(view) is not True:
        return "abstain"
    relation = range_relation(left, right)
    if relation == "disjoint":
        return "conflict_escalation"
    if relation == "overlap":
        return "enrich_record"
    return "abstain"


def vector_version(value: str | None) -> str | None:
    match = re.match(r"^CVSS:([0-9.]+)/", value or "")
    return match.group(1) if match else None


def typed(view: dict, field: str, abstention: bool) -> str:
    status = view["field_discrepancies"][field].get("status")
    if status not in TYPE_MAP:
        raise ValueError(f"invalid status {status!r}")
    if not abstention:
        return TYPE_MAP[status]
    value = view[field]
    if field == "severity" and status == "factual_conflict":
        first = vector_version(value["nvd"].get("vector"))
        second = vector_version(value["ghsa"].get("vector"))
        if first and second and first != second:
            return "abstain"
    if field in {"published", "references"} and status == "factual_conflict":
        return "abstain"
    if field == "affected_versions":
        left, right = value.get("nvd") or [], value.get("ghsa") or []
        if left and right and comparable(view) is not True:
            return "abstain"
        if status == "factual_conflict" and range_relation(left, right) == "unknown":
            return "abstain"
    return TYPE_MAP[status]


def all_actions(view: dict, field: str) -> dict[str, str]:
    return {
        "binary_observed_non_equal": binary(observed(view, field)),
        "binary_canonical_non_equal": binary(canonical(view, field)),
        "field_aware_simple_v1": simple(view, field),
        "type_first_current_v1": typed(view, field, False),
        "type_first_abstention_v1": typed(view, field, True),
        "always_manual": "conflict_escalation",
        "abstain_all": "abstain",
    }


def exact_p(first_only: int, second_only: int) -> float:
    total = first_only + second_only
    if total == 0:
        return 1.0
    lower = min(first_only, second_only)
    numerator = sum(math.comb(total, item) for item in range(lower + 1))
    return min(1.0, 2.0 * numerator / (2**total))


def rejection_rows() -> int:
    return next(rows for rows in range(1, 10_001) if exact_p(0, rows) <= ALPHA)


def power(rows: int, probability: float) -> float:
    return sum(
        math.comb(rows, wins)
        * (probability**wins)
        * ((1 - probability) ** (rows - wins))
        for wins in range(rows + 1)
        if wins > rows - wins and exact_p(rows - wins, wins) <= ALPHA
    )


def power_rows(probability: float) -> dict:
    for rows in range(1, 10_001):
        achieved = power(rows, probability)
        if achieved >= 0.80:
            return {
                "candidate_win_probability_on_effective_discordance": probability,
                "target_power": 0.80,
                "minimum_effective_discordant_rows": rows,
                "achieved_exact_power": achieved,
            }
    raise ValueError("power target unavailable")


def ordered(counter: dict[str, Counter]) -> dict[str, dict[str, int]]:
    return {
        key: {name: values[name] for name in sorted(values)}
        for key, values in sorted(counter.items())
    }


def recompute(rows: list[dict]) -> dict:
    statuses = defaultdict(Counter)
    policy_counts = {policy: defaultdict(Counter) for policy in POLICIES}
    pairwise = defaultdict(Counter)
    main_field = defaultdict(Counter)
    main_status = defaultdict(Counter)
    main_pairs = defaultdict(Counter)
    for row in rows:
        view = row.get("unified_view") or {}
        discrepancies = row.get("field_discrepancies") or {}
        if set(FIELDS) - set(view) or set(FIELDS) - set(discrepancies):
            raise ValueError(f"{row.get('cve_id')}: incomplete field record")
        policy_view = dict(view)
        policy_view["field_discrepancies"] = discrepancies
        for field in FIELDS:
            status = discrepancies[field]["status"]
            statuses[field][status] += 1
            actions = all_actions(policy_view, field)
            for policy, action in actions.items():
                policy_counts[policy][field][action] += 1
            for index, first in enumerate(POLICIES):
                for second in POLICIES[index + 1 :]:
                    if actions[first] != actions[second]:
                        pairwise[f"{first}__vs__{second}"][field] += 1
            first, second = actions[MAIN_FIRST], actions[MAIN_SECOND]
            if first != second:
                main_field[field]["action_disagreement"] += 1
                main_status[f"{field}:{status}"]["action_disagreement"] += 1
                main_pairs[field][f"{first}__to__{second}"] += 1
            if (first == "conflict_escalation") != (
                second == "conflict_escalation"
            ):
                main_field[field]["conflict_queue_disagreement"] += 1
                main_status[f"{field}:{status}"][
                    "conflict_queue_disagreement"
                ] += 1
            if (first in MANUAL) != (second in MANUAL):
                main_field[field]["manual_review_disagreement"] += 1
                main_status[f"{field}:{status}"]["manual_review_disagreement"] += 1

    by_field = {}
    sampling = {}
    for field in FIELDS:
        by_field[field] = {
            "rows": sum(statuses[field].values()),
            "action_disagreement": main_field[field]["action_disagreement"],
            "conflict_queue_disagreement": main_field[field][
                "conflict_queue_disagreement"
            ],
            "manual_review_disagreement": main_field[field][
                "manual_review_disagreement"
            ],
            "action_pairs": {
                name: main_pairs[field][name] for name in sorted(main_pairs[field])
            },
        }
        action_capacity = min(BUDGET[field], by_field[field]["action_disagreement"])
        conflict_capacity = min(
            BUDGET[field], by_field[field]["conflict_queue_disagreement"]
        )
        manual_capacity = min(
            BUDGET[field], by_field[field]["manual_review_disagreement"]
        )
        sampling[field] = {
            "formal_budget": BUDGET[field],
            "available_action_disagreements": by_field[field][
                "action_disagreement"
            ],
            "available_conflict_queue_disagreements": by_field[field][
                "conflict_queue_disagreement"
            ],
            "available_manual_review_disagreements": by_field[field][
                "manual_review_disagreement"
            ],
            "maximum_sampled_action_disagreements": action_capacity,
            "maximum_sampled_conflict_queue_disagreements": conflict_capacity,
            "maximum_sampled_manual_review_disagreements": manual_capacity,
            "minimum_attainable_exact_p_if_all_effective_action_discordance_one_way": (
                exact_p(0, action_capacity) if action_capacity else 1.0
            ),
        }

    simple_conflict = sum(
        policy_counts[MAIN_FIRST][field]["conflict_escalation"] for field in FIELDS
    )
    candidate_conflict = sum(
        policy_counts[MAIN_SECOND][field]["conflict_escalation"] for field in FIELDS
    )
    simple_manual = sum(
        policy_counts[MAIN_FIRST][field][action]
        for field in FIELDS
        for action in MANUAL
    )
    candidate_manual = sum(
        policy_counts[MAIN_SECOND][field][action]
        for field in FIELDS
        for action in MANUAL
    )
    action_total = sum(
        item["maximum_sampled_action_disagreements"] for item in sampling.values()
    )
    conflict_total = sum(
        item["maximum_sampled_conflict_queue_disagreements"]
        for item in sampling.values()
    )
    manual_total = sum(
        item["maximum_sampled_manual_review_disagreements"]
        for item in sampling.values()
    )
    sensitivities = [power_rows(item) for item in (0.70, 0.80, 0.90)]
    required_power_rows = sensitivities[1]["minimum_effective_discordant_rows"]
    minimum = rejection_rows()
    fields = [
        field
        for field in FIELDS
        if sampling[field]["maximum_sampled_action_disagreements"] >= minimum
    ]
    efficacy = [
        field
        for field in ("severity", "affected_versions")
        if sampling[field]["maximum_sampled_manual_review_disagreements"] >= minimum
    ]
    gates = {
        "input_has_no_human_labels": {
            "status": "PASS",
            "basis": "the frozen field view contains deterministic records only",
        },
        "main_policies_are_distinct": {
            "status": (
                "PASS"
                if sum(item["action_disagreement"] for item in by_field.values())
                >= minimum
                else "FAIL"
            ),
            "minimum_required_action_disagreements": minimum,
        },
        "multi_field_action_identifiability": {
            "status": "PASS" if len(fields) >= 2 else "FAIL",
            "fields_meeting_minimum": fields,
            "minimum_required_fields": 2,
        },
        "efficacy_field_manual_review_identifiability": {
            "status": "PASS" if efficacy else "FAIL",
            "fields_meeting_minimum": efficacy,
        },
        "planned_sample_conditional_power_capacity": {
            "status": "PASS" if action_total >= required_power_rows else "FAIL",
            "maximum_effective_action_discordance_capacity": action_total,
            "required_if_candidate_wins_80_percent_of_effective_discordance": (
                required_power_rows
            ),
            "capacity_is_not_realized_power": True,
        },
    }
    decision = (
        "CONDITIONAL_GO_FOR_V3_PACKET_DESIGN"
        if all(item["status"] == "PASS" for item in gates.values())
        else "NO_GO_FOR_POSITIVE_ROUTING_V3_UNDER_CURRENT_POLICIES"
    )
    return {
        "rows": len(rows),
        "field_instances": len(rows) * len(FIELDS),
        "deterministic_status_counts": ordered(statuses),
        "policy_action_counts": {
            policy: ordered(policy_counts[policy]) for policy in POLICIES
        },
        "pairwise_action_disagreement_counts": ordered(pairwise),
        "primary_comparison": {
            "first": MAIN_FIRST,
            "second": MAIN_SECOND,
            "manual_review_actions": sorted(MANUAL),
            "by_field": by_field,
            "by_field_and_deterministic_status": ordered(main_status),
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
        "sampling_capacity": {
            "planned_formal_rows": sum(BUDGET.values()),
            "planned_budget_by_field": BUDGET,
            "by_field": sampling,
            "maximum_sampled_action_disagreements": action_total,
            "maximum_sampled_conflict_queue_disagreements": conflict_total,
            "maximum_sampled_manual_review_disagreements": manual_total,
            "minimum_rows_for_any_two_sided_exact_rejection": minimum,
            "conditional_power_sensitivity": sensitivities,
            "sampling_capacity_is_not_power_or_expected_effect": True,
        },
        "gates": gates,
        "decision": decision,
    }


def main() -> int:
    args = parse_args()
    result_dir = resolve(args.result_dir)
    manifest_path = result_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "t1_routing_precheck_manifest_v1":
        raise ValueError("unexpected manifest artifact type")
    inputs = manifest.get("inputs") or {}
    outputs = manifest.get("outputs") or {}
    field_view_path = checked(inputs.get("field_view") or {}, "field view")
    checked(inputs.get("contract") or {}, "contract")
    checked(inputs.get("analyzer") or {}, "analyzer")
    verifier_path = checked(inputs.get("verifier") or {}, "verifier")
    if verifier_path != Path(__file__).resolve():
        raise ValueError("manifest is not bound to this verifier")
    analysis_path = checked(outputs.get("analysis") or {}, "analysis")
    checked(outputs.get("markdown") or {}, "markdown")
    rows = list(records(field_view_path))
    if len(rows) != 8066:
        raise ValueError(f"expected 8,066 rows, found {len(rows)}")
    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    expected = recompute(rows)
    for key, value in expected.items():
        if observed.get(key) != value:
            raise ValueError(f"analysis section does not recompute: {key}")
    boundary = {
        "label_is_human": False,
        "uses_any_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_workload_reduction_claim": False,
        "eligible_for_submission_readiness_claim": False,
    }
    if manifest.get("claim_boundary") != boundary:
        raise ValueError("manifest claim boundary drift")
    if any(observed.get(key) is not value for key, value in boundary.items()):
        raise ValueError("analysis claim boundary drift")
    if manifest.get("decision") != expected["decision"]:
        raise ValueError("manifest decision drift")
    main_pair = expected["primary_comparison"]
    print(
        "Verified T1 routing precheck: "
        f"rows={expected['rows']} "
        f"action_differences="
        f"{sum(item['action_disagreement'] for item in main_pair['by_field'].values())} "
        f"decision={expected['decision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
