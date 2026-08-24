#!/usr/bin/env python3
"""Independently verify the RQ2 staged adjudication frontier artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = "results/holdout/rq2_typing_v1/staged_adjudication_frontier_v1/manifest.json"
USAGE_KEYS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
EXPECTED_LOG_COUNTS = {
    "reviewer_a": (28, 28, 1250, 1250, 0, 0),
    "reviewer_b": (70, 67, 1340, 1250, 3, 90),
    "reviewer_c": (5, 5, 103, 103, 0, 0),
    "reviewer_d": (4, 4, 37, 37, 0, 0),
    "reviewer_e": (4, 4, 37, 37, 0, 0),
}
EXPECTED_BOUNDARY = {
    "post_hoc": True,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "accuracy_claim_allowed": False,
    "production_switch_allowed": False,
    "existing_logs_mutated": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def payload(event: dict) -> tuple[str, ...]:
    if event["event_type"] == "request":
        return tuple(item["sample_id"] for item in event["items"])
    if event["event_type"] == "response_success":
        return tuple(event["sample_ids"])
    raise ValueError(f"unexpected event type: {event['event_type']}")


def independent_log_stats(events: list[dict]) -> dict:
    requests = [event for event in events if event.get("event_type") == "request"]
    successes = [event for event in events if event.get("event_type") == "response_success"]
    if len(requests) + len(successes) != len(events):
        raise ValueError("unsupported request-log event")
    req_payloads = Counter(payload(event) for event in requests)
    success_payloads = Counter(payload(event) for event in successes)
    unpaired = sum(max(0, count - success_payloads[key]) for key, count in req_payloads.items())
    successful_ids = {sample_id for event in successes for sample_id in payload(event)}
    gap_keys = [key for key, count in req_payloads.items() if count > success_payloads[key]]
    usage = {
        key: sum(int((event.get("execution_usage") or {}).get(key, 0) or 0) for event in successes)
        for key in USAGE_KEYS
    }
    request_rows = sum(len(payload(event)) for event in requests)
    success_rows = sum(len(payload(event)) for event in successes)
    return {
        "request_count": len(requests),
        "response_success_count": len(successes),
        "request_row_attempts": request_rows,
        "successful_reviewer_rows": success_rows,
        "unpaired_request_attempts": unpaired,
        "retry_row_overhead": request_rows - success_rows,
        "gap_payload_group_count": len(gap_keys),
        "gap_rows_eventually_successful": all(set(key) <= successful_ids for key in gap_keys),
        "ambiguous_gap_group_count": sum(
            1 for key in gap_keys if req_payloads[key] > 1 and success_payloads[key] > 0
        ),
        "recorded_success_usage": usage,
    }


def validate(manifest: dict) -> None:
    if manifest.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("manifest boundary drift")
    checked(manifest["analyzer"], "analyzer")
    inputs = {name: checked(record, name) for name, record in manifest["inputs"].items()}
    analysis_path = checked(manifest["outputs"]["analysis"], "analysis")
    checked(manifest["outputs"]["summary"], "summary")
    analysis = read_json(analysis_path)
    if analysis.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("analysis boundary drift")

    stats = {}
    for reviewer in EXPECTED_LOG_COUNTS:
        stats[reviewer] = independent_log_stats(read_jsonl(inputs[reviewer]))
        actual_tuple = tuple(
            stats[reviewer][key]
            for key in (
                "request_count",
                "response_success_count",
                "request_row_attempts",
                "successful_reviewer_rows",
                "unpaired_request_attempts",
                "retry_row_overhead",
            )
        )
        if actual_tuple != EXPECTED_LOG_COUNTS[reviewer]:
            raise ValueError(f"{reviewer} request provenance drift: {actual_tuple!r}")
        reported = analysis["request_provenance"][reviewer]
        for key in (
            "request_count",
            "response_success_count",
            "request_row_attempts",
            "successful_reviewer_rows",
            "unpaired_request_attempts",
            "retry_row_overhead",
            "recorded_success_usage",
        ):
            if reported[key] != stats[reviewer][key]:
                raise ValueError(f"{reviewer} reported {key} drift")

    if (
        stats["reviewer_b"]["gap_payload_group_count"] != 3
        or not stats["reviewer_b"]["gap_rows_eventually_successful"]
        or stats["reviewer_b"]["ambiguous_gap_group_count"] != 1
    ):
        raise ValueError("reviewer B gap characterization drift")
    for reviewer in ("reviewer_a", "reviewer_c", "reviewer_d", "reviewer_e"):
        if stats[reviewer]["gap_payload_group_count"]:
            raise ValueError(f"unexpected gap group for {reviewer}")

    dual = read_json(inputs["dual_summary"])
    tiebreak = read_json(inputs["tiebreak_summary"])
    evidence = read_json(inputs["evidence_summary"])
    baseline = read_json(inputs["baseline_metrics"])
    residual = read_json(inputs["residual_analysis"])
    expected_stages = (
        ("dual_review_a_b", 1250, 2500, 2590, 1147, 1147),
        ("reviewer_c_tiebreak", 103, 103, 103, 66, 1213),
        ("reviewer_d_e_frozen_evidence", 37, 74, 74, 6, 1219),
    )
    if (
        dual["strict_consensus_rows"] != 1147
        or tiebreak["resolved_tiebreak_rows"] != 66
        or evidence["secondary_strict_rows"] != 6
        or baseline["candidate_rows"] != 1219
        or residual["summary"]["promoted_candidate_count"] != 0
    ):
        raise ValueError("fixed frontier input drift")
    for reported, expected in zip(analysis["stages"], expected_stages, strict=True):
        actual = (
            reported["stage"],
            reported["selected_rows"],
            reported["successful_reviewer_row_decisions"],
            reported["request_row_attempts_including_retries"],
            reported["added_candidate_rows"],
            reported["cumulative_candidate_rows"],
        )
        if actual != expected:
            raise ValueError(f"stage frontier drift: {actual!r}")

    totals = analysis["totals"]
    expected_usage = {
        key: sum(item["recorded_success_usage"][key] for item in stats.values())
        for key in USAGE_KEYS
    }
    expected_totals = {
        "request_events": 111,
        "response_success_events": 108,
        "unpaired_request_attempts": 3,
        "request_row_attempts_including_retries": 2767,
        "successful_reviewer_row_decisions": 2677,
        "retry_row_overhead": 90,
        "recorded_success_usage": expected_usage,
    }
    if totals != expected_totals:
        raise ValueError("frontier totals drift")

    target = evidence["advancement_gate"]["thresholds"]["minimum_combined_candidate_coverage"]
    frontier = analysis["frontier"]
    unresolved = {
        field: item["rows"] - item["candidate_rows"]
        for field, item in baseline["per_field"].items()
    }
    expected_frontier = {
        "total_rows": 1250,
        "final_candidate_rows": 1219,
        "final_candidate_coverage": 1219 / 1250,
        "fixed_target_coverage": target,
        "fixed_target_candidate_rows": math.ceil(target * 1250),
        "candidate_row_deficit_to_target": math.ceil(target * 1250) - 1219,
        "remaining_unresolved_rows": 31,
        "remaining_unresolved_by_field": unresolved,
        "residual_targeted_rows": 3,
        "residual_mechanism_supported_rows": 1,
        "residual_promoted_rows": 0,
        "real_person_review_rows_remaining": 1250,
    }
    if frontier != expected_frontier:
        raise ValueError("frontier summary drift")
    if analysis["decision"] != manifest["decision"]:
        raise ValueError("decision binding drift")
    if not analysis["decision"]["stop_same_model_escalation"]:
        raise ValueError("sealed stop rule not satisfied")


def main() -> int:
    args = parse_args()
    path = resolve(args.manifest)
    if not path.is_file():
        raise FileNotFoundError(path)
    validate(read_json(path))
    print("Verified staged frontier: 1219/1250; 3 unpaired request attempts; stop no-go")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
