#!/usr/bin/env python3
"""Reconstruct RQ2 request provenance and the staged candidate frontier."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_staged_adjudication_frontier_v1"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1/staged_adjudication_frontier_v1"
CONTRACT = "docs/annotation_guidelines/rq2_staged_adjudication_frontier_contract_v1.md"
DUAL_SUMMARY = "results/holdout/rq2_typing_v1/dual_review_summary.json"
TIEBREAK_SUMMARY = "results/holdout/rq2_typing_v1/tiebreak_v1/summary.json"
EVIDENCE_SUMMARY = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/summary.json"
)
BASELINE_METRICS = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "baseline_candidate_agreement.json"
)
RESIDUAL_ANALYSIS = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "residual_nonaffected_evidence_v1/analysis.json"
)
REQUEST_LOGS = {
    "reviewer_a": "data/annotations/holdout/rq2_typing_v1/reviewer_a.requests.jsonl",
    "reviewer_b": "data/annotations/holdout/rq2_typing_v1/reviewer_b.requests.jsonl",
    "reviewer_c": (
        "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/reviewer_c.requests.jsonl"
    ),
    "reviewer_d": (
        "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
        "reviewer_d.requests.jsonl"
    ),
    "reviewer_e": (
        "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
        "reviewer_e.requests.jsonl"
    ),
}
USAGE_KEYS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
BOUNDARY = {
    "post_hoc": True,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "accuracy_claim_allowed": False,
    "production_switch_allowed": False,
    "existing_logs_mutated": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def portable(path: Path) -> str:
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


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def event_sample_ids(event: dict) -> tuple[str, ...]:
    if event.get("event_type") == "request":
        return tuple(item["sample_id"] for item in event.get("items", []))
    if event.get("event_type") == "response_success":
        return tuple(event.get("sample_ids", []))
    return ()


def audit_events(events: list[dict], reviewer: str) -> dict:
    requests: list[tuple[int, tuple[str, ...]]] = []
    successes: list[tuple[int, tuple[str, ...]]] = []
    successful_ids: set[str] = set()
    usage = {key: 0 for key in USAGE_KEYS}

    for line_number, event in enumerate(events, start=1):
        event_type = event.get("event_type")
        ids = event_sample_ids(event)
        if event_type == "request":
            if not ids:
                raise ValueError(f"{reviewer} request line {line_number} has no items")
            requests.append((line_number, ids))
        elif event_type == "response_success":
            if not ids:
                raise ValueError(f"{reviewer} success line {line_number} has no sample_ids")
            successes.append((line_number, ids))
            successful_ids.update(ids)
            record = event.get("execution_usage") or {}
            for key in USAGE_KEYS:
                usage[key] += int(record.get(key, 0) or 0)
        else:
            raise ValueError(f"unsupported {reviewer} event type: {event_type!r}")

    request_counts = Counter(ids for _, ids in requests)
    success_counts = Counter(ids for _, ids in successes)
    gap_groups = []
    for ids in sorted(request_counts, key=lambda item: (item[0], len(item))):
        excess = request_counts[ids] - success_counts[ids]
        if excess <= 0:
            continue
        request_lines = [line for line, payload in requests if payload == ids]
        success_lines = [line for line, payload in successes if payload == ids]
        gap_groups.append(
            {
                "sample_count": len(ids),
                "first_sample_id": ids[0],
                "last_sample_id": ids[-1],
                "request_count": request_counts[ids],
                "exact_success_count": success_counts[ids],
                "unpaired_request_attempts": excess,
                "candidate_request_lines": request_lines,
                "exact_success_lines": success_lines,
                "attempt_identity_ambiguous": request_counts[ids] > 1 and bool(success_lines),
                "all_rows_eventually_successful": set(ids) <= successful_ids,
                "error_reason_known": False,
            }
        )

    request_row_attempts = sum(len(ids) for _, ids in requests)
    successful_reviewer_rows = sum(len(ids) for _, ids in successes)
    return {
        "reviewer": reviewer,
        "event_count": len(events),
        "request_count": len(requests),
        "response_success_count": len(successes),
        "request_row_attempts": request_row_attempts,
        "successful_reviewer_rows": successful_reviewer_rows,
        "unique_successful_sample_ids": len(successful_ids),
        "retry_row_overhead": request_row_attempts - successful_reviewer_rows,
        "unpaired_request_attempts": sum(
            group["unpaired_request_attempts"] for group in gap_groups
        ),
        "gap_payload_groups": gap_groups,
        "recorded_success_usage": usage,
    }


def safe_divide(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def summed_usage(audits: dict[str, dict], reviewers: tuple[str, ...]) -> dict:
    return {
        key: sum(audits[name]["recorded_success_usage"][key] for name in reviewers)
        for key in USAGE_KEYS
    }


def build_frontier(
    dual: dict,
    tiebreak: dict,
    evidence: dict,
    baseline: dict,
    residual: dict,
    audits: dict[str, dict],
) -> dict:
    if dual.get("rows") != 1250 or dual.get("strict_consensus_rows") != 1147:
        raise ValueError("dual-review summary drift")
    if (
        tiebreak.get("original_strict_rows") != 1147
        or tiebreak.get("resolved_tiebreak_rows") != 66
        or tiebreak.get("combined_candidate_rows") != 1213
    ):
        raise ValueError("tiebreak summary drift")
    if (
        evidence.get("parent_candidate_rows") != 1213
        or evidence.get("secondary_strict_rows") != 6
        or evidence.get("combined_candidate_rows") != 1219
    ):
        raise ValueError("evidence-secondary summary drift")
    if baseline.get("candidate_rows") != 1219 or baseline.get("rows") != 1250:
        raise ValueError("baseline candidate metric drift")
    residual_summary = residual.get("summary", {})
    if residual_summary.get("promoted_candidate_count") != 0:
        raise ValueError("residual promotion boundary drift")

    expected_success_rows = {
        "reviewer_a": 1250,
        "reviewer_b": 1250,
        "reviewer_c": 103,
        "reviewer_d": 37,
        "reviewer_e": 37,
    }
    for reviewer, expected in expected_success_rows.items():
        if audits[reviewer]["successful_reviewer_rows"] != expected:
            raise ValueError(f"{reviewer} successful row count drift")

    stages = []
    stage_specs = (
        (
            "dual_review_a_b",
            1250,
            1147,
            1147,
            ("reviewer_a", "reviewer_b"),
        ),
        (
            "reviewer_c_tiebreak",
            103,
            66,
            1213,
            ("reviewer_c",),
        ),
        (
            "reviewer_d_e_frozen_evidence",
            37,
            6,
            1219,
            ("reviewer_d", "reviewer_e"),
        ),
    )
    for name, selected, added, cumulative, reviewers in stage_specs:
        reviewer_rows = sum(audits[item]["successful_reviewer_rows"] for item in reviewers)
        request_rows = sum(audits[item]["request_row_attempts"] for item in reviewers)
        stages.append(
            {
                "stage": name,
                "selected_rows": selected,
                "successful_reviewer_row_decisions": reviewer_rows,
                "request_row_attempts_including_retries": request_rows,
                "retry_row_overhead": request_rows - reviewer_rows,
                "added_candidate_rows": added,
                "cumulative_candidate_rows": cumulative,
                "cumulative_candidate_coverage": cumulative / 1250,
                "marginal_candidates_per_selected_row": safe_divide(added, selected),
                "marginal_candidates_per_successful_reviewer_row": safe_divide(
                    added, reviewer_rows
                ),
                "recorded_success_usage": summed_usage(audits, reviewers),
            }
        )

    target = float(evidence["advancement_gate"]["thresholds"]["minimum_combined_candidate_coverage"])
    required_rows = math.ceil(target * 1250)
    unresolved_fields = {
        field: metrics["rows"] - metrics["candidate_rows"]
        for field, metrics in baseline["per_field"].items()
    }
    stop = (
        not tiebreak["advancement_gate"]["passed"]
        and not evidence["advancement_gate"]["passed"]
        and evidence["combined_candidate_coverage"] < target
        and residual_summary["promoted_candidate_count"] == 0
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_staged_adjudication_frontier",
        "boundary": dict(BOUNDARY),
        "request_provenance": audits,
        "stages": stages,
        "totals": {
            "request_events": sum(item["request_count"] for item in audits.values()),
            "response_success_events": sum(
                item["response_success_count"] for item in audits.values()
            ),
            "unpaired_request_attempts": sum(
                item["unpaired_request_attempts"] for item in audits.values()
            ),
            "request_row_attempts_including_retries": sum(
                item["request_row_attempts"] for item in audits.values()
            ),
            "successful_reviewer_row_decisions": sum(
                item["successful_reviewer_rows"] for item in audits.values()
            ),
            "retry_row_overhead": sum(
                item["retry_row_overhead"] for item in audits.values()
            ),
            "recorded_success_usage": summed_usage(audits, tuple(audits)),
        },
        "frontier": {
            "total_rows": 1250,
            "final_candidate_rows": 1219,
            "final_candidate_coverage": 1219 / 1250,
            "fixed_target_coverage": target,
            "fixed_target_candidate_rows": required_rows,
            "candidate_row_deficit_to_target": required_rows - 1219,
            "remaining_unresolved_rows": 31,
            "remaining_unresolved_by_field": unresolved_fields,
            "residual_targeted_rows": residual_summary["row_count"],
            "residual_mechanism_supported_rows": residual_summary["mechanism_supported_rows"],
            "residual_promoted_rows": residual_summary["promoted_candidate_count"],
            "real_person_review_rows_remaining": 1250,
        },
        "decision": {
            "stop_same_model_escalation": stop,
            "status": "stop_same_model_escalation_no_go" if stop else "continue_audit",
            "next_value_bearing_paths": [
                "real_person_review_with_independent_reviewer_and_author_signoff",
                "later_independently_collected_confirmation_snapshot",
            ],
            "future_yield_prediction_allowed": False,
        },
    }


def summary_markdown(analysis: dict) -> str:
    frontier = analysis["frontier"]
    totals = analysis["totals"]
    lines = [
        "# RQ2 Staged Adjudication Frontier v1",
        "",
        "> Post-hoc non-human operational audit; not human-gold accuracy.",
        "",
        f"- Final candidate coverage: `{frontier['final_candidate_rows']}/{frontier['total_rows']}` "
        f"(`{frontier['final_candidate_coverage']:.4f}`)",
        f"- Fixed 0.982 target: `{frontier['fixed_target_candidate_rows']}` rows; "
        f"deficit `{frontier['candidate_row_deficit_to_target']}`",
        f"- Request events / successful responses / unpaired attempts: "
        f"`{totals['request_events']}/{totals['response_success_events']}/"
        f"{totals['unpaired_request_attempts']}`",
        f"- Request row-attempts / successful reviewer-row decisions / retry overhead: "
        f"`{totals['request_row_attempts_including_retries']}/"
        f"{totals['successful_reviewer_row_decisions']}/{totals['retry_row_overhead']}`",
        "",
        "| Stage | Selected | Added | Cumulative | Added/selected | Added/reviewer-row |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for stage in analysis["stages"]:
        lines.append(
            f"| {stage['stage']} | {stage['selected_rows']} | "
            f"{stage['added_candidate_rows']} | {stage['cumulative_candidate_rows']} | "
            f"{stage['marginal_candidates_per_selected_row']:.4f} | "
            f"{stage['marginal_candidates_per_successful_reviewer_row']:.4f} |"
        )
    lines.extend(
        [
            "",
            "Reviewer B has three excess request attempts covering 90 retry row-items. "
            "All affected rows eventually have successful outcomes, but the old log does "
            "not identify an error reason and one duplicate-payload attempt is ambiguous.",
            "",
            "The sealed stop rule is satisfied: further same-model escalation on this "
            "revealed cohort is a no-go. This does not reduce the 1,250-row real-person "
            "review requirement or predict future-review yield.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    input_paths = {
        "contract": resolve(CONTRACT),
        "dual_summary": resolve(DUAL_SUMMARY),
        "tiebreak_summary": resolve(TIEBREAK_SUMMARY),
        "evidence_summary": resolve(EVIDENCE_SUMMARY),
        "baseline_metrics": resolve(BASELINE_METRICS),
        "residual_analysis": resolve(RESIDUAL_ANALYSIS),
        **{name: resolve(path) for name, path in REQUEST_LOGS.items()},
    }
    for name, path in input_paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")

    audits = {
        name: audit_events(load_jsonl(resolve(path)), name)
        for name, path in REQUEST_LOGS.items()
    }
    analysis = build_frontier(
        load_json(input_paths["dual_summary"]),
        load_json(input_paths["tiebreak_summary"]),
        load_json(input_paths["evidence_summary"]),
        load_json(input_paths["baseline_metrics"]),
        load_json(input_paths["residual_analysis"]),
        audits,
    )

    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(canonical_json(analysis), encoding="utf-8")
    summary_path.write_text(summary_markdown(analysis), encoding="utf-8")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_staged_adjudication_frontier_manifest",
        "boundary": dict(BOUNDARY),
        "inputs": {
            name: {"path": portable(path), "sha256": sha256(path)}
            for name, path in input_paths.items()
        },
        "analyzer": {
            "path": portable(Path(__file__)),
            "sha256": sha256(Path(__file__)),
        },
        "outputs": {
            "analysis": {"path": portable(analysis_path), "sha256": sha256(analysis_path)},
            "summary": {"path": portable(summary_path), "sha256": sha256(summary_path)},
        },
        "decision": analysis["decision"],
    }
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    print(
        "Wrote staged frontier: "
        f"{analysis['frontier']['final_candidate_rows']}/1250; "
        f"unpaired requests={analysis['totals']['unpaired_request_attempts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
