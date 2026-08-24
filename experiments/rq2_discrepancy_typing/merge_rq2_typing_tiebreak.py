#!/usr/bin/env python3
"""Merge a blind third RQ2 review into a non-human expert candidate."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import evaluate_rq2_typing_holdout as evaluation
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = "data/annotations/holdout/rq2_typing_v1/tiebreak_v1"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1/tiebreak_v1"
EXPECTED_ROWS = 1250
EXPECTED_ORIGINAL_STRICT = 1147
EXPECTED_SELECTED = 103


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def qualified_vote(annotation: dict) -> bool:
    return (
        annotation.get("discrepancy_label") != "uncertain"
        and annotation.get("confidence") != "low"
        and annotation.get("needs_human_review") is False
    )


def majority_label(annotations: list[dict]) -> tuple[str | None, dict[str, int]]:
    counts = Counter(
        item["discrepancy_label"] for item in annotations if qualified_vote(item)
    )
    winners = [label for label, count in counts.items() if count >= 2]
    if len(winners) != 1:
        return None, dict(sorted(counts.items()))
    return winners[0], dict(sorted(counts.items()))


def validate_request_log(
    path: Path,
    worklist: dict[str, dict],
    manifest: dict,
    reviewer_sessions: set[str],
) -> dict:
    events = list(dual.iter_jsonl(path))
    if len(events) % 2 or not events:
        raise ValueError("reviewer C request log must contain request/success pairs")
    requested_ids = []
    success_sessions = set()
    batch_sizes = []
    for index in range(0, len(events), 2):
        request, response = events[index : index + 2]
        if request.get("event_type") != "request" or response.get("event_type") != "response_success":
            raise ValueError("reviewer C request log contains a failure or non-paired event")
        items = request.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("reviewer C request event has no items")
        sample_ids = [item.get("sample_id") for item in items]
        if response.get("sample_ids") != sample_ids:
            raise ValueError("reviewer C response sample IDs differ from its request")
        if request.get("pass_id") != manifest["review_protocol"]["reviewer_c_pass_id"]:
            raise ValueError("reviewer C request pass ID drift")
        if request.get("input_sha256") != manifest["outputs"]["blind_worklist_c"]["sha256"]:
            raise ValueError("reviewer C request input hash drift")
        if request.get("binding_manifest_sha256") != dual.sha256(Path(manifest["outputs"]["blind_worklist_c"]["path"]).parents[1] / "manifest.sealed.json"):
            raise ValueError("reviewer C request manifest hash drift")
        requested_ids.extend(sample_ids)
        batch_sizes.append(len(sample_ids))
        success_sessions.add(response.get("execution_session_id"))
    if requested_ids != list(worklist):
        raise ValueError("reviewer C request schedule differs from sealed input order")
    if success_sessions != reviewer_sessions or None in success_sessions:
        raise ValueError("reviewer C request-log sessions differ from accepted outputs")
    return {
        "event_count": len(events),
        "request_count": len(events) // 2,
        "response_success_count": len(events) // 2,
        "response_error_count": 0,
        "batch_sizes": batch_sizes,
        "session_count": len(success_sessions),
    }


def candidate_metrics(rows: list[dict], predictions: dict[str, dict]) -> dict:
    resolved = [row for row in rows if row["candidate_label"] is not None]
    records = [
        {
            "gold": row["candidate_label"],
            "current": predictions[row["sample_id"]]["current"],
        }
        for row in resolved
    ]
    correct = sum(row["gold"] == row["current"] for row in records)
    per_field = {}
    for field in sorted({row["field"] for row in rows}):
        all_field = [row for row in rows if row["field"] == field]
        field_resolved = [row for row in all_field if row["candidate_label"] is not None]
        field_correct = sum(
            predictions[row["sample_id"]]["current"] == row["candidate_label"]
            for row in field_resolved
        )
        per_field[field] = {
            "rows": len(all_field),
            "candidate_rows": len(field_resolved),
            "candidate_coverage": len(field_resolved) / len(all_field),
            "agreement_count": field_correct,
            "agreement_on_candidate_rows": field_correct / len(field_resolved) if field_resolved else 0.0,
            "full_cohort_lower_bound_agreement": field_correct / len(all_field),
        }
    return {
        "rows": len(rows),
        "candidate_rows": len(resolved),
        "candidate_coverage": len(resolved) / len(rows),
        "agreement_count": correct,
        "agreement_on_candidate_rows": correct / len(resolved),
        "macro_f1_on_candidate_rows": evaluation.macro_f1(records, "current"),
        "full_cohort_lower_bound_agreement": correct / len(rows),
        "per_field": per_field,
        "metric_boundary": "agreement with a same-model-family non-human expert candidate; not human-gold accuracy",
    }


def render_markdown(summary: dict, metrics: dict) -> str:
    gate = summary["advancement_gate"]
    return "\n".join(
        [
            "# RQ2 Typing Third-Pass Expert Candidate v1",
            "",
            "> Post-unsealing, same-model-family, non-human disagreement adjudication.",
            "",
            f"- Original strict rows: `{summary['original_strict_rows']}/{summary['rows']}`",
            f"- Tiebreak rows selected: `{summary['selected_tiebreak_rows']}`",
            f"- Tiebreak rows resolved: `{summary['resolved_tiebreak_rows']}`",
            f"- Combined candidate coverage: `{summary['combined_candidate_rows']}/{summary['rows']}` (`{summary['combined_candidate_coverage']:.4f}`)",
            f"- Advancement gate: `{gate['status']}`",
            f"- Current baseline agreement on candidate rows: `{metrics['agreement_count']}/{metrics['candidate_rows']}` (`{metrics['agreement_on_candidate_rows']:.4f}`)",
            "- `label_is_human=false`",
            "",
            "No row is promoted to human gold. Unresolved rows remain abstentions.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite tiebreak result: {output_dir}")
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_typing_tiebreak_manifest":
        raise ValueError("unexpected tiebreak manifest")
    if manifest.get("label_is_human") is not False:
        raise ValueError("tiebreak manifest must remain non-human")
    for name, record in manifest["inputs"].items():
        if not isinstance(record, dict) or "path" not in record or "sha256" not in record:
            raise ValueError(f"input record is not hash-bound: {name}")
        path = Path(record["path"])
        if not path.is_file() or dual.sha256(path) != record["sha256"]:
            raise ValueError(f"input hash mismatch: {name}")
    worklist_record = manifest["outputs"]["blind_worklist_c"]
    worklist_path = Path(worklist_record["path"])
    if dual.sha256(worklist_path) != worklist_record["sha256"]:
        raise ValueError("blind worklist hash mismatch")
    reviewer_c_path = Path(manifest["outputs"]["reviewer_c"])
    if not reviewer_c_path.is_file() or reviewer_c_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("reviewer C output is missing or predates the seal")
    requests_path = Path(manifest["outputs"]["reviewer_c_requests"])
    if not requests_path.is_file() or requests_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("reviewer C request log is missing or predates the seal")

    source_manifest_path = Path(manifest["inputs"]["source_manifest"]["path"])
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    worklist = dual.load_unique(worklist_path)
    review_c = dual.load_unique(reviewer_c_path)
    if set(worklist) != set(review_c) or len(worklist) != EXPECTED_SELECTED:
        raise ValueError("reviewer C row set differs from sealed tiebreak worklist")
    validated_c = {}
    for sample_id, blind in worklist.items():
        validated_c[sample_id] = dual.validate_review(
            review_c[sample_id],
            blind,
            expected_pass_id=manifest["review_protocol"]["reviewer_c_pass_id"],
            expected_input_path=worklist_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=dual.sha256(manifest_path),
            expected_execution=manifest["review_protocol"]["execution_contract"],
        )
    sessions_c = {row["execution_session_id"] for row in review_c.values()}
    sessions_a = {row["execution_session_id"] for row in dual.load_unique(Path(manifest["inputs"]["reviewer_a"]["path"])).values()}
    sessions_b = {row["execution_session_id"] for row in dual.load_unique(Path(manifest["inputs"]["reviewer_b"]["path"])).values()}
    if sessions_c & (sessions_a | sessions_b):
        raise ValueError("reviewer C sessions overlap A/B sessions")
    request_log_summary = validate_request_log(requests_path, worklist, manifest, sessions_c)

    original = dual.load_unique(Path(manifest["inputs"]["dual_consensus"]["path"]))
    predictions = evaluation.load_unique(Path(manifest["inputs"]["predictions"]["path"]))
    source_rows = dual.load_unique(Path(manifest["inputs"]["source_rows"]["path"]))
    if set(original) != set(predictions) or set(original) != set(source_rows) or len(original) != EXPECTED_ROWS:
        raise ValueError("source, prediction, and original consensus row sets differ")
    selected_ids = {sample_id for sample_id, row in original.items() if row["strict_consensus"] is False}
    if selected_ids != set(worklist):
        raise ValueError("tiebreak selector differs from all original non-strict rows")

    merged = []
    resolved_tiebreak = 0
    for sample_id, prior in original.items():
        if prior["strict_consensus"]:
            label = prior["consensus_label"]
            resolution = "original_dual_strict"
            vote_counts = {label: 2}
            reviewer_c = None
        else:
            reviewer_c = validated_c[sample_id]
            label, vote_counts = majority_label([prior["reviewer_a"], prior["reviewer_b"], reviewer_c])
            resolution = "qualified_two_of_three" if label is not None else "unresolved_after_tiebreak"
            resolved_tiebreak += label is not None
        merged.append(
            {
                "sample_id": sample_id,
                "cve_id": prior["cve_id"],
                "field": prior["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "candidate_label": label,
                "candidate_resolved": label is not None,
                "resolution": resolution,
                "qualified_vote_counts": vote_counts,
                "reviewer_a": prior["reviewer_a"],
                "reviewer_b": prior["reviewer_b"],
                "reviewer_c": reviewer_c,
            }
        )

    original_strict = sum(row["resolution"] == "original_dual_strict" for row in merged)
    if original_strict != EXPECTED_ORIGINAL_STRICT:
        raise ValueError(f"original strict row count changed: {original_strict}")
    combined = original_strict + resolved_tiebreak
    selected_resolution = resolved_tiebreak / EXPECTED_SELECTED
    overall_coverage = combined / EXPECTED_ROWS
    thresholds = manifest["thresholds_fixed_before_reviewer_c"]
    checks = {
        "minimum_selected_resolution": selected_resolution >= thresholds["minimum_selected_resolution"],
        "minimum_overall_candidate_coverage": overall_coverage >= thresholds["minimum_overall_candidate_coverage"],
        "non_human_boundary_preserved": True,
    }
    gate_passed = all(checks.values())
    per_field = {}
    for field in sorted({row["field"] for row in merged}):
        subset = [row for row in merged if row["field"] == field]
        selected = [row for row in subset if row["reviewer_c"] is not None]
        resolved = [row for row in selected if row["candidate_resolved"]]
        per_field[field] = {
            "rows": len(subset),
            "selected_tiebreak_rows": len(selected),
            "resolved_tiebreak_rows": len(resolved),
            "combined_candidate_rows": sum(row["candidate_resolved"] for row in subset),
        }
    summary = {
        "schema_version": manifest["schema_version"],
        "artifact_type": "rq2_typing_tiebreak_summary",
        "rows": EXPECTED_ROWS,
        "original_strict_rows": original_strict,
        "selected_tiebreak_rows": EXPECTED_SELECTED,
        "resolved_tiebreak_rows": resolved_tiebreak,
        "selected_resolution_rate": selected_resolution,
        "combined_candidate_rows": combined,
        "combined_candidate_coverage": overall_coverage,
        "remaining_unresolved_rows": EXPECTED_ROWS - combined,
        "candidate_label_counts": dict(sorted(Counter(row["candidate_label"] for row in merged if row["candidate_label"]).items())),
        "per_field": per_field,
        "advancement_gate": {
            "status": "pass_non_human_tiebreak_coverage_development_only" if gate_passed else "no_go_non_human_tiebreak_coverage",
            "passed": gate_passed,
            "checks": checks,
            "failed_checks": [name for name, passed in checks.items() if not passed],
            "thresholds": thresholds,
        },
        "reviewer_c_request_log": request_log_summary,
        "boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "same_model_family": True,
            "post_unsealing": True,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
        },
    }
    metrics = candidate_metrics(merged, predictions)
    output_dir.mkdir(parents=True, exist_ok=False)
    candidate_path = output_dir / "expert_candidate_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    metrics_path = output_dir / "baseline_candidate_agreement.json"
    markdown_path = output_dir / "summary.md"
    result_manifest_path = output_dir / "manifest.json"
    dual.write_jsonl(candidate_path, merged)
    write_json(summary_path, summary)
    write_json(metrics_path, metrics)
    markdown_path.write_text(render_markdown(summary, metrics), encoding="utf-8")
    result_manifest = {
        "schema_version": manifest["schema_version"],
        "artifact_type": "rq2_typing_tiebreak_result_manifest",
        "label_is_human": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": dual.sha256(manifest_path)},
            "reviewer_c": {"path": str(reviewer_c_path), "sha256": dual.sha256(reviewer_c_path)},
            "reviewer_c_requests": {"path": str(requests_path), "sha256": dual.sha256(requests_path)},
            "merge_code": {"path": str(Path(__file__).resolve()), "sha256": dual.sha256(Path(__file__).resolve())},
        },
        "outputs": {
            "candidate": {"path": str(candidate_path), "sha256": dual.sha256(candidate_path)},
            "summary": {"path": str(summary_path), "sha256": dual.sha256(summary_path)},
            "metrics": {"path": str(metrics_path), "sha256": dual.sha256(metrics_path)},
            "markdown": {"path": str(markdown_path), "sha256": dual.sha256(markdown_path)},
        },
        "advancement_gate": summary["advancement_gate"],
        "boundary": summary["boundary"],
    }
    write_json(result_manifest_path, result_manifest)
    print(f"Wrote {candidate_path}")
    print(f"Resolved tiebreak rows: {resolved_tiebreak}/{EXPECTED_SELECTED}")
    print(f"Combined candidate coverage: {combined}/{EXPECTED_ROWS}")
    print(f"Gate: {summary['advancement_gate']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
