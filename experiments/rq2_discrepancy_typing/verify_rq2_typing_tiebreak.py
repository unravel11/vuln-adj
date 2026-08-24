#!/usr/bin/env python3
"""Independently recompute the RQ2 third-pass expert candidate and no-go gate."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import evaluate_rq2_typing_holdout as evaluation
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = "results/holdout/rq2_typing_v1/tiebreak_v1/manifest.json"
EXPECTED_ROWS = 1250
EXPECTED_ORIGINAL_STRICT = 1147
EXPECTED_SELECTED = 103
EXPECTED_RESOLVED = 66
EXPECTED_COMBINED = 1213


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verified_record(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or dual.sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def qualified(annotation: dict) -> bool:
    return (
        annotation.get("discrepancy_label") != "uncertain"
        and annotation.get("confidence") != "low"
        and annotation.get("needs_human_review") is False
    )


def recompute_vote(annotations: list[dict]) -> tuple[str | None, dict[str, int]]:
    counts = Counter(item["discrepancy_label"] for item in annotations if qualified(item))
    winners = [label for label, count in counts.items() if count >= 2]
    return (winners[0] if len(winners) == 1 else None), dict(sorted(counts.items()))


def verify_request_log(
    path: Path,
    worklist: dict[str, dict],
    sealed: dict,
    accepted_sessions: set[str],
) -> dict:
    events = list(dual.iter_jsonl(path))
    if not events or len(events) % 2:
        raise ValueError("request log is not paired")
    requested = []
    sessions = set()
    sizes = []
    for index in range(0, len(events), 2):
        request, success = events[index : index + 2]
        if request.get("event_type") != "request" or success.get("event_type") != "response_success":
            raise ValueError("request log contains a non-success event")
        ids = [item.get("sample_id") for item in request.get("items") or []]
        if not ids or success.get("sample_ids") != ids:
            raise ValueError("request/response sample IDs differ")
        if request.get("pass_id") != sealed["review_protocol"]["reviewer_c_pass_id"]:
            raise ValueError("request pass ID drift")
        if request.get("input_sha256") != sealed["outputs"]["blind_worklist_c"]["sha256"]:
            raise ValueError("request input hash drift")
        requested.extend(ids)
        sizes.append(len(ids))
        sessions.add(success.get("execution_session_id"))
    if requested != list(worklist):
        raise ValueError("request schedule differs from sealed worklist")
    if sessions != accepted_sessions or None in sessions:
        raise ValueError("request sessions differ from accepted reviewer output")
    return {
        "event_count": len(events),
        "request_count": len(events) // 2,
        "response_success_count": len(events) // 2,
        "response_error_count": 0,
        "batch_sizes": sizes,
        "session_count": len(sessions),
    }


def recompute_metrics(rows: list[dict], predictions: dict[str, dict]) -> dict:
    resolved = [row for row in rows if row["candidate_label"] is not None]
    metric_rows = [
        {"gold": row["candidate_label"], "current": predictions[row["sample_id"]]["current"]}
        for row in resolved
    ]
    correct = sum(row["gold"] == row["current"] for row in metric_rows)
    per_field = {}
    for field in sorted({row["field"] for row in rows}):
        field_rows = [row for row in rows if row["field"] == field]
        field_resolved = [row for row in field_rows if row["candidate_label"] is not None]
        field_correct = sum(
            predictions[row["sample_id"]]["current"] == row["candidate_label"]
            for row in field_resolved
        )
        per_field[field] = {
            "rows": len(field_rows),
            "candidate_rows": len(field_resolved),
            "candidate_coverage": len(field_resolved) / len(field_rows),
            "agreement_count": field_correct,
            "agreement_on_candidate_rows": field_correct / len(field_resolved) if field_resolved else 0.0,
            "full_cohort_lower_bound_agreement": field_correct / len(field_rows),
        }
    return {
        "rows": len(rows),
        "candidate_rows": len(resolved),
        "candidate_coverage": len(resolved) / len(rows),
        "agreement_count": correct,
        "agreement_on_candidate_rows": correct / len(resolved),
        "macro_f1_on_candidate_rows": evaluation.macro_f1(metric_rows, "current"),
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


def validate(result_manifest: dict) -> dict:
    if result_manifest.get("artifact_type") != "rq2_typing_tiebreak_result_manifest":
        raise ValueError("unexpected result manifest")
    if result_manifest.get("label_is_human") is not False:
        raise ValueError("result manifest must remain non-human")
    input_paths = {
        name: verified_record(record, f"input:{name}")
        for name, record in result_manifest["inputs"].items()
    }
    output_paths = {
        name: verified_record(record, f"output:{name}")
        for name, record in result_manifest["outputs"].items()
    }
    sealed_path = input_paths["sealed_manifest"]
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_typing_tiebreak_manifest":
        raise ValueError("unexpected sealed manifest")
    for name, record in sealed["inputs"].items():
        verified_record(record, f"sealed_input:{name}")
    worklist_path = verified_record(sealed["outputs"]["blind_worklist_c"], "sealed_worklist")
    reviewer_c_path = input_paths["reviewer_c"]
    requests_path = input_paths["reviewer_c_requests"]
    if Path(sealed["outputs"]["reviewer_c"]) != reviewer_c_path:
        raise ValueError("reviewer C path differs from the seal")
    if Path(sealed["outputs"]["reviewer_c_requests"]) != requests_path:
        raise ValueError("reviewer C request path differs from the seal")

    worklist = dual.load_unique(worklist_path)
    reviewer_c = dual.load_unique(reviewer_c_path)
    if set(worklist) != set(reviewer_c) or len(worklist) != EXPECTED_SELECTED:
        raise ValueError("reviewer C rows differ from the worklist")
    prompt_path = Path(sealed["inputs"]["prompt"]["path"])
    validated_c = {
        sample_id: dual.validate_review(
            reviewer_c[sample_id],
            worklist[sample_id],
            expected_pass_id=sealed["review_protocol"]["reviewer_c_pass_id"],
            expected_input_path=worklist_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=sealed_path,
            expected_manifest_sha256=dual.sha256(sealed_path),
            expected_execution=sealed["review_protocol"]["execution_contract"],
        )
        for sample_id in worklist
    }
    sessions_c = {row["execution_session_id"] for row in reviewer_c.values()}
    reviewers_a = dual.load_unique(Path(sealed["inputs"]["reviewer_a"]["path"]))
    reviewers_b = dual.load_unique(Path(sealed["inputs"]["reviewer_b"]["path"]))
    sessions_a = {row["execution_session_id"] for row in reviewers_a.values()}
    sessions_b = {row["execution_session_id"] for row in reviewers_b.values()}
    if sessions_c & (sessions_a | sessions_b):
        raise ValueError("reviewer C sessions overlap A/B")
    request_summary = verify_request_log(requests_path, worklist, sealed, sessions_c)

    original = dual.load_unique(Path(sealed["inputs"]["dual_consensus"]["path"]))
    predictions = evaluation.load_unique(Path(sealed["inputs"]["predictions"]["path"]))
    if len(original) != EXPECTED_ROWS or set(original) != set(predictions):
        raise ValueError("original consensus or prediction row set changed")
    if {sample_id for sample_id, row in original.items() if not row["strict_consensus"]} != set(worklist):
        raise ValueError("worklist is not exactly the non-strict original rows")

    recomputed = []
    resolved_tiebreak = 0
    for sample_id, prior in original.items():
        if prior["strict_consensus"]:
            label = prior["consensus_label"]
            resolution = "original_dual_strict"
            counts = {label: 2}
            third = None
        else:
            third = validated_c[sample_id]
            label, counts = recompute_vote([prior["reviewer_a"], prior["reviewer_b"], third])
            resolution = "qualified_two_of_three" if label else "unresolved_after_tiebreak"
            resolved_tiebreak += label is not None
        recomputed.append(
            {
                "sample_id": sample_id,
                "cve_id": prior["cve_id"],
                "field": prior["field"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "candidate_label": label,
                "candidate_resolved": label is not None,
                "resolution": resolution,
                "qualified_vote_counts": counts,
                "reviewer_a": prior["reviewer_a"],
                "reviewer_b": prior["reviewer_b"],
                "reviewer_c": third,
            }
        )
    observed_candidate = list(dual.iter_jsonl(output_paths["candidate"]))
    if observed_candidate != recomputed:
        raise ValueError("candidate rows differ from independent vote recomputation")
    original_strict = sum(row["resolution"] == "original_dual_strict" for row in recomputed)
    combined = sum(row["candidate_resolved"] for row in recomputed)
    thresholds = sealed["thresholds_fixed_before_reviewer_c"]
    checks = {
        "minimum_selected_resolution": resolved_tiebreak / EXPECTED_SELECTED >= thresholds["minimum_selected_resolution"],
        "minimum_overall_candidate_coverage": combined / EXPECTED_ROWS >= thresholds["minimum_overall_candidate_coverage"],
        "non_human_boundary_preserved": True,
    }
    per_field = {}
    for field in sorted({row["field"] for row in recomputed}):
        subset = [row for row in recomputed if row["field"] == field]
        selected = [row for row in subset if row["reviewer_c"] is not None]
        per_field[field] = {
            "rows": len(subset),
            "selected_tiebreak_rows": len(selected),
            "resolved_tiebreak_rows": sum(row["candidate_resolved"] for row in selected),
            "combined_candidate_rows": sum(row["candidate_resolved"] for row in subset),
        }
    expected_summary = {
        "schema_version": sealed["schema_version"],
        "artifact_type": "rq2_typing_tiebreak_summary",
        "rows": EXPECTED_ROWS,
        "original_strict_rows": original_strict,
        "selected_tiebreak_rows": EXPECTED_SELECTED,
        "resolved_tiebreak_rows": resolved_tiebreak,
        "selected_resolution_rate": resolved_tiebreak / EXPECTED_SELECTED,
        "combined_candidate_rows": combined,
        "combined_candidate_coverage": combined / EXPECTED_ROWS,
        "remaining_unresolved_rows": EXPECTED_ROWS - combined,
        "candidate_label_counts": dict(sorted(Counter(row["candidate_label"] for row in recomputed if row["candidate_label"]).items())),
        "per_field": per_field,
        "advancement_gate": {
            "status": "pass_non_human_tiebreak_coverage_development_only" if all(checks.values()) else "no_go_non_human_tiebreak_coverage",
            "passed": all(checks.values()),
            "checks": checks,
            "failed_checks": [name for name, passed in checks.items() if not passed],
            "thresholds": thresholds,
        },
        "reviewer_c_request_log": request_summary,
        "boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "same_model_family": True,
            "post_unsealing": True,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
        },
    }
    observed_summary = json.loads(output_paths["summary"].read_text(encoding="utf-8"))
    if observed_summary != expected_summary:
        raise ValueError("summary differs from independent recomputation")
    metrics = recompute_metrics(recomputed, predictions)
    if json.loads(output_paths["metrics"].read_text(encoding="utf-8")) != metrics:
        raise ValueError("candidate-agreement metrics differ from independent recomputation")
    if output_paths["markdown"].read_text(encoding="utf-8") != render_markdown(expected_summary, metrics):
        raise ValueError("Markdown differs from independent rendering")
    if result_manifest.get("advancement_gate") != expected_summary["advancement_gate"]:
        raise ValueError("result manifest gate mismatch")
    if result_manifest.get("boundary") != expected_summary["boundary"]:
        raise ValueError("result manifest boundary mismatch")
    if (original_strict, resolved_tiebreak, combined) != (
        EXPECTED_ORIGINAL_STRICT,
        EXPECTED_RESOLVED,
        EXPECTED_COMBINED,
    ):
        raise ValueError("fixed snapshot counts changed")
    if expected_summary["advancement_gate"]["status"] != "no_go_non_human_tiebreak_coverage":
        raise ValueError("fixed snapshot gate must remain no-go")
    return {"summary": expected_summary, "metrics": metrics}


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    result = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    summary = result["summary"]
    print(
        "Verified RQ2 tiebreak: "
        f"{summary['resolved_tiebreak_rows']}/{summary['selected_tiebreak_rows']} resolved; "
        f"combined={summary['combined_candidate_rows']}/{summary['rows']}; "
        "gate=no-go; label_is_human=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
