#!/usr/bin/env python3
"""Independently verify the 37-row RQ2 evidence-secondary result."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_typing_unresolved_evidence_secondary as builder
import evaluate_rq2_typing_holdout as evaluation
import merge_rq2_typing_holdout_reviews as dual


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "manifest.json"
)
EXPECTED_PARENT = 1213
EXPECTED_TOTAL = 1250


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verified(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or dual.sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def successful_urls(blind: dict) -> set[str]:
    return {
        record["url"]
        for record in (blind.get("evidence_context") or {}).get("records", [])
        if record.get("fetch_status") == "ok"
        and str(record.get("text_snippet") or "").strip()
    }


def citation_ok(annotation: dict, blind: dict, required: bool) -> bool:
    return not required or bool(set(annotation["evidence_urls"]) & successful_urls(blind))


def strict_pair(left: dict, right: dict) -> bool:
    return (
        left["discrepancy_label"] == right["discrepancy_label"]
        and left["discrepancy_label"] != "uncertain"
        and left["confidence"] != "low"
        and right["confidence"] != "low"
        and left["needs_human_review"] is False
        and right["needs_human_review"] is False
    )


def validate_log(
    path: Path,
    worklist_ids: list[str],
    input_hash: str,
    manifest_hash: str,
    pass_id: str,
    sessions: set[str],
) -> dict:
    events = list(dual.iter_jsonl(path))
    if not events or len(events) % 2:
        raise ValueError(f"{path}: malformed request log")
    observed_ids = []
    observed_sessions = set()
    batch_sizes = []
    for index in range(0, len(events), 2):
        request, response = events[index : index + 2]
        if request.get("event_type") != "request" or response.get("event_type") != "response_success":
            raise ValueError(f"{path}: non-success request pair")
        ids = [item.get("sample_id") for item in request.get("items") or []]
        if not ids or response.get("sample_ids") != ids:
            raise ValueError(f"{path}: request/response sample mismatch")
        if request.get("pass_id") != pass_id:
            raise ValueError(f"{path}: pass ID mismatch")
        if request.get("input_sha256") != input_hash:
            raise ValueError(f"{path}: input hash mismatch")
        if request.get("binding_manifest_sha256") != manifest_hash:
            raise ValueError(f"{path}: manifest hash mismatch")
        observed_ids.extend(ids)
        batch_sizes.append(len(ids))
        observed_sessions.add(response.get("execution_session_id"))
    if observed_ids != worklist_ids or observed_sessions != sessions:
        raise ValueError(f"{path}: schedule or session mismatch")
    return {
        "event_count": len(events),
        "request_count": len(events) // 2,
        "response_success_count": len(events) // 2,
        "response_error_count": 0,
        "batch_sizes": batch_sizes,
        "session_count": len(observed_sessions),
    }


def gate(evidence_rate: float, strict_count: int, combined_count: int) -> dict:
    checks = {
        "minimum_evidence_availability": evidence_rate >= builder.MIN_EVIDENCE_AVAILABILITY,
        "minimum_secondary_strict_resolution": (
            strict_count / builder.EXPECTED_ROWS >= builder.MIN_SECONDARY_STRICT_RESOLUTION
        ),
        "minimum_combined_candidate_coverage": (
            combined_count / EXPECTED_TOTAL >= builder.MIN_COMBINED_CANDIDATE_COVERAGE
        ),
        "non_human_boundary_preserved": True,
    }
    passed = all(checks.values())
    return {
        "status": (
            "pass_non_human_evidence_secondary_development_only"
            if passed
            else "no_go_non_human_evidence_secondary"
        ),
        "passed": passed,
        "checks": checks,
        "failed_checks": [name for name, value in checks.items() if not value],
        "thresholds": {
            "minimum_evidence_availability": builder.MIN_EVIDENCE_AVAILABILITY,
            "minimum_secondary_strict_resolution": builder.MIN_SECONDARY_STRICT_RESOLUTION,
            "minimum_combined_candidate_coverage": builder.MIN_COMBINED_CANDIDATE_COVERAGE,
        },
        "scope": "post_unsealing_same_model_non_human_development_only",
        "human_gold_claim_allowed": False,
        "accuracy_claim_allowed": False,
        "production_switch_allowed": False,
    }


def metrics(rows: list[dict], predictions: dict[str, dict]) -> dict:
    resolved = [row for row in rows if row["candidate_label"] is not None]
    records = [
        {"gold": row["candidate_label"], "current": predictions[row["sample_id"]]["current"]}
        for row in resolved
    ]
    correct = sum(row["gold"] == row["current"] for row in records)
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
        "macro_f1_on_candidate_rows": evaluation.macro_f1(records, "current"),
        "full_cohort_lower_bound_agreement": correct / len(rows),
        "per_field": per_field,
        "metric_boundary": (
            "agreement with a post-selected same-model-family non-human candidate; "
            "not human-gold accuracy"
        ),
    }


def validate(result_manifest: dict) -> dict:
    if result_manifest.get("artifact_type") != "rq2_typing_unresolved_evidence_secondary_result_manifest":
        raise ValueError("unexpected result manifest")
    if result_manifest.get("label_is_human") is not False:
        raise ValueError("result must remain non-human")
    inputs = {
        name: verified(record, f"result.input.{name}")
        for name, record in result_manifest["inputs"].items()
    }
    outputs = {
        name: verified(record, f"result.output.{name}")
        for name, record in result_manifest["outputs"].items()
    }
    sealed_path = inputs["sealed_manifest"]
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_typing_unresolved_evidence_secondary_manifest":
        raise ValueError("unexpected sealed manifest")
    if sealed.get("selected_rows") != builder.EXPECTED_ROWS:
        raise ValueError("sealed selected-row count drift")
    for name, record in sealed["inputs"].items():
        verified(record, f"sealed.input.{name}")
    for record in sealed["evidence_cache"]:
        verified(record, f"sealed.cache.{record['fetch_url']}")
    for name in ("blind_worklist_d", "blind_worklist_e", "author_triage"):
        verified(sealed["outputs"][name], f"sealed.output.{name}")

    blind_d_path = Path(sealed["outputs"]["blind_worklist_d"]["path"])
    blind_e_path = Path(sealed["outputs"]["blind_worklist_e"]["path"])
    blind_d = dual.load_unique(blind_d_path)
    blind_e = dual.load_unique(blind_e_path)
    review_d = dual.load_unique(inputs["reviewer_d"])
    review_e = dual.load_unique(inputs["reviewer_e"])
    ids = set(blind_d)
    if any(set(rows) != ids for rows in (blind_e, review_d, review_e)) or len(ids) != builder.EXPECTED_ROWS:
        raise ValueError("D/E row-set drift")
    if any(blind_d[sample_id] != blind_e[sample_id] for sample_id in ids):
        raise ValueError("D/E blind-content drift")

    execution = sealed["review_protocol"]["execution_contract"]
    prompt_path = Path(sealed["inputs"]["prompt"]["path"])
    sealed_hash = dual.sha256(sealed_path)
    annotations_d = {}
    annotations_e = {}
    for sample_id in blind_d:
        annotations_d[sample_id] = dual.validate_review(
            review_d[sample_id], blind_d[sample_id],
            expected_pass_id=sealed["review_protocol"]["reviewer_d_pass_id"],
            expected_input_path=blind_d_path, expected_prompt_path=prompt_path,
            expected_manifest_path=sealed_path, expected_manifest_sha256=sealed_hash,
            expected_execution=execution,
        )
        annotations_e[sample_id] = dual.validate_review(
            review_e[sample_id], blind_e[sample_id],
            expected_pass_id=sealed["review_protocol"]["reviewer_e_pass_id"],
            expected_input_path=blind_e_path, expected_prompt_path=prompt_path,
            expected_manifest_path=sealed_path, expected_manifest_sha256=sealed_hash,
            expected_execution=execution,
        )
    sessions_d = {row["execution_session_id"] for row in review_d.values()}
    sessions_e = {row["execution_session_id"] for row in review_e.values()}
    if sessions_d & sessions_e:
        raise ValueError("D/E session overlap")
    logs = {
        "reviewer_d": validate_log(
            inputs["reviewer_d_requests"], list(blind_d), dual.sha256(blind_d_path),
            sealed_hash, sealed["review_protocol"]["reviewer_d_pass_id"], sessions_d,
        ),
        "reviewer_e": validate_log(
            inputs["reviewer_e_requests"], list(blind_e), dual.sha256(blind_e_path),
            sealed_hash, sealed["review_protocol"]["reviewer_e_pass_id"], sessions_e,
        ),
    }

    triage = dual.load_unique(Path(sealed["outputs"]["author_triage"]["path"]))
    citation_fields = set(sealed["review_protocol"]["citation_required_fields"])
    expected_secondary = {}
    strict_count = 0
    strict_by_field = Counter()
    strict_by_group = Counter()
    for sample_id in blind_d:
        left, right = annotations_d[sample_id], annotations_e[sample_id]
        required = blind_d[sample_id]["field"] in citation_fields
        left_citation = citation_ok(left, blind_d[sample_id], required)
        right_citation = citation_ok(right, blind_d[sample_id], required)
        base = strict_pair(left, right)
        strict = base and left_citation and right_citation
        strict_count += int(strict)
        strict_by_field[blind_d[sample_id]["field"]] += int(strict)
        group = triage[sample_id]["selection_group"]
        strict_by_group[group] += int(strict)
        expected_secondary[sample_id] = {
            "strict": strict,
            "label": left["discrepancy_label"] if strict else None,
            "base": base,
            "left_citation": left_citation,
            "right_citation": right_citation,
            "group": group,
        }

    generated_secondary = dual.load_unique(outputs["secondary_consensus"])
    if set(generated_secondary) != ids:
        raise ValueError("generated secondary row set drift")
    for sample_id, expected in expected_secondary.items():
        row = generated_secondary[sample_id]
        observed = (
            row["secondary_strict_consensus"], row["secondary_consensus_label"],
            row["base_strict_consensus"], row["reviewer_d_citation_passed"],
            row["reviewer_e_citation_passed"], row["prior_vote_group"],
        )
        target = (
            expected["strict"], expected["label"], expected["base"],
            expected["left_citation"], expected["right_citation"], expected["group"],
        )
        if observed != target or row.get("label_is_human") is not False:
            raise ValueError(f"secondary merge drift for {sample_id}")

    parent_rows = list(dual.iter_jsonl(Path(sealed["inputs"]["parent_candidate"]["path"])))
    if len(parent_rows) != EXPECTED_TOTAL or sum(row["candidate_resolved"] for row in parent_rows) != EXPECTED_PARENT:
        raise ValueError("parent candidate drift")
    expected_labels = {}
    for row in parent_rows:
        secondary = expected_secondary.get(row["sample_id"])
        label = row["candidate_label"] if row["candidate_resolved"] else None
        if label is None and secondary and secondary["strict"]:
            label = secondary["label"]
        expected_labels[row["sample_id"]] = label
    combined_count = sum(label is not None for label in expected_labels.values())
    generated_combined = dual.load_unique(outputs["combined_candidate"])
    if set(generated_combined) != set(expected_labels):
        raise ValueError("combined candidate row-set drift")
    for sample_id, label in expected_labels.items():
        row = generated_combined[sample_id]
        if row["candidate_label"] != label or row["candidate_resolved"] != (label is not None):
            raise ValueError(f"combined candidate drift for {sample_id}")
        if row.get("label_is_human") is not False:
            raise ValueError(f"human boundary drift for {sample_id}")

    evidence_rate = sealed["evidence"]["successful_nonempty_evidence_rate"]
    expected_gate = gate(evidence_rate, strict_count, combined_count)
    summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
    if summary["secondary_strict_rows"] != strict_count:
        raise ValueError("summary strict count drift")
    if summary["combined_candidate_rows"] != combined_count:
        raise ValueError("summary combined count drift")
    if summary["reviewer_request_logs"] != logs or summary["advancement_gate"] != expected_gate:
        raise ValueError("summary request-log or gate drift")
    if summary.get("label_is_human") is not False:
        raise ValueError("summary human boundary drift")

    predictions = dual.load_unique(Path(sealed["inputs"]["predictions"]["path"]))
    expected_metrics = metrics(list(generated_combined.values()), predictions)
    observed_metrics = json.loads(outputs["metrics"].read_text(encoding="utf-8"))
    if observed_metrics != expected_metrics:
        raise ValueError("baseline-candidate agreement metric drift")
    if result_manifest["advancement_gate"] != expected_gate:
        raise ValueError("result-manifest gate drift")
    return {
        "selected_rows": builder.EXPECTED_ROWS,
        "secondary_strict_rows": strict_count,
        "combined_candidate_rows": combined_count,
        "gate": expected_gate["status"],
        "label_is_human": False,
    }


def main() -> int:
    args = parse_args()
    manifest = json.loads(resolve(args.manifest).read_text(encoding="utf-8"))
    result = validate(manifest)
    print(
        f"Verified RQ2 evidence secondary: {result['secondary_strict_rows']}/"
        f"{result['selected_rows']} strict; combined={result['combined_candidate_rows']}/"
        f"{EXPECTED_TOTAL}; gate={result['gate']}; label_is_human=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
