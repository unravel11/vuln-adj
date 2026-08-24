#!/usr/bin/env python3
"""Validate and wrap interactive Codex adjudication decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from run_expert_candidate_annotation import ANNOTATION_SCHEMA
from run_expert_candidate_annotation import LABELS
from run_expert_candidate_annotation import SOURCES
from run_expert_candidate_annotation import VERSION_REASONING
from run_expert_candidate_annotation import validate_batch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "ai_gold_adjudication_v1"
CONFIDENCE = {"high", "medium", "low"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--pass-id", required=True)
    parser.add_argument(
        "--overrides-mode",
        action="store_true",
        help="Treat decisions as sample_id/updates/review_note rows merged over prior candidates.",
    )
    parser.add_argument(
        "--prompt-path", default="docs/prompts/ai_gold_adjudication_prompt.md"
    )
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_raw_decision(decision: dict) -> None:
    expected_keys = set(ANNOTATION_SCHEMA["properties"])
    if set(decision) != expected_keys:
        raise ValueError(
            f"{decision.get('sample_id')}: schema keys differ; "
            f"missing={sorted(expected_keys - set(decision))} "
            f"extra={sorted(set(decision) - expected_keys)}"
        )
    for key in (
        "sample_id",
        "cve_id",
        "field",
        "discrepancy_label",
        "adjudicated_source",
        "adjudicated_value",
        "rationale",
        "evidence_notes",
        "uncertainty_notes",
        "version_reasoning_type",
        "confidence",
    ):
        if not isinstance(decision[key], str):
            raise ValueError(f"{decision.get('sample_id')}: {key} must be a string")
    if decision["discrepancy_label"] not in LABELS:
        raise ValueError(f"{decision['sample_id']}: invalid discrepancy_label")
    if decision["adjudicated_source"] not in SOURCES:
        raise ValueError(f"{decision['sample_id']}: invalid adjudicated_source")
    if decision["version_reasoning_type"] not in VERSION_REASONING:
        raise ValueError(f"{decision['sample_id']}: invalid version_reasoning_type")
    if decision["confidence"] not in CONFIDENCE:
        raise ValueError(f"{decision['sample_id']}: invalid confidence")
    if not isinstance(decision["needs_human_review"], bool):
        raise ValueError(f"{decision['sample_id']}: needs_human_review must be boolean")
    urls = decision["evidence_urls"]
    if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
        raise ValueError(f"{decision['sample_id']}: evidence_urls must be a string list")
    if len(urls) != len(set(urls)):
        raise ValueError(f"{decision['sample_id']}: duplicate evidence URL")
    if len(decision["rationale"].strip()) < 30:
        raise ValueError(f"{decision['sample_id']}: rationale is too short")
    if (
        decision["discrepancy_label"] == "uncertain"
        or decision["confidence"] == "low"
    ) and not decision["needs_human_review"]:
        raise ValueError(
            f"{decision['sample_id']}: uncertain/low decision must request review"
        )


def main() -> int:
    args = parse_args()
    worklist_path = resolve(args.worklist)
    decisions_path = resolve(args.decisions)
    output_path = resolve(args.output)
    prompt_path = resolve(args.prompt_path)
    worklist = load_jsonl(worklist_path)
    raw_decisions = load_jsonl(decisions_path)
    if len(worklist) != len(raw_decisions):
        raise ValueError(f"row count mismatch: {len(worklist)} != {len(raw_decisions)}")
    review_notes = {}
    if args.overrides_mode:
        worklist_by_id = {row["sample_id"]: row for row in worklist}
        overrides_by_id = {}
        for row in raw_decisions:
            if set(row) != {"sample_id", "updates", "review_note"}:
                raise ValueError(
                    "override rows require exactly sample_id, updates, and review_note"
                )
            sample_id = row["sample_id"]
            if sample_id in overrides_by_id:
                raise ValueError(f"duplicate override sample_id: {sample_id}")
            if sample_id not in worklist_by_id:
                raise ValueError(f"unknown override sample_id: {sample_id}")
            if not isinstance(row["updates"], dict):
                raise ValueError(f"{sample_id}: updates must be an object")
            forbidden = {"sample_id", "cve_id", "field"} & set(row["updates"])
            if forbidden:
                raise ValueError(f"{sample_id}: identity updates are forbidden: {forbidden}")
            unknown = set(row["updates"]) - set(ANNOTATION_SCHEMA["properties"])
            if unknown:
                raise ValueError(f"{sample_id}: unknown update keys: {unknown}")
            review_note = row["review_note"]
            if not isinstance(review_note, str) or len(review_note.strip()) < 20:
                raise ValueError(f"{sample_id}: review_note is too short")
            overrides_by_id[sample_id] = row["updates"]
            review_notes[sample_id] = review_note.strip()
        if set(overrides_by_id) != set(worklist_by_id):
            raise ValueError("override identities do not exactly match worklist")
        decisions = []
        for item in worklist:
            sample_id = item["sample_id"]
            decision = dict(item["candidate_to_review"]["annotation"])
            decision.update(overrides_by_id[sample_id])
            decisions.append(decision)
    else:
        decisions = raw_decisions
    for decision in decisions:
        validate_raw_decision(decision)
    normalized = validate_batch(worklist, {"annotations": decisions})
    normalized_by_id = {row["sample_id"]: row for row in normalized}

    generated_at = datetime.now(timezone.utc).isoformat()
    wrappers = []
    changed_label = 0
    changed_source = 0
    for item in worklist:
        sample_id = item["sample_id"]
        annotation = normalized_by_id[sample_id]
        contract_normalizations = annotation.pop("_contract_normalizations", [])
        prior = item["candidate_to_review"]
        prior_annotation = prior["annotation"]
        changed_label += (
            annotation["discrepancy_label"]
            != prior_annotation["discrepancy_label"]
        )
        changed_source += (
            annotation["adjudicated_source"]
            != prior_annotation["adjudicated_source"]
        )
        wrappers.append(
            {
                "schema_version": SCHEMA_VERSION,
                "adjudication_status": (
                    "final_abstain"
                    if annotation["discrepancy_label"] == "uncertain"
                    or (
                        item["task_kind"] == "rq3"
                        and annotation["adjudicated_source"] == "abstain"
                    )
                    else "final_determinate"
                ),
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "adjudicator_type": "ai_security_expert",
                "adjudicator_id": f"codex_ai_gold_adjudicator:interactive:{args.pass_id}",
                "model": "codex_current_session",
                "api_route": "interactive_codex",
                "pass_id": args.pass_id,
                "generated_at": generated_at,
                "prompt_path": str(prompt_path),
                "worklist_path": str(worklist_path),
                "worklist_sha256": sha256(worklist_path),
                "decisions_path": str(decisions_path),
                "decisions_sha256": sha256(decisions_path),
                "same_model_family_review": True,
                "independent_human_review": False,
                "sample_id": sample_id,
                "cve_id": annotation["cve_id"],
                "field": annotation["field"],
                "selection_reasons": item["selection_reasons"],
                "contract_normalizations": contract_normalizations,
                "prior_candidate": prior,
                "comparison_passes": item["comparison_passes"],
                "interactive_review_note": review_notes.get(sample_id, ""),
                "annotation": annotation,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in wrappers:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    summary = {
        "schema_version": SCHEMA_VERSION,
        "row_count": len(wrappers),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "changed_label_count": changed_label,
        "changed_source_count": changed_source,
        "label_counts": dict(
            sorted(Counter(row["annotation"]["discrepancy_label"] for row in wrappers).items())
        ),
        "source_counts": dict(
            sorted(Counter(row["annotation"]["adjudicated_source"] for row in wrappers).items())
        ),
        "needs_additional_review_count": sum(
            row["annotation"]["needs_human_review"] for row in wrappers
        ),
        "worklist_sha256": sha256(worklist_path),
        "decisions_sha256": sha256(decisions_path),
        "output_sha256": sha256(output_path),
    }
    summary_path = output_path.with_suffix(".summary.json")
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
