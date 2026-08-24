#!/usr/bin/env python3
"""Validate signed human review over isolated AI expert candidate packets."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = "data/annotations/expert_candidate/review_packets"
DEFAULT_OUTPUT_DIR = "results/expert_candidate_validation"

LABELS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
SOURCES = {"nvd", "ghsa", "both", "neither", "abstain", "uncertain"}
VERSION_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
    "not_applicable",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate human sign-off without promoting rows to canonical gold."
    )
    parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="Fail unless at least one row passes the human sign-off gate.",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail unless every packet row is signed or explicitly excluded.",
    )
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                yield line_number, json.loads(line)


def parse_time(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def signed_status(row: dict) -> bool:
    review = row.get("human_review") or {}
    return (
        review.get("review_status") in {"approved", "revised"}
        and review.get("author_signoff") == "signed"
    )


def packet_path(input_dir: Path, manifest_value: str) -> Path:
    path = Path(manifest_value)
    if path.is_absolute():
        return path
    local_copy = input_dir / path.name
    if local_copy.exists():
        return local_copy
    return resolve_path(path)


def validate_packet(row: dict) -> list[str]:
    sample_id = row.get("sample_id") or "<missing>"
    errors = []
    if row.get("schema_version") != "expert_candidate_review_v1":
        errors.append(f"{sample_id}: invalid schema_version")
    if row.get("label_is_human") is not False:
        errors.append(f"{sample_id}: packet label_is_human must remain false")
    candidate = row.get("ai_candidate")
    if not isinstance(candidate, dict) or not candidate.get("discrepancy_label"):
        errors.append(f"{sample_id}: missing ai_candidate")
    review = row.get("human_review")
    if not isinstance(review, dict):
        return [*errors, f"{sample_id}: missing human_review"]

    review_status = review.get("review_status")
    author_signoff = review.get("author_signoff")
    if review_status not in {"pending", "approved", "revised", "excluded"}:
        errors.append(f"{sample_id}: invalid review_status={review_status!r}")
    if author_signoff not in {"pending", "signed", "rejected"}:
        errors.append(f"{sample_id}: invalid author_signoff={author_signoff!r}")
    if not signed_status(row):
        return errors

    final_label = review.get("final_label")
    if final_label not in LABELS:
        errors.append(f"{sample_id}: invalid final_label={final_label!r}")
    if len(str(review.get("final_rationale") or "").strip()) < 10:
        errors.append(f"{sample_id}: final_rationale must contain at least 10 characters")
    annotator = str(review.get("human_annotator_id") or "").strip()
    reviewer = str(review.get("independent_reviewer_id") or "").strip()
    if not annotator:
        errors.append(f"{sample_id}: human_annotator_id is required")
    if not reviewer:
        errors.append(f"{sample_id}: independent_reviewer_id is required")
    elif annotator and reviewer == annotator:
        errors.append(f"{sample_id}: reviewer must differ from annotator")
    if not parse_time(review.get("reviewed_at")):
        errors.append(f"{sample_id}: reviewed_at must be an ISO date/time")

    task_kind = row.get("task_kind")
    if task_kind == "rq2":
        if review.get("is_baseline_correct") not in {"yes", "no", "uncertain"}:
            errors.append(f"{sample_id}: invalid is_baseline_correct")
        if review.get("needs_adjudication") not in {"yes", "no"}:
            errors.append(f"{sample_id}: invalid needs_adjudication")
        if final_label == "factual_conflict" and review.get("needs_adjudication") != "yes":
            errors.append(f"{sample_id}: factual_conflict requires needs_adjudication=yes")
    elif task_kind == "rq3":
        source = review.get("final_source")
        if source not in SOURCES:
            errors.append(f"{sample_id}: invalid final_source={source!r}")
        evidence_urls = review.get("evidence_urls")
        if not isinstance(evidence_urls, list):
            errors.append(f"{sample_id}: evidence_urls must be a list")
        elif source not in {"abstain", "uncertain"} and not evidence_urls:
            errors.append(f"{sample_id}: non-abstain source requires evidence_urls")
        if source not in {"abstain", "uncertain"} and len(
            str(review.get("evidence_notes") or "").strip()
        ) < 10:
            errors.append(f"{sample_id}: non-abstain source requires evidence_notes")
        if row.get("field") == "affected_versions" and review.get(
            "version_reasoning_type"
        ) not in VERSION_REASONING:
            errors.append(f"{sample_id}: invalid version_reasoning_type")
    else:
        errors.append(f"{sample_id}: invalid task_kind={task_kind!r}")
    return errors


def render_markdown(metrics: dict) -> str:
    lines = [
        "# Human Review Packet Readiness",
        "",
        "AI candidates remain non-human until signed review passes this gate.",
        "",
        f"- Packet rows: `{metrics['packet_rows']}`",
        f"- Signed human rows: `{metrics['signed_human_rows']}`",
        f"- Excluded rows: `{metrics['excluded_rows']}`",
        f"- Pending rows: `{metrics['pending_rows']}`",
        f"- Validation errors: `{metrics['validation_error_count']}`",
        f"- Complete: `{str(metrics['complete']).lower()}`",
        "",
        "| Dataset | Rows | Signed | Excluded | Pending | Errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for dataset, values in metrics["datasets"].items():
        lines.append(
            f"| {dataset} | {values['rows']} | {values['signed']} | "
            f"{values['excluded']} | {values['pending']} | {values['errors']} |"
        )
    if metrics["errors"]:
        lines.extend(["", "## First Errors", ""])
        lines.extend(f"- {error}" for error in metrics["errors"][:20])
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    input_dir = resolve_path(args.input_dir)
    output_dir = resolve_path(args.output_dir)
    manifest_path = input_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    datasets = {}
    errors = []
    total_rows = signed = excluded = pending = 0

    for dataset in manifest.get("datasets", []):
        name = dataset["dataset"]
        path = packet_path(input_dir, dataset["jsonl_path"])
        rows = list(iter_jsonl(path))
        if len(rows) != dataset["candidate_rows"]:
            errors.append(
                f"{name}: manifest rows={dataset['candidate_rows']} actual={len(rows)}"
            )
        dataset_errors = 0
        dataset_signed = dataset_excluded = dataset_pending = 0
        for _line_number, row in rows:
            row_errors = validate_packet(row)
            errors.extend(row_errors)
            dataset_errors += len(row_errors)
            if signed_status(row) and not row_errors:
                dataset_signed += 1
            elif (row.get("human_review") or {}).get("review_status") == "excluded":
                dataset_excluded += 1
            else:
                dataset_pending += 1
        datasets[name] = {
            "rows": len(rows),
            "signed": dataset_signed,
            "excluded": dataset_excluded,
            "pending": dataset_pending,
            "errors": dataset_errors,
        }
        total_rows += len(rows)
        signed += dataset_signed
        excluded += dataset_excluded
        pending += dataset_pending

    complete = total_rows > 0 and signed + excluded == total_rows and not errors
    metrics = {
        "artifact_type": "human_review_packet_readiness",
        "candidate_label_is_human": False,
        "packet_rows": total_rows,
        "signed_human_rows": signed,
        "excluded_rows": excluded,
        "pending_rows": pending,
        "validation_error_count": len(errors),
        "complete": complete,
        "datasets": datasets,
        "errors": errors[:100],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "human_review_packet_readiness.json"
    md_path = output_dir / "human_review_packet_readiness.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if errors or (args.require_signed and signed == 0) or (
        args.require_complete and not complete
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
