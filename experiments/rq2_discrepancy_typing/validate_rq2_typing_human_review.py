#!/usr/bin/env python3
"""Fail-closed validation for the full RQ2 typing human review packet."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import build_rq2_typing_human_review_packet as builder


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = "data/annotations/holdout/rq2_typing_v1/human_review"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1/human_review"
SCHEMA_VERSION = builder.SCHEMA_VERSION
EXPECTED_ROWS = builder.EXPECTED_ROWS
LABELS = set(builder.LABELS)
CONFIDENCE = set(builder.CONFIDENCE)
SOURCE_BOUND_KEYS = (
    "review_id",
    "sample_id",
    "cve_id",
    "field",
    "source_snapshot",
    "review_contract",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--require-signed", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def parse_time(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_evidence_urls(
    sample_id: str,
    role: str,
    evidence_urls: object,
    snapshot: dict,
) -> list[str]:
    if not isinstance(evidence_urls, list):
        return [f"{sample_id}: {role}.evidence_urls must be a list"]
    if len(evidence_urls) != len(set(evidence_urls)):
        return [f"{sample_id}: {role}.evidence_urls contains duplicates"]
    snapshot_text = json.dumps(snapshot, ensure_ascii=False, sort_keys=True)
    return [
        f"{sample_id}: {role}.evidence_urls contains a URL outside the frozen snapshot"
        for url in evidence_urls
        if not isinstance(url, str) or not url or url not in snapshot_text
    ]


def validate_decision(
    sample_id: str,
    role: str,
    decision: dict,
    snapshot: dict,
) -> list[str]:
    errors = []
    if not str(decision.get("human_id") or "").strip():
        errors.append(f"{sample_id}: {role}.human_id is required")
    label = decision.get("discrepancy_label")
    confidence = decision.get("confidence")
    if label not in LABELS:
        errors.append(f"{sample_id}: invalid {role}.discrepancy_label")
    if confidence not in CONFIDENCE:
        errors.append(f"{sample_id}: invalid {role}.confidence")
    if len(str(decision.get("rationale") or "").strip()) < 80:
        errors.append(f"{sample_id}: {role}.rationale must contain at least 80 characters")
    construct_notes = str(decision.get("construct_notes") or "").strip()
    if (label == "uncertain" or confidence == "low") and len(construct_notes) < 40:
        errors.append(
            f"{sample_id}: {role}.construct_notes must explain uncertain or low-confidence decisions"
        )
    errors.extend(
        validate_evidence_urls(
            sample_id,
            role,
            decision.get("evidence_urls"),
            snapshot,
        )
    )
    if not parse_time(decision.get("reviewed_at")):
        errors.append(f"{sample_id}: {role}.reviewed_at must include an ISO timezone")
    return errors


def validate_resolution(
    sample_id: str,
    resolution: dict,
    annotator: dict,
    reviewer: dict,
) -> list[str]:
    errors = []
    final_label = resolution.get("final_label")
    basis = resolution.get("resolution_basis")
    if final_label not in LABELS:
        errors.append(f"{sample_id}: invalid resolution.final_label")
    if basis not in {"agreement", "adjudicated"}:
        errors.append(f"{sample_id}: invalid resolution.resolution_basis")
    elif basis == "agreement" and not (
        annotator.get("discrepancy_label")
        == reviewer.get("discrepancy_label")
        == final_label
    ):
        errors.append(
            f"{sample_id}: agreement resolution requires matching independent labels"
        )
    if len(str(resolution.get("resolution_rationale") or "").strip()) < 80:
        errors.append(
            f"{sample_id}: resolution_rationale must contain at least 80 characters"
        )
    if not str(resolution.get("author_id") or "").strip():
        errors.append(f"{sample_id}: resolution.author_id is required")
    if resolution.get("author_signoff") != "signed":
        errors.append(f"{sample_id}: resolution.author_signoff must be signed")
    if not parse_time(resolution.get("signed_at")):
        errors.append(f"{sample_id}: resolution.signed_at must include an ISO timezone")
    return errors


def validate_row(row: dict, source: dict) -> list[str]:
    sample_id = str(row.get("sample_id") or "<missing>")
    errors = []
    expected = builder.packet_row(source)
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{sample_id}: invalid schema_version")
    if row.get("artifact_type") != "rq2_typing_human_review_packet":
        errors.append(f"{sample_id}: invalid artifact_type")
    if row.get("label_is_human") is not False:
        errors.append(f"{sample_id}: packet label_is_human must remain false")
    if row.get("eligible_for_human_gold_claim") is not False:
        errors.append(
            f"{sample_id}: packet eligible_for_human_gold_claim must remain false"
        )
    forbidden = builder.FORBIDDEN_BLIND_KEYS & set(row)
    if forbidden:
        errors.append(f"{sample_id}: packet exposes forbidden blind keys {sorted(forbidden)}")
    for key in SOURCE_BOUND_KEYS:
        if row.get(key) != expected.get(key):
            errors.append(f"{sample_id}: source identity/value drift for {key}")

    review = row.get("human_review")
    if not isinstance(review, dict):
        return [*errors, f"{sample_id}: missing human_review"]
    status = review.get("review_status")
    if status not in {"pending", "final", "excluded"}:
        errors.append(f"{sample_id}: invalid review_status")
        return errors
    if status == "pending":
        if review != builder.empty_human_review():
            errors.append(f"{sample_id}: pending row must not contain review content")
        return errors

    annotator = review.get("annotator") or {}
    reviewer = review.get("independent_reviewer") or {}
    resolution = review.get("resolution") or {}
    if status == "excluded":
        if len(str(review.get("exclusion_reason") or "").strip()) < 80:
            errors.append(f"{sample_id}: exclusion_reason must contain at least 80 characters")
        if annotator != builder.empty_decision():
            errors.append(f"{sample_id}: excluded row annotator content must remain blank")
        if reviewer != builder.empty_decision():
            errors.append(f"{sample_id}: excluded row reviewer content must remain blank")
        permitted_resolution = {
            **builder.empty_resolution(),
            "author_id": resolution.get("author_id"),
            "author_signoff": resolution.get("author_signoff"),
            "signed_at": resolution.get("signed_at"),
        }
        if resolution != permitted_resolution:
            errors.append(f"{sample_id}: excluded row must not contain a final label")
        if not str(resolution.get("author_id") or "").strip():
            errors.append(f"{sample_id}: excluded row requires author_id")
        if resolution.get("author_signoff") != "signed":
            errors.append(f"{sample_id}: excluded row requires signed author resolution")
        if not parse_time(resolution.get("signed_at")):
            errors.append(f"{sample_id}: excluded row requires a timezone-aware signed_at")
        return errors

    snapshot = row.get("source_snapshot") or {}
    errors.extend(validate_decision(sample_id, "annotator", annotator, snapshot))
    errors.extend(
        validate_decision(sample_id, "independent_reviewer", reviewer, snapshot)
    )
    annotator_id = str(annotator.get("human_id") or "").strip()
    reviewer_id = str(reviewer.get("human_id") or "").strip()
    if annotator_id and annotator_id == reviewer_id:
        errors.append(f"{sample_id}: independent reviewer must differ from annotator")
    errors.extend(validate_resolution(sample_id, resolution, annotator, reviewer))
    if str(review.get("exclusion_reason") or "").strip():
        errors.append(f"{sample_id}: final row exclusion_reason must be blank")
    return errors


def validate_manifest(manifest: dict, input_dir: Path) -> tuple[Path, Path, Path]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid human packet manifest schema_version")
    if manifest.get("artifact_type") != "rq2_typing_human_review_manifest":
        raise ValueError("invalid human packet manifest artifact_type")
    if manifest.get("row_count") != EXPECTED_ROWS:
        raise ValueError("human packet manifest row count is not 1250")
    if manifest.get("label_is_human") is not False:
        raise ValueError("human packet manifest label_is_human must remain false")
    if manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("human packet manifest cannot claim human-gold eligibility")
    if manifest.get("label_definitions") != builder.LABEL_DEFINITIONS:
        raise ValueError("human packet label-definition contract drift")
    if manifest.get("review_contract") != builder.REVIEW_CONTRACT:
        raise ValueError("human packet review contract drift")

    sealed_path = Path(manifest["source_sealed_manifest"])
    source_path = Path(manifest["source_rows"])
    merge_path = Path(manifest["source_merge_manifest"])
    consensus_path = Path(manifest["source_non_human_consensus"])
    packet_path = Path(manifest["packet_path"])
    scheduler_path = Path(manifest["scheduler_path"])
    checks = (
        (sealed_path, "source_sealed_manifest_sha256"),
        (source_path, "source_rows_sha256"),
        (merge_path, "source_merge_manifest_sha256"),
        (consensus_path, "source_non_human_consensus_sha256"),
        (scheduler_path, "scheduler_sha256"),
    )
    for path, key in checks:
        if not path.is_file() or builder.sha256(path) != manifest.get(key):
            raise ValueError(f"human packet source/hash mismatch for {key}")
    bound_source, bound_consensus = builder.validate_bound_inputs(sealed_path, merge_path)
    if bound_source != source_path or bound_consensus != consensus_path:
        raise ValueError("human packet manifest differs from the sealed source graph")
    if packet_path.parent != input_dir:
        raise ValueError("packet JSONL is outside the declared input directory")
    if packet_path.name != "rq2_typing_holdout_human_review.jsonl":
        raise ValueError("unexpected human packet JSONL filename")
    if scheduler_path.parent != input_dir:
        raise ValueError("scheduler JSONL is outside the declared input directory")
    return source_path, consensus_path, packet_path


def validate_scheduler(
    scheduler_path: Path,
    source_rows: list[dict],
    consensus_rows: list[dict],
) -> None:
    actual = list(iter_jsonl(scheduler_path))
    expected = [
        builder.schedule_row(source, consensus)
        for source, consensus in zip(source_rows, consensus_rows)
    ]
    expected.sort(key=lambda row: (row["queue_tier"], row["within_tier_order_key"]))
    if actual != expected:
        raise ValueError("author-only scheduler content or order drift")


def render_markdown(metrics: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Typing Human Review Readiness",
            "",
            f"- Rows: `{metrics['rows']}`",
            f"- Signed final rows: `{metrics['signed_final_rows']}`",
            f"- Excluded rows: `{metrics['excluded_rows']}`",
            f"- Pending rows: `{metrics['pending_rows']}`",
            f"- Validation errors: `{metrics['validation_error_count']}`",
            f"- Workflow complete: `{str(metrics['workflow_complete']).lower()}`",
            f"- Eligible for separate human-gold promotion: `{str(metrics['eligible_for_promotion_to_human_gold']).lower()}`",
            "",
            "The packet itself remains non-human provenance metadata. Real-person identity and independence require external verification.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    input_dir = resolve(args.input_dir)
    output_dir = resolve(args.output_dir)
    manifest = json.loads((input_dir / "manifest.json").read_text(encoding="utf-8"))
    source_path, consensus_path, packet_path = validate_manifest(manifest, input_dir)
    scheduler_path = Path(manifest["scheduler_path"])
    source_rows = list(iter_jsonl(source_path))
    consensus_rows = list(iter_jsonl(consensus_path))
    packet_rows = list(iter_jsonl(packet_path))
    if not (
        len(source_rows) == len(consensus_rows) == len(packet_rows) == EXPECTED_ROWS
    ):
        raise ValueError("expected 1250 source, consensus, and packet rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    packet_ids = [row.get("sample_id") for row in packet_rows]
    if source_ids != packet_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source and packet sample IDs must be unique and ordered identically")
    validate_scheduler(scheduler_path, source_rows, consensus_rows)

    errors = []
    signed = excluded = pending = 0
    field_status = {
        field: Counter()
        for field in sorted({row["field"] for row in source_rows})
    }
    for row, source in zip(packet_rows, source_rows):
        row_errors = validate_row(row, source)
        errors.extend(row_errors)
        status = (row.get("human_review") or {}).get("review_status")
        if status == "final" and not row_errors:
            signed += 1
            field_status[source["field"]]["signed"] += 1
        elif status == "excluded" and not row_errors:
            excluded += 1
            field_status[source["field"]]["excluded"] += 1
        else:
            pending += 1
            field_status[source["field"]]["pending"] += 1
    workflow_complete = signed + excluded == EXPECTED_ROWS and not errors
    promotion_ready = signed == EXPECTED_ROWS and excluded == 0 and not errors
    metrics = {
        "artifact_type": "rq2_typing_human_review_readiness",
        "packet_label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "rows": len(packet_rows),
        "signed_final_rows": signed,
        "excluded_rows": excluded,
        "pending_rows": pending,
        "validation_error_count": len(errors),
        "workflow_complete": workflow_complete,
        "eligible_for_promotion_to_human_gold": promotion_ready,
        "external_identity_verification_required": True,
        "fields": {
            field: dict(sorted(counts.items()))
            for field, counts in field_status.items()
        },
        "errors": errors[:100],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_typing_human_review_readiness.json"
    md_path = output_dir / "rq2_typing_human_review_readiness.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if errors or (args.require_signed and signed == 0) or (
        args.require_complete and not promotion_ready
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
