#!/usr/bin/env python3
"""Fail-closed validation for the post-profile three-stage human review packet."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_post_profile_human_review_packet as builder
import validate_rq2_typing_human_review as common


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/human_review"
)
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_post_profile_snapshot_v1/human_review"
SCHEMA_VERSION = builder.SCHEMA_VERSION
EXPECTED_ROWS = builder.EXPECTED_ROWS
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


def validate_row(row: dict, source: dict) -> list[str]:
    sample_id = str(row.get("sample_id") or "<missing>")
    errors = []
    expected = builder.packet_row(source)
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{sample_id}: invalid schema_version")
    if row.get("artifact_type") != "rq2_post_profile_human_review_packet":
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
        if not common.parse_time(resolution.get("signed_at")):
            errors.append(f"{sample_id}: excluded row requires a timezone-aware signed_at")
        return errors

    snapshot = row.get("source_snapshot") or {}
    errors.extend(
        common.validate_decision(sample_id, "annotator", annotator, snapshot)
    )
    errors.extend(
        common.validate_decision(
            sample_id, "independent_reviewer", reviewer, snapshot
        )
    )
    annotator_id = str(annotator.get("human_id") or "").strip()
    reviewer_id = str(reviewer.get("human_id") or "").strip()
    if annotator_id and annotator_id == reviewer_id:
        errors.append(f"{sample_id}: independent reviewer must differ from annotator")
    errors.extend(
        common.validate_resolution(sample_id, resolution, annotator, reviewer)
    )
    if str(review.get("exclusion_reason") or "").strip():
        errors.append(f"{sample_id}: final row exclusion_reason must be blank")
    return errors


def checked_manifest_path(manifest: dict, path_key: str, hash_key: str) -> Path:
    path = Path(manifest[path_key])
    if not path.is_file() or builder.sha256(path) != manifest.get(hash_key):
        raise ValueError(f"human packet source/hash mismatch for {hash_key}")
    return path


def validate_manifest(manifest: dict, input_dir: Path) -> tuple[Path, ...]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid human packet manifest schema_version")
    if manifest.get("artifact_type") != "rq2_post_profile_human_review_manifest":
        raise ValueError("invalid human packet manifest artifact_type")
    if manifest.get("row_count") != EXPECTED_ROWS:
        raise ValueError("human packet manifest row count is not 250")
    if manifest.get("label_is_human") is not False:
        raise ValueError("human packet manifest label_is_human must remain false")
    if manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("human packet manifest cannot claim human-gold eligibility")
    if manifest.get("label_definitions") != builder.LABEL_DEFINITIONS:
        raise ValueError("human packet label-definition contract drift")
    if manifest.get("review_contract") != builder.REVIEW_CONTRACT:
        raise ValueError("human packet review contract drift")
    blindness = manifest.get("blindness_contract") or {}
    if blindness.get("scheduler_contains_labels") is not False:
        raise ValueError("author scheduler must not claim to contain labels")
    if blindness.get("packet_contains_scheduler_signals") is not False:
        raise ValueError("blind packet must not contain scheduler signals")

    sealed_path = checked_manifest_path(
        manifest, "source_sealed_manifest", "source_sealed_manifest_sha256"
    )
    source_path = checked_manifest_path(
        manifest, "source_rows", "source_rows_sha256"
    )
    prediction_path = checked_manifest_path(
        manifest, "source_predictions", "source_predictions_sha256"
    )
    merge_path = checked_manifest_path(
        manifest, "source_merge_manifest", "source_merge_manifest_sha256"
    )
    consensus_path = checked_manifest_path(
        manifest,
        "source_non_human_consensus",
        "source_non_human_consensus_sha256",
    )
    evidence_merge_path = checked_manifest_path(
        manifest,
        "source_all50_evidence_merge",
        "source_all50_evidence_merge_sha256",
    )
    evidence_consensus_path = checked_manifest_path(
        manifest,
        "source_all50_evidence_consensus",
        "source_all50_evidence_consensus_sha256",
    )
    scheduler_path = checked_manifest_path(
        manifest, "scheduler_path", "scheduler_sha256"
    )
    bound = builder.validate_bound_inputs(
        sealed_path, merge_path, evidence_merge_path
    )
    if bound != (
        source_path,
        prediction_path,
        consensus_path,
        evidence_consensus_path,
    ):
        raise ValueError("human packet manifest differs from the sealed source graph")

    packet_path = Path(manifest["packet_path"])
    if not packet_path.is_file() or packet_path.parent != input_dir:
        raise ValueError("packet JSONL is missing or outside the declared input directory")
    if packet_path.name != "rq2_post_profile_human_review.jsonl":
        raise ValueError("unexpected human packet JSONL filename")
    if scheduler_path.parent != input_dir:
        raise ValueError("scheduler JSONL is outside the declared input directory")
    return (
        source_path,
        prediction_path,
        consensus_path,
        evidence_consensus_path,
        packet_path,
        scheduler_path,
    )


def validate_scheduler(
    scheduler_path: Path,
    source_rows: list[dict],
    prediction_rows: list[dict],
    consensus_rows: list[dict],
    evidence_rows: list[dict],
) -> None:
    evidence_by_id = {row["original_sample_id"]: row for row in evidence_rows}
    expected = [
        builder.schedule_row(
            source,
            prediction,
            consensus,
            evidence_by_id.get(source["sample_id"]),
        )
        for source, prediction, consensus in zip(
            source_rows, prediction_rows, consensus_rows
        )
    ]
    expected.sort(
        key=lambda row: (row["queue_tier"], row["within_tier_order_key"])
    )
    actual = list(builder.iter_jsonl(scheduler_path))
    if actual != expected:
        raise ValueError("author-only scheduler content or order drift")


def render_markdown(metrics: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Post-profile Human Review Readiness",
            "",
            f"- Rows: `{metrics['rows']}`",
            f"- Signed final rows: `{metrics['signed_final_rows']}`",
            f"- Excluded rows: `{metrics['excluded_rows']}`",
            f"- Pending rows: `{metrics['pending_rows']}`",
            f"- Validation errors: `{metrics['validation_error_count']}`",
            f"- File workflow complete: `{str(metrics['file_workflow_complete']).lower()}`",
            f"- Ready for external identity verification: `{str(metrics['ready_for_external_identity_verification']).lower()}`",
            "- Human-gold promotion performed: `false`",
            "",
            "The validator cannot prove real-person identity or reviewer independence. External verification and a separate promotion decision remain required.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    input_dir = resolve(args.input_dir)
    output_dir = resolve(args.output_dir)
    manifest = json.loads((input_dir / "manifest.json").read_text(encoding="utf-8"))
    (
        source_path,
        prediction_path,
        consensus_path,
        evidence_consensus_path,
        packet_path,
        scheduler_path,
    ) = validate_manifest(manifest, input_dir)
    source_rows = list(builder.iter_jsonl(source_path))
    prediction_rows = list(builder.iter_jsonl(prediction_path))
    consensus_rows = list(builder.iter_jsonl(consensus_path))
    evidence_rows = list(builder.iter_jsonl(evidence_consensus_path))
    packet_rows = list(builder.iter_jsonl(packet_path))
    if not (
        len(source_rows)
        == len(prediction_rows)
        == len(consensus_rows)
        == len(packet_rows)
        == EXPECTED_ROWS
    ):
        raise ValueError("expected 250 source, prediction, consensus, and packet rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    if [row.get("sample_id") for row in packet_rows] != source_ids:
        raise ValueError("source and packet rows must be ordered identically")
    if len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source sample IDs must be unique")
    validate_scheduler(
        scheduler_path,
        source_rows,
        prediction_rows,
        consensus_rows,
        evidence_rows,
    )

    errors = []
    signed = excluded = pending = 0
    field_status = {
        field: Counter() for field in sorted({row["field"] for row in source_rows})
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
    file_complete = signed == EXPECTED_ROWS and excluded == 0 and not errors
    metrics = {
        "artifact_type": "rq2_post_profile_human_review_readiness",
        "packet_label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "human_gold_promotion_performed": False,
        "rows": len(packet_rows),
        "signed_final_rows": signed,
        "excluded_rows": excluded,
        "pending_rows": pending,
        "validation_error_count": len(errors),
        "file_workflow_complete": file_complete,
        "ready_for_external_identity_verification": file_complete,
        "external_identity_verification_required": True,
        "validator_can_prove_real_person_identity": False,
        "fields": {
            field: dict(sorted(counts.items()))
            for field, counts in field_status.items()
        },
        "errors": errors[:100],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_post_profile_human_review_readiness.json"
    md_path = output_dir / "rq2_post_profile_human_review_readiness.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if errors or (args.require_signed and signed == 0) or (
        args.require_complete and not file_complete
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
