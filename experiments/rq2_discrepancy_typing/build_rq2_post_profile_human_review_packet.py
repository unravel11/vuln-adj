#!/usr/bin/env python3
"""Build a blind three-stage human review packet for the post-profile cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import build_rq2_typing_human_review_packet as common


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HOLDOUT_DIR = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_RESULTS_DIR = "results/holdout/rq2_post_profile_snapshot_v1/review"
DEFAULT_EVIDENCE_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/cwe_all50_evidence_v3"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/human_review"
)
SCHEMA_VERSION = "rq2_post_profile_human_review_v1"
EXPECTED_ROWS = 250
EXPECTED_ROWS_PER_FIELD = 50
EXPECTED_CWE_ROWS = 50
LABELS = common.LABELS
CONFIDENCE = common.CONFIDENCE
LABEL_DEFINITIONS = common.LABEL_DEFINITIONS
SOURCE_SNAPSHOT_KEYS = common.SOURCE_SNAPSHOT_KEYS
FORBIDDEN_BLIND_KEYS = {
    *common.FORBIDDEN_BLIND_KEYS,
    "current",
    "reference_resource_identity_original_v1",
    "reference_resource_identity_audited_v1",
    "cwe_taxonomy_v1",
    "combined_original_v1",
    "combined_audited_v1",
    "profile_difference",
    "profile_direction",
    "reviewer_e",
    "reviewer_f",
    "queue_tier",
    "queue_reason",
    "priority_signals",
}
REVIEW_CONTRACT = {
    **common.REVIEW_CONTRACT,
    "cohort": "rq2_post_profile_snapshot_v1",
    "all_sealed_rows_required": True,
    "non_human_labels_must_not_be_copied_into_human_fields": True,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout-dir", default=DEFAULT_HOLDOUT_DIR)
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--evidence-dir", default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def empty_decision() -> dict:
    return common.empty_decision()


def empty_resolution() -> dict:
    return common.empty_resolution()


def empty_human_review() -> dict:
    return common.empty_human_review()


def source_snapshot(source: dict) -> dict:
    return {key: source.get(key) for key in SOURCE_SNAPSHOT_KEYS}


def packet_row(source: dict) -> dict:
    snapshot = source_snapshot(source)
    if FORBIDDEN_BLIND_KEYS & set(snapshot):
        raise ValueError("blind source projection contains a forbidden key")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_human_review_packet",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "review_id": source["sample_id"],
        "sample_id": source["sample_id"],
        "cve_id": source["cve_id"],
        "field": source["field"],
        "source_snapshot": snapshot,
        "review_contract": REVIEW_CONTRACT,
        "human_review": empty_human_review(),
    }


def schedule_row(
    source: dict,
    prediction: dict,
    consensus: dict,
    evidence: dict | None,
) -> dict:
    original_non_strict = consensus.get("strict_consensus") is not True
    profile_difference = prediction.get("current") != prediction.get("cwe_taxonomy_v1")
    evidence_non_strict = bool(evidence) and evidence.get("strict_consensus") is not True
    evidence_shift = bool(evidence) and (
        evidence.get("strict_consensus") is True
        and evidence.get("prior_strict_consensus") is True
        and evidence.get("consensus_label") != evidence.get("prior_consensus_label")
    )
    baseline_mismatch = consensus.get("strict_consensus") is True and (
        source.get("baseline_status") != consensus.get("consensus_label")
    )
    signals = {
        "original_review_non_strict": original_non_strict,
        "sealed_cwe_profile_difference": profile_difference,
        "field_complete_evidence_non_strict": evidence_non_strict,
        "field_complete_evidence_shift": evidence_shift,
        "baseline_vs_original_strict_consensus_mismatch": baseline_mismatch,
    }
    if original_non_strict:
        tier = 1
        reason = "original_non_human_review_unresolved"
    elif profile_difference or evidence_non_strict or evidence_shift:
        tier = 2
        reason = "post_hoc_cwe_diagnostic_focus"
    elif baseline_mismatch:
        tier = 3
        reason = "baseline_vs_non_human_consensus_disagreement"
    else:
        tier = 4
        reason = "full_sealed_cohort_completion"
    return {
        "sample_id": source["sample_id"],
        "queue_tier": tier,
        "queue_reason": reason,
        "priority_signals": signals,
        "within_tier_order_key": hashlib.sha256(
            source["sample_id"].encode("utf-8")
        ).hexdigest(),
    }


def checked_output(manifest: dict, key: str) -> Path:
    entry = (manifest.get("outputs") or {}).get(key) or {}
    path = Path(entry.get("path", ""))
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise ValueError(f"manifest output/hash mismatch for {key}")
    return path


def validate_bound_inputs(
    sealed_manifest_path: Path,
    merge_manifest_path: Path,
    evidence_merge_path: Path,
) -> tuple[Path, Path, Path, Path]:
    sealed = json.loads(sealed_manifest_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected sealed cohort manifest artifact_type")
    if sealed.get("selected_rows") != EXPECTED_ROWS:
        raise ValueError("sealed post-profile cohort does not contain 250 rows")
    if (sealed.get("boundary") or {}).get("label_is_human") is not False:
        raise ValueError("sealed cohort unexpectedly claims human labels")
    source_path = checked_output(sealed, "source_rows")
    prediction_path = checked_output(sealed, "predictions")

    merge = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if merge.get("artifact_type") != "rq2_post_profile_snapshot_merge_manifest":
        raise ValueError("unexpected post-profile merge manifest artifact_type")
    sealed_entry = (merge.get("inputs") or {}).get("sealed_manifest") or {}
    if Path(sealed_entry.get("path", "")) != sealed_manifest_path:
        raise ValueError("review merge is not bound to the selected cohort")
    if sha256(sealed_manifest_path) != sealed_entry.get("sha256"):
        raise ValueError("sealed cohort hash differs from the review merge")
    consensus_path = checked_output(merge, "consensus")

    evidence_merge = json.loads(evidence_merge_path.read_text(encoding="utf-8"))
    if evidence_merge.get("artifact_type") != "rq2_post_profile_cwe_all50_merge_manifest_v3":
        raise ValueError("unexpected all-50 evidence merge manifest artifact_type")
    evidence_manifest_entry = evidence_merge.get("source_manifest") or {}
    evidence_manifest_path = Path(evidence_manifest_entry.get("path", ""))
    if (
        not evidence_manifest_path.is_file()
        or sha256(evidence_manifest_path) != evidence_manifest_entry.get("sha256")
    ):
        raise ValueError("all-50 evidence source manifest/hash mismatch")
    evidence_consensus_path = checked_output(evidence_merge, "consensus")
    return source_path, prediction_path, consensus_path, evidence_consensus_path


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    holdout_dir = resolve(args.holdout_dir)
    results_dir = resolve(args.results_dir)
    evidence_dir = resolve(args.evidence_dir)
    output_dir = resolve(args.output_dir)
    sealed_manifest_path = holdout_dir / "manifest.sealed.json"
    merge_manifest_path = results_dir / "merge_manifest.json"
    evidence_merge_path = evidence_dir / "merge_manifest.json"
    source_path, prediction_path, consensus_path, evidence_consensus_path = (
        validate_bound_inputs(
            sealed_manifest_path,
            merge_manifest_path,
            evidence_merge_path,
        )
    )
    source_rows = list(iter_jsonl(source_path))
    prediction_rows = list(iter_jsonl(prediction_path))
    consensus_rows = list(iter_jsonl(consensus_path))
    evidence_rows = list(iter_jsonl(evidence_consensus_path))
    if not (
        len(source_rows) == len(prediction_rows) == len(consensus_rows) == EXPECTED_ROWS
    ):
        raise ValueError("expected 250 source, prediction, and consensus rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    if len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source sample IDs must be unique")
    for rows, name in ((prediction_rows, "prediction"), (consensus_rows, "consensus")):
        if [row.get("sample_id") for row in rows] != source_ids:
            raise ValueError(f"{name} rows are not ordered like the sealed source")
    field_counts = Counter(row.get("field") for row in source_rows)
    if set(field_counts.values()) != {EXPECTED_ROWS_PER_FIELD}:
        raise ValueError("expected 50 rows for every post-profile field")

    evidence_by_id = {
        row.get("original_sample_id"): row for row in evidence_rows
    }
    if len(evidence_by_id) != EXPECTED_CWE_ROWS or None in evidence_by_id:
        raise ValueError("expected 50 unique all-50 evidence rows")
    expected_cwe_ids = {
        row["sample_id"] for row in source_rows if row.get("field") == "cwe_ids"
    }
    if set(evidence_by_id) != expected_cwe_ids:
        raise ValueError("all-50 evidence rows do not cover the sealed CWE field")

    packet_rows = [packet_row(source) for source in source_rows]
    scheduler_rows = [
        schedule_row(source, prediction, consensus, evidence_by_id.get(source["sample_id"]))
        for source, prediction, consensus in zip(
            source_rows, prediction_rows, consensus_rows
        )
    ]
    scheduler_rows.sort(
        key=lambda row: (row["queue_tier"], row["within_tier_order_key"])
    )
    packet_path = output_dir / "rq2_post_profile_human_review.jsonl"
    scheduler_path = output_dir / "author_review_scheduler.jsonl"
    manifest_path = output_dir / "manifest.json"
    readme_path = output_dir / "README.md"
    existing = [
        path
        for path in (packet_path, scheduler_path, manifest_path, readme_path)
        if path.exists()
    ]
    if existing:
        raise FileExistsError(f"refusing to overwrite human review files: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(packet_path, packet_rows)
    write_jsonl(scheduler_path, scheduler_rows)

    tier_counts = Counter(row["queue_tier"] for row in scheduler_rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_human_review_manifest",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(packet_rows),
        "field_counts": dict(sorted(field_counts.items())),
        "human_fields_blank_at_build": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "source_sealed_manifest": str(sealed_manifest_path),
        "source_sealed_manifest_sha256": sha256(sealed_manifest_path),
        "source_rows": str(source_path),
        "source_rows_sha256": sha256(source_path),
        "source_predictions": str(prediction_path),
        "source_predictions_sha256": sha256(prediction_path),
        "source_merge_manifest": str(merge_manifest_path),
        "source_merge_manifest_sha256": sha256(merge_manifest_path),
        "source_non_human_consensus": str(consensus_path),
        "source_non_human_consensus_sha256": sha256(consensus_path),
        "source_all50_evidence_merge": str(evidence_merge_path),
        "source_all50_evidence_merge_sha256": sha256(evidence_merge_path),
        "source_all50_evidence_consensus": str(evidence_consensus_path),
        "source_all50_evidence_consensus_sha256": sha256(evidence_consensus_path),
        "packet_path": str(packet_path),
        "initial_blank_packet_sha256": sha256(packet_path),
        "scheduler_path": str(scheduler_path),
        "scheduler_sha256": sha256(scheduler_path),
        "scheduler_tier_counts": {
            str(tier): tier_counts[tier] for tier in sorted(tier_counts)
        },
        "label_definitions": LABEL_DEFINITIONS,
        "review_contract": REVIEW_CONTRACT,
        "blindness_contract": {
            "packet_omits": sorted(FORBIDDEN_BLIND_KEYS),
            "scheduler_is_author_only": True,
            "scheduler_contains_labels": False,
            "packet_contains_scheduler_signals": False,
        },
        "instructions": [
            "Two different real people independently label every row from the packet only.",
            "Neither reviewer may see model outputs, consensus labels, or the author scheduler.",
            "An author resolves the independent decisions and signs every row.",
            "Real-person identity and independence require verification outside this file.",
            "This packet and validator cannot by themselves create or claim human gold.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    readme_path.write_text(
        "# RQ2 Post-profile Human Review Packet\n\n"
        "This directory contains a blank, source-bound packet for all 250 sealed "
        "post-profile rows (50 per field). The review rows omit baselines, profile "
        "predictions, all non-human reviewer decisions, consensus labels, sampling "
        "strata, and author-side priority signals.\n\n"
        "## Required process\n\n"
        "1. A real human annotator labels every row from `rq2_post_profile_human_review.jsonl`.\n"
        "2. A different real human repeats the review independently.\n"
        "3. An author resolves and signs every row.\n"
        "4. Run the fail-closed validator with `--require-complete`.\n"
        "5. Verify reviewer identities and independence outside the JSON files before any human-gold claim.\n\n"
        "`author_review_scheduler.jsonl` is author-only and contains priority signals "
        "but no labels. Do not expose it to either reviewer. The validator checks file "
        "integrity and process fields; it cannot prove that an ID belongs to a real person.\n",
        encoding="utf-8",
    )
    print(f"Wrote {packet_path}")
    print(f"Wrote {scheduler_path}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
