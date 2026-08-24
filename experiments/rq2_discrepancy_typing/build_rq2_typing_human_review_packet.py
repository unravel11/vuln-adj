#!/usr/bin/env python3
"""Build a blind, blank three-stage human review packet for all RQ2 holdout rows."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HOLDOUT_DIR = "data/annotations/holdout/rq2_typing_v1"
DEFAULT_RESULTS_DIR = "results/holdout/rq2_typing_v1"
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/rq2_typing_v1/human_review"
SCHEMA_VERSION = "rq2_typing_human_review_v1"
EXPECTED_ROWS = 1250
EXPECTED_ROWS_PER_FIELD = 250
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)
CONFIDENCE = ("high", "medium", "low")
LABEL_DEFINITIONS = {
    "equivalent": (
        "Both sources express the same field fact after conservative, documented normalization."
    ),
    "representation_discrepancy": (
        "The sources use different syntax, schema, encoding, or compatible granularity, "
        "and neither is a strict information subset of the other."
    ),
    "incomplete": (
        "One source is empty or is a compatible strict information subset of the other."
    ),
    "temporal_discrepancy": (
        "The difference is specifically attributable to publication or update timing."
    ),
    "factual_conflict": (
        "Comparable non-empty values make materially incompatible claims after conservative normalization."
    ),
    "uncertain": (
        "The frozen evidence is insufficient to resolve identity, taxonomy, range semantics, or another construct choice."
    ),
}
SOURCE_SNAPSHOT_KEYS = (
    "nvd_source_id",
    "ghsa_source_id",
    "nvd_value",
    "ghsa_value",
    "field_context",
    "reference_context",
    "package_names",
)
FORBIDDEN_BLIND_KEYS = {
    "baseline_status",
    "baseline_note",
    "sampling_stratum",
    "consensus_label",
    "strict_consensus",
    "reviewer_a",
    "reviewer_b",
}
REVIEW_CONTRACT = {
    "task": "nvd_ghsa_field_discrepancy_typing",
    "allowed_labels": list(LABELS),
    "allowed_confidence": list(CONFIDENCE),
    "typing_only": True,
    "frozen_evidence_only": True,
    "annotator_and_reviewer_must_be_different_real_people": True,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout-dir", default=DEFAULT_HOLDOUT_DIR)
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR)
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
    return {
        "human_id": "",
        "discrepancy_label": "",
        "confidence": "",
        "rationale": "",
        "construct_notes": "",
        "evidence_urls": [],
        "reviewed_at": "",
    }


def empty_resolution() -> dict:
    return {
        "final_label": "",
        "resolution_basis": "",
        "resolution_rationale": "",
        "author_id": "",
        "author_signoff": "pending",
        "signed_at": "",
    }


def empty_human_review() -> dict:
    return {
        "review_status": "pending",
        "annotator": empty_decision(),
        "independent_reviewer": empty_decision(),
        "resolution": empty_resolution(),
        "exclusion_reason": "",
    }


def source_snapshot(source: dict) -> dict:
    return {key: source.get(key) for key in SOURCE_SNAPSHOT_KEYS}


def packet_row(source: dict) -> dict:
    if FORBIDDEN_BLIND_KEYS & set(source_snapshot(source)):
        raise ValueError("blind source projection contains a forbidden key")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_typing_human_review_packet",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "review_id": source["sample_id"],
        "sample_id": source["sample_id"],
        "cve_id": source["cve_id"],
        "field": source["field"],
        "source_snapshot": source_snapshot(source),
        "review_contract": REVIEW_CONTRACT,
        "human_review": empty_human_review(),
    }


def schedule_row(source: dict, consensus: dict) -> dict:
    if not consensus.get("strict_consensus"):
        tier = 1
        reason = "non_human_reviewer_disagreement"
    elif source["baseline_status"] != consensus.get("consensus_label"):
        tier = 2
        reason = "baseline_vs_non_human_consensus_disagreement"
    else:
        tier = 3
        reason = "full_holdout_completion"
    return {
        "sample_id": source["sample_id"],
        "queue_tier": tier,
        "queue_reason": reason,
        "within_tier_order_key": hashlib.sha256(
            source["sample_id"].encode("utf-8")
        ).hexdigest(),
    }


def validate_bound_inputs(
    sealed_manifest_path: Path,
    merge_manifest_path: Path,
) -> tuple[Path, Path]:
    sealed = json.loads(sealed_manifest_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_typing_holdout_v1_manifest":
        raise ValueError("unexpected sealed holdout manifest artifact_type")
    if sealed.get("selected_rows") != EXPECTED_ROWS:
        raise ValueError("sealed holdout does not contain 1250 rows")
    if sealed.get("contains_human_labels") is not False:
        raise ValueError("sealed holdout unexpectedly claims human labels")
    source_entry = (sealed.get("outputs") or {}).get("source_rows") or {}
    source_path = Path(source_entry.get("path", ""))
    if not source_path.is_file() or sha256(source_path) != source_entry.get("sha256"):
        raise ValueError("source rows do not match the sealed holdout manifest")

    merge = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if merge.get("artifact_type") != "rq2_typing_holdout_merge_manifest":
        raise ValueError("unexpected merge manifest artifact_type")
    sealed_entry = (merge.get("inputs") or {}).get("sealed_manifest") or {}
    if Path(sealed_entry.get("path", "")) != sealed_manifest_path:
        raise ValueError("merge manifest is not bound to the selected sealed holdout")
    if sha256(sealed_manifest_path) != sealed_entry.get("sha256"):
        raise ValueError("sealed holdout hash differs from the merge manifest")
    consensus_entry = (merge.get("outputs") or {}).get("consensus") or {}
    consensus_path = Path(consensus_entry.get("path", ""))
    if not consensus_path.is_file() or sha256(consensus_path) != consensus_entry.get(
        "sha256"
    ):
        raise ValueError("consensus rows do not match the merge manifest")
    return source_path, consensus_path


def main() -> int:
    args = parse_args()
    holdout_dir = resolve(args.holdout_dir)
    results_dir = resolve(args.results_dir)
    output_dir = resolve(args.output_dir)
    sealed_manifest_path = holdout_dir / "manifest.sealed.json"
    merge_manifest_path = results_dir / "merge_manifest.json"
    source_path, consensus_path = validate_bound_inputs(
        sealed_manifest_path, merge_manifest_path
    )
    source_rows = list(iter_jsonl(source_path))
    consensus_rows = list(iter_jsonl(consensus_path))
    if len(source_rows) != EXPECTED_ROWS or len(consensus_rows) != EXPECTED_ROWS:
        raise ValueError("expected 1250 source and consensus rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    consensus_ids = [row.get("sample_id") for row in consensus_rows]
    if source_ids != consensus_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source and consensus sample IDs must be unique and ordered identically")
    field_counts = Counter(row.get("field") for row in source_rows)
    if set(field_counts.values()) != {EXPECTED_ROWS_PER_FIELD}:
        raise ValueError("expected 250 rows for every holdout field")

    packet_rows = [packet_row(source) for source in source_rows]
    scheduler_rows = [
        schedule_row(source, consensus)
        for source, consensus in zip(source_rows, consensus_rows)
    ]
    scheduler_rows.sort(
        key=lambda row: (row["queue_tier"], row["within_tier_order_key"])
    )
    packet_path = output_dir / "rq2_typing_holdout_human_review.jsonl"
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
    with packet_path.open("w", encoding="utf-8") as handle:
        for row in packet_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    with scheduler_path.open("w", encoding="utf-8") as handle:
        for row in scheduler_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    tier_counts = Counter(row["queue_tier"] for row in scheduler_rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_typing_human_review_manifest",
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
        "source_merge_manifest": str(merge_manifest_path),
        "source_merge_manifest_sha256": sha256(merge_manifest_path),
        "source_non_human_consensus": str(consensus_path),
        "source_non_human_consensus_sha256": sha256(consensus_path),
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
        },
        "instructions": [
            "Two different real people independently label every row from the packet only.",
            "The author-only scheduler may control order but must not be shown to either reviewer.",
            "An author resolves the two labels and signs each row; source-bound fields must not be edited.",
            "The packet remains non-human provenance metadata; canonical promotion is a separate guarded step.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    readme_path.write_text(
        "# RQ2 Typing Human Review Packet\n\n"
        "This directory contains a blank, source-bound review packet for all 1,250 frozen RQ2 holdout rows. "
        "No baseline label, sampling stratum, non-human reviewer label, or consensus label appears in the review rows.\n\n"
        "## Required process\n\n"
        "1. A real human annotator labels every row from `rq2_typing_holdout_human_review.jsonl`.\n"
        "2. A different real human repeats the review independently without seeing the first decision.\n"
        "3. An author records the final resolution and signs each row.\n"
        "4. Run the fail-closed validator with `--require-complete` before any separate canonical promotion.\n\n"
        "`author_review_scheduler.jsonl` is optional author-only workflow metadata. It prioritizes unresolved non-human rows but contains no labels; do not expose it to annotators. "
        "The JSONL packet is authoritative. Human identity and independence must also be verified outside the file because a validator cannot prove that an ID belongs to a real person.\n",
        encoding="utf-8",
    )
    print(f"Wrote {packet_path}")
    print(f"Wrote {scheduler_path}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
