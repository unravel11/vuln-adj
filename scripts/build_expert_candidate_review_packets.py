#!/usr/bin/env python3
"""Build isolated human-review packets from AI expert candidate labels."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = "data/annotations/expert_candidate/review_packets"
SCHEMA_VERSION = "expert_candidate_review_v1"

DATASETS = {
    "rq2_primary": {
        "task_kind": "rq2",
        "template": "data/annotations/rq2/discrepancy_typing_seed.jsonl",
        "candidate": "data/annotations/expert_candidate/raw/rq2_primary.jsonl",
        "template_id": "sample_id",
    },
    "rq2_review": {
        "task_kind": "rq2",
        "template": (
            "data/annotations/rq2/consistency_review/"
            "discrepancy_typing_consistency_review.jsonl"
        ),
        "candidate": "data/annotations/expert_candidate/raw/rq2_review.jsonl",
        "template_id": "review_sample_id",
    },
    "rq3_severity": {
        "task_kind": "rq3",
        "template": "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
        "candidate": "data/annotations/expert_candidate/raw/rq3_severity.jsonl",
        "template_id": "sample_id",
    },
    "rq3_affected_versions": {
        "task_kind": "rq3",
        "template": (
            "data/annotations/rq3/gold_audit/"
            "affected_versions_adjudication_audit.jsonl"
        ),
        "candidate": (
            "data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl"
        ),
        "template_id": "sample_id",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build review packets without modifying canonical gold templates."
    )
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing packets. Refused by default to protect human edits.",
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


def load_unique(path: Path, id_key: str) -> dict[str, dict]:
    rows = {}
    for line_number, row in iter_jsonl(path):
        sample_id = str(row.get(id_key) or "").strip()
        if not sample_id:
            raise ValueError(f"{path}:{line_number}: missing {id_key}")
        if sample_id in rows:
            raise ValueError(f"{path}:{line_number}: duplicate {id_key}={sample_id}")
        rows[sample_id] = row
    return rows


def empty_human_review(task_kind: str) -> dict:
    review = {
        "review_status": "pending",
        "final_label": "",
        "final_rationale": "",
        "is_baseline_correct": "",
        "needs_adjudication": "",
        "final_source": "",
        "final_value": "",
        "evidence_urls": [],
        "evidence_notes": "",
        "uncertainty_notes": "",
        "version_reasoning_type": "",
        "human_annotator_id": "",
        "independent_reviewer_id": "",
        "author_signoff": "pending",
        "reviewed_at": "",
        "review_notes": "",
    }
    if task_kind == "rq2":
        review["final_source"] = "abstain"
    return review


def make_packet(dataset: str, spec: dict, source: dict, candidate: dict) -> dict:
    if candidate.get("label_is_human") is not False:
        raise ValueError(f"{candidate.get('sample_id')}: candidate must be non-human")
    annotation = candidate.get("annotation") or {}
    sample_id = candidate["sample_id"]
    return {
        "schema_version": SCHEMA_VERSION,
        "dataset": dataset,
        "task_kind": spec["task_kind"],
        "packet_status": "pending_human_review",
        "label_is_human": False,
        "human_gold_eligible": False,
        "sample_id": sample_id,
        "original_sample_id": source.get("original_sample_id"),
        "cve_id": source.get("cve_id"),
        "field": source.get("field"),
        "baseline_status": source.get("baseline_status"),
        "baseline_note": source.get("baseline_note"),
        "nvd_value": source.get("nvd_value"),
        "ghsa_value": source.get("ghsa_value"),
        "field_context": source.get("field_context"),
        "package_names": source.get("package_names"),
        "reference_context": source.get("reference_context"),
        "nvd_context": source.get("nvd_context"),
        "ghsa_context": source.get("ghsa_context"),
        "evidence_summary": source.get("evidence_summary"),
        "ai_candidate": {
            "annotator_id": candidate.get("annotator_id"),
            "model": candidate.get("model"),
            "pass_id": candidate.get("pass_id"),
            "generated_at": candidate.get("generated_at"),
            "schedule": candidate.get("schedule", "input"),
            "discrepancy_label": annotation.get("discrepancy_label"),
            "adjudicated_source": annotation.get("adjudicated_source"),
            "adjudicated_value": annotation.get("adjudicated_value"),
            "evidence_urls": annotation.get("evidence_urls", []),
            "rationale": annotation.get("rationale"),
            "evidence_notes": annotation.get("evidence_notes"),
            "uncertainty_notes": annotation.get("uncertainty_notes"),
            "version_reasoning_type": annotation.get("version_reasoning_type"),
            "confidence": annotation.get("confidence"),
            "needs_human_review": annotation.get("needs_human_review"),
        },
        "human_review": empty_human_review(spec["task_kind"]),
        "provenance": {
            "source_template": spec["template"],
            "source_candidate": spec["candidate"],
        },
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def portable_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "sample_id",
        "original_sample_id",
        "cve_id",
        "field",
        "baseline_status",
        "nvd_value_json",
        "ghsa_value_json",
        "candidate_label",
        "candidate_source",
        "candidate_rationale",
        "candidate_confidence",
        "candidate_needs_human_review",
        "candidate_evidence_urls_json",
        "review_status",
        "final_label",
        "final_rationale",
        "is_baseline_correct",
        "needs_adjudication",
        "final_source",
        "final_value",
        "evidence_urls_json",
        "evidence_notes",
        "uncertainty_notes",
        "version_reasoning_type",
        "human_annotator_id",
        "independent_reviewer_id",
        "author_signoff",
        "reviewed_at",
        "review_notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            candidate = row["ai_candidate"]
            review = row["human_review"]
            writer.writerow(
                {
                    "sample_id": row["sample_id"],
                    "original_sample_id": row.get("original_sample_id") or "",
                    "cve_id": row.get("cve_id") or "",
                    "field": row.get("field") or "",
                    "baseline_status": row.get("baseline_status") or "",
                    "nvd_value_json": compact(row.get("nvd_value")),
                    "ghsa_value_json": compact(row.get("ghsa_value")),
                    "candidate_label": candidate.get("discrepancy_label") or "",
                    "candidate_source": candidate.get("adjudicated_source") or "",
                    "candidate_rationale": candidate.get("rationale") or "",
                    "candidate_confidence": candidate.get("confidence") or "",
                    "candidate_needs_human_review": candidate.get(
                        "needs_human_review"
                    ),
                    "candidate_evidence_urls_json": compact(
                        candidate.get("evidence_urls", [])
                    ),
                    "review_status": review["review_status"],
                    "final_label": review["final_label"],
                    "final_rationale": review["final_rationale"],
                    "is_baseline_correct": review["is_baseline_correct"],
                    "needs_adjudication": review["needs_adjudication"],
                    "final_source": review["final_source"],
                    "final_value": review["final_value"],
                    "evidence_urls_json": compact(review["evidence_urls"]),
                    "evidence_notes": review["evidence_notes"],
                    "uncertainty_notes": review["uncertainty_notes"],
                    "version_reasoning_type": review["version_reasoning_type"],
                    "human_annotator_id": review["human_annotator_id"],
                    "independent_reviewer_id": review[
                        "independent_reviewer_id"
                    ],
                    "author_signoff": review["author_signoff"],
                    "reviewed_at": review["reviewed_at"],
                    "review_notes": review["review_notes"],
                }
            )


def summarize(dataset: str, rows: list[dict], paths: dict) -> dict:
    return {
        "dataset": dataset,
        "candidate_rows": len(rows),
        "human_signed_rows": 0,
        "field_counts": dict(sorted(Counter(row["field"] for row in rows).items())),
        "candidate_label_counts": dict(
            sorted(
                Counter(
                    row["ai_candidate"]["discrepancy_label"] for row in rows
                ).items()
            )
        ),
        "candidate_source_counts": dict(
            sorted(
                Counter(
                    row["ai_candidate"]["adjudicated_source"] for row in rows
                ).items()
            )
        ),
        "needs_human_review_rows": sum(
            bool(row["ai_candidate"]["needs_human_review"]) for row in rows
        ),
        "jsonl_path": portable_path(paths["jsonl"]),
        "csv_path": portable_path(paths["csv"]),
    }


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label_is_human": False,
        "author_review_required": True,
        "human_gold_rows": 0,
        "datasets": [],
        "missing_candidate_datasets": [],
    }

    for dataset, spec in DATASETS.items():
        template_path = resolve_path(spec["template"])
        candidate_path = resolve_path(spec["candidate"])
        if not candidate_path.exists():
            manifest["missing_candidate_datasets"].append(dataset)
            continue
        source_rows = load_unique(template_path, spec["template_id"])
        candidate_rows = load_unique(candidate_path, "sample_id")
        missing = sorted(set(candidate_rows) - set(source_rows))
        if missing:
            raise ValueError(f"{dataset}: candidates missing from template: {missing[:5]}")
        rows = [
            make_packet(dataset, spec, source_rows[sample_id], candidate)
            for sample_id, candidate in candidate_rows.items()
        ]
        rows.sort(key=lambda row: row["sample_id"])
        paths = {
            "jsonl": output_dir / f"{dataset}.review.jsonl",
            "csv": output_dir / f"{dataset}.review.csv",
        }
        existing = [path for path in paths.values() if path.exists()]
        if existing and not args.overwrite:
            raise FileExistsError(
                f"Refusing to overwrite review packets: {existing}. Use --overwrite only before human edits."
            )
        write_jsonl(paths["jsonl"], rows)
        write_csv(paths["csv"], rows)
        manifest["datasets"].append(summarize(dataset, rows, paths))

    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists() and not args.overwrite:
        raise FileExistsError(f"Refusing to overwrite {manifest_path}")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    print("Boundary: review packets are not human-gold until signed human review passes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
