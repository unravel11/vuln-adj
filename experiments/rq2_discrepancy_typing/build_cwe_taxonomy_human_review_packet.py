#!/usr/bin/env python3
"""Build a blank three-stage human review packet for the 17 CWE impact rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_IMPACT_DIR = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/rq2/cwe_taxonomy_impact_human_review"
)
SCHEMA_VERSION = "rq2_cwe_taxonomy_human_review_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impact-dir", default=DEFAULT_IMPACT_DIR)
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


def empty_human_review() -> dict:
    return {
        "review_status": "pending",
        "annotator": {
            "human_id": "",
            "label": "",
            "rationale": "",
            "supporting_cwe_paths": [],
            "reviewed_at": "",
        },
        "independent_reviewer": {
            "human_id": "",
            "label": "",
            "rationale": "",
            "supporting_cwe_paths": [],
            "reviewed_at": "",
        },
        "resolution": {
            "final_label": "",
            "resolution_rationale": "",
            "author_id": "",
            "author_signoff": "pending",
            "signed_at": "",
        },
        "exclusion_reason": "",
    }


def packet_row(source: dict, priority_ids: set[str]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_cwe_taxonomy_human_review_packet",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "review_id": source["review_id"],
        "cve_id": source["cve_id"],
        "field": source["field"],
        "priority_audit": source["review_id"] in priority_ids,
        "nvd_value": source["nvd_value"],
        "ghsa_value": source["ghsa_value"],
        "vulnerability_context": source["vulnerability_context"],
        "official_cwe_entries": source["official_cwe_entries"],
        "official_cross_source_ancestor_descendant_paths": source[
            "official_cross_source_ancestor_descendant_paths"
        ],
        "taxonomy_source": source["taxonomy_source"],
        "human_review": empty_human_review(),
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "review_id",
        "cve_id",
        "priority_audit",
        "nvd_value_json",
        "ghsa_value_json",
        "vulnerability_context_json",
        "official_cwe_paths_json",
        "review_status",
        "annotator_human_id",
        "annotator_label",
        "annotator_rationale",
        "annotator_supporting_cwe_paths_json",
        "annotator_reviewed_at",
        "reviewer_human_id",
        "reviewer_label",
        "reviewer_rationale",
        "reviewer_supporting_cwe_paths_json",
        "reviewer_reviewed_at",
        "final_label",
        "resolution_rationale",
        "author_id",
        "author_signoff",
        "signed_at",
        "exclusion_reason",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            review = row["human_review"]
            annotator = review["annotator"]
            reviewer = review["independent_reviewer"]
            resolution = review["resolution"]
            paths = row["official_cross_source_ancestor_descendant_paths"]
            writer.writerow(
                {
                    "review_id": row["review_id"],
                    "cve_id": row["cve_id"],
                    "priority_audit": row["priority_audit"],
                    "nvd_value_json": json.dumps(row["nvd_value"]),
                    "ghsa_value_json": json.dumps(row["ghsa_value"]),
                    "vulnerability_context_json": json.dumps(
                        row["vulnerability_context"], ensure_ascii=False
                    ),
                    "official_cwe_paths_json": json.dumps(paths, ensure_ascii=False),
                    "review_status": review["review_status"],
                    "annotator_human_id": annotator["human_id"],
                    "annotator_label": annotator["label"],
                    "annotator_rationale": annotator["rationale"],
                    "annotator_supporting_cwe_paths_json": json.dumps(
                        annotator["supporting_cwe_paths"]
                    ),
                    "annotator_reviewed_at": annotator["reviewed_at"],
                    "reviewer_human_id": reviewer["human_id"],
                    "reviewer_label": reviewer["label"],
                    "reviewer_rationale": reviewer["rationale"],
                    "reviewer_supporting_cwe_paths_json": json.dumps(
                        reviewer["supporting_cwe_paths"]
                    ),
                    "reviewer_reviewed_at": reviewer["reviewed_at"],
                    "final_label": resolution["final_label"],
                    "resolution_rationale": resolution["resolution_rationale"],
                    "author_id": resolution["author_id"],
                    "author_signoff": resolution["author_signoff"],
                    "signed_at": resolution["signed_at"],
                    "exclusion_reason": review["exclusion_reason"],
                }
            )


def main() -> int:
    args = parse_args()
    impact_dir = resolve(args.impact_dir)
    output_dir = resolve(args.output_dir)
    worklist_path = impact_dir / "cwe_taxonomy_impact_worklist.blind.jsonl"
    priority_path = impact_dir / "cwe_taxonomy_human_priority_worklist.blind.jsonl"
    seal_path = impact_dir / "cwe_taxonomy_impact_manifest.sealed.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    if sha256(worklist_path) != seal["worklist"]["sha256"]:
        raise ValueError("blind worklist does not match sealed manifest")
    worklist = list(iter_jsonl(worklist_path))
    priority_ids = {row["review_id"] for row in iter_jsonl(priority_path)}
    if len(worklist) != 17 or len(priority_ids) != 9:
        raise ValueError("expected 17 packet rows and 9 priority rows")
    rows = [packet_row(row, priority_ids) for row in worklist]

    jsonl_path = output_dir / "cwe_taxonomy_impact_human_review.jsonl"
    csv_path = output_dir / "cwe_taxonomy_impact_human_review.csv"
    manifest_path = output_dir / "manifest.json"
    readme_path = output_dir / "README.md"
    existing = [
        path
        for path in (jsonl_path, csv_path, manifest_path, readme_path)
        if path.exists()
    ]
    if existing:
        raise FileExistsError(f"refusing to overwrite human review files: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    write_csv(csv_path, rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(rows),
        "priority_rows": len(priority_ids),
        "signed_human_rows": 0,
        "label_is_human": False,
        "source_seal": str(seal_path),
        "source_seal_sha256": sha256(seal_path),
        "source_worklist": str(worklist_path),
        "source_worklist_sha256": sha256(worklist_path),
        "source_priority_worklist": str(priority_path),
        "source_priority_worklist_sha256": sha256(priority_path),
        "jsonl_path": str(jsonl_path),
        "csv_path": str(csv_path),
        "instructions": [
            "The primary annotator should use the blind source worklist, not Codex consensus labels.",
            "The independent reviewer must use a different human_id.",
            "No row becomes canonical human gold until author_signoff=signed passes the validator.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    readme_path.write_text(
        "# CWE Taxonomy Human Review Packet\n\n"
        "This is a blank three-stage human review packet for all 17 taxonomy-v1 impact rows.\n\n"
        "1. A real human annotator labels from the sealed blind worklist.\n"
        "2. A different real human independently reviews the same row.\n"
        "3. An author resolves the row and signs it.\n\n"
        "Codex decisions are provenance only and must not be copied into human fields. "
        "The packet itself remains `label_is_human=false`; canonical promotion is a separate guarded step.\n\n"
        "Edit the JSONL file as the authoritative review record. The CSV is a read-only "
        "convenience view and is not imported by the validator.\n",
        encoding="utf-8",
    )
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {csv_path}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
