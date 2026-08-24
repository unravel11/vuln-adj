#!/usr/bin/env python3
"""Build blank human-audit templates for RQ3 adjudication."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = "data/annotations/rq3/gold_audit"

DATASETS = {
    "severity": {
        "evidence": "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
        ),
        "jsonl": "severity_adjudication_audit.jsonl",
        "csv": "severity_adjudication_audit.csv",
    },
    "affected_versions": {
        "evidence": "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
        ),
        "jsonl": "affected_versions_adjudication_audit.jsonl",
        "csv": "affected_versions_adjudication_audit.csv",
    },
}

SCHEMA_VERSION = "rq3_human_audit_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build RQ3 human-audit templates.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate sample_id in {path}: {sample_id}")
        rows[sample_id] = row
    return rows


def json_cell(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def compact_json(value, max_chars: int = 520) -> str:
    text = json_cell(value)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def evidence_summary(row: dict) -> dict:
    status_counts = Counter()
    ok_hosts = Counter()
    ok_urls = []
    for record in row.get("evidence_context", {}).get("records", []):
        status = record.get("fetch_status") or "missing"
        status_counts[status] += 1
        if status == "ok":
            ok_hosts[record.get("host") or ""] += 1
            ok_urls.append(record.get("url"))
    return {
        "candidate_url_count": row.get("evidence_context", {}).get("candidate_url_count", 0),
        "fetch_status_counts": dict(sorted(status_counts.items())),
        "top_ok_hosts": [host for host, _count in ok_hosts.most_common(5)],
        "ok_url_count": len(ok_urls),
        "first_ok_urls": ok_urls[:5],
    }


def build_row(field: str, evidence_row: dict, silver_row: dict, spec: dict) -> dict:
    silver_annotation = silver_row["llm_annotation"]
    row = {
        "schema_version": SCHEMA_VERSION,
        "sample_id": evidence_row["sample_id"],
        "source_line_number": evidence_row.get("source_line_number"),
        "cve_id": evidence_row["cve_id"],
        "nvd_source_id": evidence_row.get("nvd_source_id"),
        "ghsa_source_id": evidence_row.get("ghsa_source_id"),
        "field": field,
        "source_evidence_path": str(resolve_path(spec["evidence"])),
        "silver_v2_path": str(resolve_path(spec["silver"])),
        "baseline_status": evidence_row.get("baseline_status"),
        "baseline_note": evidence_row.get("baseline_note"),
        "nvd_value": evidence_row.get("nvd_value"),
        "ghsa_value": evidence_row.get("ghsa_value"),
        "nvd_context": evidence_row.get("nvd_context"),
        "ghsa_context": evidence_row.get("ghsa_context"),
        "evidence_summary": evidence_summary(evidence_row),
        "silver_v2_annotation": {
            "llm_label": silver_annotation.get("llm_label"),
            "is_baseline_false_positive": silver_annotation.get(
                "is_baseline_false_positive"
            ),
            "adjudicated_source": silver_annotation.get("adjudicated_source"),
            "adjudicated_value": silver_annotation.get("adjudicated_value"),
            "evidence_urls": silver_annotation.get("evidence_urls", []),
            "confidence": silver_annotation.get("confidence"),
        },
        "human_audit": {
            "audit_status": "draft",
            "human_label": "",
            "is_baseline_false_positive": "",
            "adjudicated_source": "",
            "adjudicated_value": "",
            "evidence_urls": [],
            "evidence_notes": "",
            "uncertainty_notes": "",
            "annotator_id": "",
            "reviewer_id": "",
            "review_status": "not_reviewed",
            "audited_at": "",
        },
    }
    if field == "affected_versions":
        row["human_audit"]["version_reasoning_type"] = ""
    return row


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "sample_id",
        "source_line_number",
        "cve_id",
        "nvd_source_id",
        "ghsa_source_id",
        "field",
        "baseline_status",
        "baseline_note",
        "nvd_value_json",
        "ghsa_value_json",
        "evidence_summary_json",
        "silver_llm_label",
        "silver_is_baseline_false_positive",
        "silver_adjudicated_source",
        "silver_confidence",
        "audit_status",
        "human_label",
        "is_baseline_false_positive",
        "adjudicated_source",
        "adjudicated_value",
        "evidence_urls",
        "evidence_notes",
        "uncertainty_notes",
        "version_reasoning_type",
        "annotator_id",
        "reviewer_id",
        "review_status",
        "audited_at",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            human = row["human_audit"]
            silver = row["silver_v2_annotation"]
            writer.writerow(
                {
                    "sample_id": row["sample_id"],
                    "source_line_number": row["source_line_number"],
                    "cve_id": row["cve_id"],
                    "nvd_source_id": row["nvd_source_id"],
                    "ghsa_source_id": row["ghsa_source_id"],
                    "field": row["field"],
                    "baseline_status": row["baseline_status"],
                    "baseline_note": row["baseline_note"],
                    "nvd_value_json": compact_json(row["nvd_value"]),
                    "ghsa_value_json": compact_json(row["ghsa_value"]),
                    "evidence_summary_json": compact_json(row["evidence_summary"]),
                    "silver_llm_label": silver["llm_label"],
                    "silver_is_baseline_false_positive": silver[
                        "is_baseline_false_positive"
                    ],
                    "silver_adjudicated_source": silver["adjudicated_source"],
                    "silver_confidence": silver["confidence"],
                    "audit_status": human["audit_status"],
                    "human_label": human["human_label"],
                    "is_baseline_false_positive": human["is_baseline_false_positive"],
                    "adjudicated_source": human["adjudicated_source"],
                    "adjudicated_value": human["adjudicated_value"],
                    "evidence_urls": "",
                    "evidence_notes": human["evidence_notes"],
                    "uncertainty_notes": human["uncertainty_notes"],
                    "version_reasoning_type": human.get("version_reasoning_type", ""),
                    "annotator_id": human["annotator_id"],
                    "reviewer_id": human["reviewer_id"],
                    "review_status": human["review_status"],
                    "audited_at": human["audited_at"],
                }
            )


def write_readme(path: Path, manifest: dict) -> None:
    lines = [
        "# RQ3 Human Audit Templates",
        "",
        "This directory contains blank human-audit templates for RQ3 adjudication.",
        "The templates are built from evidence-aware `silver_v2` artifacts, but the silver labels are provenance only.",
        "",
        "Do not report RQ3 gold-backed performance until the `human_audit` fields are filled and the guarded evaluator succeeds.",
        "",
        "## Files",
        "",
        "- `severity_adjudication_audit.jsonl/.csv`: severity adjudication audit template.",
        "- `affected_versions_adjudication_audit.jsonl/.csv`: affected_versions adjudication audit template.",
        "- `sample_manifest.json`: source paths and row counts.",
        "",
        "## Required Human Fields",
        "",
        "- `audit_status`: use `final` only when the row is complete, or `exclude` when it should not be evaluated.",
        "- `human_label`: equivalent, representation_discrepancy, incomplete, temporal_discrepancy, factual_conflict, or uncertain.",
        "- `is_baseline_false_positive`: yes, no, or uncertain.",
        "- `adjudicated_source`: nvd, ghsa, both, neither, or abstain.",
        "- `evidence_urls`: required unless the row is uncertain or abstain.",
        "- `annotator_id` and `audited_at`: required for final rows.",
        "- `review_status=reviewed` and a non-empty `reviewer_id` distinct from `annotator_id`: required before a final row can enter human-gold evaluation.",
        "- `version_reasoning_type`: affected_versions only; token_support, range_semantic, package_identity, insufficient_evidence, or not_applicable.",
        "",
        "## Guarded Evaluation",
        "",
        "The guarded evaluator refuses these templates while all rows are draft:",
        "",
        "```bash",
        "python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field severity",
        "python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field affected_versions",
        "```",
        "",
        "It writes `*_gold_audit_eval_metrics.*` only after valid `audit_status=final` rows exist.",
        "",
        "## Current Counts",
        "",
    ]
    for item in manifest["datasets"]:
        lines.append(f"- `{item['field']}`: `{item['row_count']}` blank audit rows")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "output_dir": str(output_dir),
        "datasets": [],
        "cautions": [
            "These files are blank human-audit templates, not completed gold labels.",
            "silver_v2 annotations are included only as provenance/context.",
            "Old URL-only LLM drafts under data/annotations/phase_d/llm_drafts must not be used as evaluation labels.",
            "Affected_versions audit must distinguish token support from semantic version-range adjudication.",
        ],
    }

    for field, spec in DATASETS.items():
        evidence_path = resolve_path(spec["evidence"])
        silver_path = resolve_path(spec["silver"])
        evidence_rows = load_by_sample_id(evidence_path)
        silver_rows = load_by_sample_id(silver_path)
        if set(evidence_rows) != set(silver_rows):
            raise ValueError(f"Evidence/silver sample_id mismatch for {field}")
        rows = [
            build_row(field, evidence_rows[sample_id], silver_rows[sample_id], spec)
            for sample_id in sorted(evidence_rows)
        ]
        jsonl_path = output_dir / spec["jsonl"]
        csv_path = output_dir / spec["csv"]
        write_jsonl(jsonl_path, rows)
        write_csv(csv_path, rows)
        manifest["datasets"].append(
            {
                "field": field,
                "source_evidence_path": str(evidence_path),
                "silver_v2_path": str(silver_path),
                "row_count": len(rows),
                "jsonl_path": str(jsonl_path),
                "csv_path": str(csv_path),
            }
        )

    manifest_path = output_dir / "sample_manifest.json"
    manifest["readme_path"] = str(output_dir / "README.md")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_readme(output_dir / "README.md", manifest)
    print(f"RQ3 audit templates written under: {output_dir}")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
