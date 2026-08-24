#!/usr/bin/env python3
"""Diagnose expert-candidate coverage bias and build a review priority list."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = "results/expert_candidate_validation"

DATASETS = {
    "rq2_primary": {
        "template": "data/annotations/rq2/discrepancy_typing_seed.jsonl",
        "template_id": "sample_id",
        "candidate": "data/annotations/expert_candidate/raw/rq2_primary.jsonl",
    },
    "rq2_review": {
        "template": (
            "data/annotations/rq2/consistency_review/"
            "discrepancy_typing_consistency_review.jsonl"
        ),
        "template_id": "review_sample_id",
        "candidate": "data/annotations/expert_candidate/raw/rq2_review.jsonl",
    },
    "rq3_severity": {
        "template": "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
        "template_id": "sample_id",
        "candidate": "data/annotations/expert_candidate/raw/rq3_severity.jsonl",
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
        ),
    },
    "rq3_affected_versions": {
        "template": (
            "data/annotations/rq3/gold_audit/"
            "affected_versions_adjudication_audit.jsonl"
        ),
        "template_id": "sample_id",
        "candidate": (
            "data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl"
        ),
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
        ),
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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
            raise ValueError(f"{path}:{line_number}: duplicate {sample_id}")
        rows[sample_id] = row
    return rows


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def contiguous_prefix_count(template_ids: list[str], candidate_ids: set[str]) -> int:
    count = 0
    for sample_id in template_ids:
        if sample_id not in candidate_ids:
            break
        count += 1
    return count


def silver_annotation(row: dict | None) -> dict:
    if not row:
        return {}
    return row.get("llm_annotation") or row.get("annotation") or {}


def priority_record(dataset: str, source: dict, candidate: dict, silver: dict) -> dict:
    annotation = candidate.get("annotation") or {}
    silver_label = silver.get("llm_label")
    silver_source = silver.get("adjudicated_source")
    candidate_label = annotation.get("discrepancy_label")
    candidate_source = annotation.get("adjudicated_source")
    reasons = []
    score = 0
    if annotation.get("needs_human_review"):
        score += 5
        reasons.append("candidate_requests_human_review")
    if candidate_label != source.get("baseline_status"):
        score += 2
        reasons.append("candidate_vs_baseline_label_mismatch")
    if silver_label and candidate_label != silver_label:
        score += 3
        reasons.append("candidate_vs_silver_label_mismatch")
    if silver_source and candidate_source != silver_source:
        score += 4
        reasons.append("candidate_vs_silver_source_mismatch")
    if annotation.get("confidence") in {"low", "medium"}:
        score += 1
        reasons.append("candidate_not_high_confidence")
    return {
        "dataset": dataset,
        "sample_id": candidate["sample_id"],
        "original_sample_id": source.get("original_sample_id"),
        "cve_id": source.get("cve_id"),
        "field": source.get("field"),
        "priority_score": score,
        "priority_reasons": reasons,
        "baseline_label": source.get("baseline_status"),
        "candidate_label": candidate_label,
        "candidate_source": candidate_source,
        "candidate_confidence": annotation.get("confidence"),
        "candidate_needs_human_review": annotation.get("needs_human_review"),
        "silver_label": silver_label,
        "silver_source": silver_source,
        "candidate_rationale": annotation.get("rationale"),
        "candidate_evidence_urls": annotation.get("evidence_urls", []),
    }


def analyze_dataset(name: str, spec: dict) -> tuple[dict, list[dict]]:
    template_path = resolve_path(spec["template"])
    candidate_path = resolve_path(spec["candidate"])
    template = load_unique(template_path, spec["template_id"])
    if not candidate_path.exists():
        return {
            "template_rows": len(template),
            "candidate_rows": 0,
            "coverage": 0.0,
            "candidate_file_present": False,
        }, []
    candidates = load_unique(candidate_path, "sample_id")
    missing = sorted(set(candidates) - set(template))
    if missing:
        raise ValueError(f"{name}: candidate IDs absent from template: {missing[:5]}")
    silver_rows = {}
    if spec.get("silver"):
        silver_rows = load_unique(resolve_path(spec["silver"]), "sample_id")

    template_field_counts = Counter(row.get("field") for row in template.values())
    candidate_field_counts = Counter(
        template[sample_id].get("field") for sample_id in candidates
    )
    by_field = {}
    for field in sorted(template_field_counts):
        by_field[field] = {
            "template_rows": template_field_counts[field],
            "candidate_rows": candidate_field_counts[field],
            "coverage": ratio(candidate_field_counts[field], template_field_counts[field]),
        }

    worklist = []
    for sample_id, candidate in candidates.items():
        silver = silver_annotation(silver_rows.get(sample_id))
        worklist.append(
            priority_record(name, template[sample_id], candidate, silver)
        )
    worklist.sort(key=lambda row: (-row["priority_score"], row["sample_id"]))

    label_disagreement = sum(
        "candidate_vs_silver_label_mismatch" in row["priority_reasons"]
        for row in worklist
    )
    source_disagreement = sum(
        "candidate_vs_silver_source_mismatch" in row["priority_reasons"]
        for row in worklist
    )
    template_ids = list(template)
    prefix_count = contiguous_prefix_count(template_ids, set(candidates))
    return {
        "template_rows": len(template),
        "candidate_rows": len(candidates),
        "coverage": ratio(len(candidates), len(template)),
        "candidate_file_present": True,
        "by_field": by_field,
        "contiguous_input_prefix_rows": prefix_count,
        "contiguous_input_prefix_fraction_of_candidates": ratio(
            prefix_count, len(candidates)
        ),
        "candidate_requests_human_review": sum(
            bool((row.get("annotation") or {}).get("needs_human_review"))
            for row in candidates.values()
        ),
        "candidate_vs_baseline_label_disagreements": sum(
            "candidate_vs_baseline_label_mismatch" in row["priority_reasons"]
            for row in worklist
        ),
        "candidate_vs_silver_label_disagreements": label_disagreement,
        "candidate_vs_silver_source_disagreements": source_disagreement,
        "candidate_vs_silver_label_agreement": (
            ratio(len(candidates) - label_disagreement, len(candidates))
            if silver_rows
            else None
        ),
        "candidate_vs_silver_source_agreement": (
            ratio(len(candidates) - source_disagreement, len(candidates))
            if silver_rows
            else None
        ),
        "priority_score_counts": dict(
            sorted(Counter(row["priority_score"] for row in worklist).items())
        ),
    }, worklist


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def render_markdown(metrics: dict) -> str:
    lines = [
        "# Expert Candidate Coverage and Review Priority",
        "",
        "These diagnostics measure candidate coverage and disagreement, not human-gold performance.",
        "",
        "| Dataset | Candidates | Template | Coverage | Prefix candidates | Needs review |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, values in metrics["datasets"].items():
        lines.append(
            f"| {name} | {values['candidate_rows']} | {values['template_rows']} | "
            f"{values['coverage']:.4f} | {values.get('contiguous_input_prefix_rows', 0)} | "
            f"{values.get('candidate_requests_human_review', 0)} |"
        )
    lines.extend(["", "## Field Coverage", ""])
    for name, values in metrics["datasets"].items():
        if not values.get("by_field"):
            continue
        lines.extend(
            [
                f"### {name}",
                "",
                "| Field | Candidates | Template | Coverage |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for field, field_values in values["by_field"].items():
            lines.append(
                f"| {field} | {field_values['candidate_rows']} | "
                f"{field_values['template_rows']} | {field_values['coverage']:.4f} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Boundary",
            "",
            "- Sequential or field-skewed partial candidates are not representative evaluation samples.",
            "- Disagreement prioritizes human review; it does not identify which label is correct.",
            "- `label_is_human=false` remains in force.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    datasets = {}
    worklist = []
    for name, spec in DATASETS.items():
        datasets[name], dataset_worklist = analyze_dataset(name, spec)
        worklist.extend(dataset_worklist)
    worklist.sort(
        key=lambda row: (-row["priority_score"], row["dataset"], row["sample_id"])
    )
    metrics = {
        "artifact_type": "expert_candidate_coverage_diagnostic",
        "label_is_human": False,
        "human_review_required": True,
        "datasets": datasets,
        "priority_worklist_rows": len(worklist),
        "positive_priority_rows": sum(row["priority_score"] > 0 for row in worklist),
    }
    json_path = output_dir / "expert_candidate_coverage_diagnostics.json"
    md_path = output_dir / "expert_candidate_coverage_diagnostics.md"
    worklist_path = output_dir / "expert_candidate_review_priority.jsonl"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    write_jsonl(worklist_path, worklist)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"Wrote {worklist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
