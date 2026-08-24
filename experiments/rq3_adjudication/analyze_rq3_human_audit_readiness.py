#!/usr/bin/env python3
"""Summarize RQ3 human-audit template readiness without evaluating metrics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"

DATASETS = {
    "severity": {
        "audit_input": "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
        "evidence_input": "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
        "expected_rows": 80,
    },
    "affected_versions": {
        "audit_input": "data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.jsonl",
        "evidence_input": "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        "expected_rows": 100,
    },
}

REQUIRED_FINAL_FIELDS = (
    "human_label",
    "is_baseline_false_positive",
    "adjudicated_source",
    "annotator_id",
    "reviewer_id",
    "audited_at",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize blank/final RQ3 human-audit template readiness."
    )
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


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for line_number, row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id:
            raise ValueError(f"{path}:{line_number}: missing sample_id")
        if sample_id in rows:
            raise ValueError(f"{path}:{line_number}: duplicate sample_id {sample_id}")
        rows[sample_id] = row
    return rows


def evidence_status_summary(row: dict) -> tuple[Counter, int]:
    statuses = Counter()
    ok_records = 0
    for record in row.get("evidence_context", {}).get("records", []):
        status = record.get("fetch_status") or "missing"
        statuses[status] += 1
        if status == "ok":
            ok_records += 1
    return statuses, ok_records


def missing_required_fields(human: dict) -> list[str]:
    missing = [field for field in REQUIRED_FINAL_FIELDS if not human.get(field)]
    if human.get("review_status") != "reviewed":
        missing.append("review_status=reviewed")
    if (
        human.get("annotator_id")
        and human.get("reviewer_id")
        and human["annotator_id"] == human["reviewer_id"]
    ):
        missing.append("independent_reviewer_id")
    if human.get("adjudicated_source") not in {"abstain", "uncertain"}:
        if not human.get("evidence_urls"):
            missing.append("evidence_urls")
        if not str(human.get("evidence_notes") or "").strip():
            missing.append("evidence_notes")
    return missing


def priority_reasons(row: dict, evidence_row: dict | None) -> list[str]:
    reasons = []
    silver = row.get("silver_v2_annotation") or {}
    human = row.get("human_audit") or {}
    ok_records = row.get("evidence_summary", {}).get("ok_url_count", 0)
    if evidence_row:
        _, ok_records = evidence_status_summary(evidence_row)

    if ok_records == 0:
        reasons.append("no_ok_evidence")
    elif ok_records <= 1:
        reasons.append("low_ok_evidence")
    if silver.get("adjudicated_source") in {"abstain", "neither", "uncertain"}:
        reasons.append("silver_no_source_selection")
    if silver.get("llm_label") == "uncertain":
        reasons.append("silver_uncertain_label")
    if silver.get("is_baseline_false_positive") == "uncertain":
        reasons.append("silver_uncertain_false_positive")
    if silver.get("confidence") == "low":
        reasons.append("silver_low_confidence")
    if (human.get("audit_status") or "draft") == "draft":
        reasons.append("human_label_blank")
    return reasons


def analyze_field(field: str, spec: dict) -> dict:
    audit_path = resolve_path(spec["audit_input"])
    evidence_path = resolve_path(spec["evidence_input"])
    audit_rows = load_by_sample_id(audit_path)
    evidence_rows = load_by_sample_id(evidence_path)

    status_counts = Counter()
    blank_required = 0
    silver_labels = Counter()
    silver_sources = Counter()
    silver_confidence = Counter()
    evidence_statuses = Counter()
    samples_with_ok = 0
    total_ok_records = 0
    priority_counts = Counter()
    worklist = []

    missing_evidence_sample_ids = sorted(set(audit_rows) - set(evidence_rows))
    extra_evidence_sample_ids = sorted(set(evidence_rows) - set(audit_rows))

    for sample_id, row in sorted(audit_rows.items()):
        human = row.get("human_audit") or {}
        status = human.get("audit_status") or "<blank>"
        status_counts[status] += 1
        missing_fields = missing_required_fields(human)
        if missing_fields:
            blank_required += 1

        silver = row.get("silver_v2_annotation") or {}
        silver_labels[silver.get("llm_label") or "missing"] += 1
        silver_sources[silver.get("adjudicated_source") or "missing"] += 1
        silver_confidence[silver.get("confidence") or "missing"] += 1

        evidence_row = evidence_rows.get(sample_id)
        ok_records = row.get("evidence_summary", {}).get("ok_url_count", 0)
        if evidence_row:
            statuses, ok_records = evidence_status_summary(evidence_row)
            evidence_statuses.update(statuses)
        if ok_records:
            samples_with_ok += 1
            total_ok_records += ok_records

        reasons = priority_reasons(row, evidence_row)
        priority_counts.update(reasons)
        if reasons:
            worklist.append(
                {
                    "sample_id": sample_id,
                    "cve_id": row.get("cve_id"),
                    "field": field,
                    "audit_status": status,
                    "silver_label": silver.get("llm_label") or "",
                    "silver_source": silver.get("adjudicated_source") or "",
                    "silver_confidence": silver.get("confidence") or "",
                    "ok_evidence_records": ok_records,
                    "priority_reasons": reasons,
                    "missing_required_human_fields": missing_fields,
                }
            )

    worklist.sort(
        key=lambda item: (
            -len(item["priority_reasons"]),
            item["ok_evidence_records"],
            item["sample_id"],
        )
    )

    row_count = len(audit_rows)
    final_count = status_counts.get("final", 0)
    return {
        "field": field,
        "audit_input": str(audit_path),
        "evidence_input": str(evidence_path),
        "expected_rows": spec["expected_rows"],
        "audit_row_count": row_count,
        "evidence_row_count": len(evidence_rows),
        "missing_evidence_sample_ids": missing_evidence_sample_ids,
        "extra_evidence_sample_ids": extra_evidence_sample_ids,
        "audit_status_counts": dict(sorted(status_counts.items())),
        "final_row_count": final_count,
        "draft_row_count": status_counts.get("draft", 0),
        "exclude_row_count": status_counts.get("exclude", 0),
        "blank_required_human_field_rows": blank_required,
        "ready_for_gold_evaluation": (
            final_count == row_count
            and row_count == spec["expected_rows"]
            and not missing_evidence_sample_ids
            and not extra_evidence_sample_ids
            and blank_required == 0
        ),
        "samples_with_ok_evidence": samples_with_ok,
        "samples_with_ok_evidence_rate": samples_with_ok / row_count if row_count else 0,
        "mean_ok_evidence_records": total_ok_records / row_count if row_count else 0,
        "evidence_fetch_status_counts": dict(sorted(evidence_statuses.items())),
        "silver_label_counts": dict(sorted(silver_labels.items())),
        "silver_source_counts": dict(sorted(silver_sources.items())),
        "silver_confidence_counts": dict(sorted(silver_confidence.items())),
        "priority_reason_counts": dict(sorted(priority_counts.items())),
        "priority_worklist_top": worklist[:20],
        "priority_worklist_count": len(worklist),
    }


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_markdown(artifact: dict) -> str:
    fields = artifact["fields"]
    lines = [
        "# RQ3 Human-Audit Readiness",
        "",
        "This diagnostic summarizes blank human-audit templates and evidence coverage. It is not a gold-label evaluation and writes no adjudication metrics.",
        "",
        table(
            [
                "Field",
                "Rows",
                "Final",
                "Draft",
                "Blank required",
                "OK evidence",
                "Ready",
            ],
            [
                [
                    field,
                    str(values["audit_row_count"]),
                    str(values["final_row_count"]),
                    str(values["draft_row_count"]),
                    str(values["blank_required_human_field_rows"]),
                    f"{values['samples_with_ok_evidence']}/{values['audit_row_count']}",
                    str(values["ready_for_gold_evaluation"]),
                ]
                for field, values in fields.items()
            ],
        ),
        "",
        "## Priority Signals",
        "",
    ]

    for field, values in fields.items():
        lines.extend(
            [
                f"### {field}",
                "",
                table(
                    ["Reason", "Rows"],
                    [
                        [reason, str(count)]
                        for reason, count in values["priority_reason_counts"].items()
                    ],
                ),
                "",
                "Top deterministic worklist rows:",
                "",
                table(
                    [
                        "Sample",
                        "CVE",
                        "Silver label",
                        "Silver source",
                        "OK evidence",
                        "Reasons",
                    ],
                    [
                        [
                            row["sample_id"],
                            row["cve_id"],
                            row["silver_label"],
                            row["silver_source"],
                            str(row["ok_evidence_records"]),
                            ", ".join(row["priority_reasons"]),
                        ]
                        for row in values["priority_worklist_top"][:8]
                    ],
                ),
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    fields = {field: analyze_field(field, spec) for field, spec in DATASETS.items()}
    artifact = {
        "schema_version": 1,
        "task": "rq3_human_audit_readiness",
        "metric_scope": "human_audit_template_readiness_only",
        "gold_label_evaluation": False,
        "cautions": [
            "This artifact summarizes blank audit-template readiness, not human-gold performance.",
            "Rows with silver abstain, uncertain labels, or low evidence are prioritization signals only.",
            "The guarded human-audit evaluator remains the authority for gold-backed metrics.",
        ],
        "fields": fields,
        "ready_for_gold_evaluation": all(
            values["ready_for_gold_evaluation"] for values in fields.values()
        ),
    }

    json_path = output_dir / "rq3_human_audit_readiness.json"
    md_path = output_dir / "rq3_human_audit_readiness.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
