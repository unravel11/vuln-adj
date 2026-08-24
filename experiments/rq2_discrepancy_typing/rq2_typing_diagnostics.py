#!/usr/bin/env python3
"""Build non-gold RQ2 discrepancy-typing diagnostics.

This script compares the existing five-class deterministic typing output with
coarser diagnostic views. It does not evaluate accuracy because the planned
human gold set is not available yet.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"

DISCREPANCY_TYPES = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
AMBIGUOUS_AS_DIFFERENT = {
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build non-gold RQ2 discrepancy-typing diagnostics."
    )
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
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


def pct(count: int, total: int, digits: int = 1) -> str:
    if not total:
        return f"{0:.{digits}f}%"
    return f"{count / total * 100:.{digits}f}%"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] + ["---:" for _ in headers[1:]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def summarize_value(value) -> str:
    if isinstance(value, list):
        if len(value) > 3:
            return json.dumps(value[:3], ensure_ascii=False) + f" ... (+{len(value) - 3})"
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def example_record(row: dict, field: str, result: dict) -> dict:
    return {
        "cve_id": row["cve_id"],
        "field": field,
        "status": result["status"],
        "note": result.get("note", ""),
        "nvd_value": summarize_value(result.get("nvd_value")),
        "ghsa_value": summarize_value(result.get("ghsa_value")),
    }


def build_diagnostics(field_views_path: Path) -> dict:
    status_by_field: dict[str, Counter] = defaultdict(Counter)
    note_by_field_status: dict[str, dict[str, Counter]] = defaultdict(
        lambda: defaultdict(Counter)
    )
    rule_triggers = Counter()
    examples: dict[str, dict[str, dict]] = defaultdict(dict)
    row_count = 0

    for row in iter_jsonl(field_views_path):
        row_count += 1
        for field, result in row.get("field_discrepancies", {}).items():
            status = result["status"]
            note = result.get("note", "")
            status_by_field[field][status] += 1
            note_by_field_status[field][status][note] += 1
            rule_triggers[(field, status, note)] += 1
            examples.setdefault(field, {})
            if status not in examples[field]:
                examples[field][status] = example_record(row, field, result)

    field_summaries = []
    all_status_counts = Counter()
    for field in sorted(status_by_field):
        counts = status_by_field[field]
        total = sum(counts.values())
        all_status_counts.update(counts)
        non_equivalent = total - counts.get("equivalent", 0)
        non_conflict_different = sum(counts.get(item, 0) for item in AMBIGUOUS_AS_DIFFERENT)
        factual_conflict = counts.get("factual_conflict", 0)
        field_summaries.append(
            {
                "field": field,
                "total": total,
                **{status: counts.get(status, 0) for status in DISCREPANCY_TYPES},
                "binary_different": non_equivalent,
                "binary_different_rate": non_equivalent / total if total else 0.0,
                "non_conflict_different": non_conflict_different,
                "non_conflict_different_rate": (
                    non_conflict_different / non_equivalent if non_equivalent else 0.0
                ),
                "factual_conflict_among_different_rate": (
                    factual_conflict / non_equivalent if non_equivalent else 0.0
                ),
            }
        )

    total_field_instances = sum(all_status_counts.values())
    total_binary_different = total_field_instances - all_status_counts.get("equivalent", 0)
    total_non_conflict_different = sum(
        all_status_counts.get(item, 0) for item in AMBIGUOUS_AS_DIFFERENT
    )

    note_summaries = {}
    for field, by_status in note_by_field_status.items():
        note_summaries[field] = {
            status: [
                {"note": note, "count": count}
                for note, count in notes.most_common(5)
            ]
            for status, notes in by_status.items()
        }

    return {
        "source_path": str(field_views_path),
        "cautions": [
            "This is a diagnostic comparison against deterministic labels, not a gold-label evaluation.",
            "No accuracy, macro-F1, precision, or recall should be claimed from this artifact.",
        ],
        "row_count": row_count,
        "field_instance_count": total_field_instances,
        "overall": {
            **{
                status: all_status_counts.get(status, 0)
                for status in DISCREPANCY_TYPES
            },
            "binary_different": total_binary_different,
            "non_conflict_different": total_non_conflict_different,
            "non_conflict_different_rate_among_binary_different": (
                total_non_conflict_different / total_binary_different
                if total_binary_different
                else 0.0
            ),
            "factual_conflict_rate_among_binary_different": (
                all_status_counts.get("factual_conflict", 0) / total_binary_different
                if total_binary_different
                else 0.0
            ),
        },
        "fields": field_summaries,
        "top_notes": note_summaries,
        "rule_triggers": [
            {
                "field": field,
                "status": status,
                "note": note,
                "count": count,
            }
            for (field, status, note), count in sorted(
                rule_triggers.items(),
                key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2]),
            )
        ],
        "examples": examples,
    }


def render_markdown(diagnostics: dict) -> str:
    lines = [
        "# RQ2 Discrepancy Typing Diagnostics",
        "",
        "This artifact is generated from the deterministic field-view output. It is a readiness/diagnostic view, not a gold-label evaluation.",
        "",
        f"- Source: `{diagnostics['source_path']}`",
        f"- Aligned pair rows: {diagnostics['row_count']}",
        f"- Field instances: {diagnostics['field_instance_count']}",
        f"- Binary-different instances: {diagnostics['overall']['binary_different']}",
        f"- Non-conflict differences among binary-different instances: {diagnostics['overall']['non_conflict_different']} ({diagnostics['overall']['non_conflict_different_rate_among_binary_different']:.1%})",
        f"- Factual conflicts among binary-different instances: {diagnostics['overall']['factual_conflict']} ({diagnostics['overall']['factual_conflict_rate_among_binary_different']:.1%})",
        "",
        "## Field Summary",
        "",
        table(
            [
                "Field",
                "Different",
                "Non-conflict different",
                "FC among different",
                "EQ",
                "RD",
                "INC",
                "TD",
                "FC",
            ],
            [
                [
                    field["field"],
                    f"{field['binary_different']} ({pct(field['binary_different'], field['total'])})",
                    f"{field['non_conflict_different']} ({field['non_conflict_different_rate']:.1%})",
                    f"{field['factual_conflict']} ({field['factual_conflict_among_different_rate']:.1%})",
                    str(field["equivalent"]),
                    str(field["representation_discrepancy"]),
                    str(field["incomplete"]),
                    str(field["temporal_discrepancy"]),
                    str(field["factual_conflict"]),
                ]
                for field in diagnostics["fields"]
            ],
        ),
        "",
        "## Top Rule Triggers",
        "",
        table(
            ["Field", "Status", "Rule note", "Count"],
            [
                [
                    item["field"],
                    item["status"],
                    item["note"],
                    str(item["count"]),
                ]
                for item in diagnostics["rule_triggers"][:12]
            ],
        ),
        "",
        "## Example Deterministic Labels",
        "",
    ]

    for field in sorted(diagnostics["examples"]):
        lines.extend([f"### {field}", ""])
        rows = []
        for status in DISCREPANCY_TYPES:
            example = diagnostics["examples"][field].get(status)
            if not example:
                continue
            rows.append(
                [
                    status,
                    example["cve_id"],
                    example["note"],
                    example["nvd_value"],
                    example["ghsa_value"],
                ]
            )
        lines.extend(
            [
                table(["Status", "CVE", "Rule note", "NVD value", "GHSA value"], rows),
                "",
            ]
        )

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    field_views_path = resolve_path(args.field_views)
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    diagnostics = build_diagnostics(field_views_path)
    json_path = output_dir / "rq2_typing_diagnostics.json"
    md_path = output_dir / "rq2_typing_diagnostics.md"
    json_path.write_text(
        json.dumps(diagnostics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(diagnostics), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
