#!/usr/bin/env python3
"""Summarize bootstrap alignment coverage for RQ1."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_OUTPUT_DIR = "results/rq1_discrepancy_distribution"


FIELD_LABELS = {
    "summary": "summary",
    "published": "published_date",
    "last_modified": "last_modified_date",
    "severity": "severity",
    "cwe_ids": "cwe",
    "references": "references",
    "affected": "affected",
}


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute basic RQ1 coverage statistics from bootstrap alignments."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Aligned NVD-GHSA JSONL path.",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for JSON/Markdown summaries.",
    )
    return parser.parse_args()


def has_severity(record: dict | None) -> bool:
    if not record:
        return False
    severity = record.get("severity") or {}
    return any(severity.get(key) is not None for key in ("score", "label", "vector"))


def field_present(record: dict | None, field: str) -> bool:
    if not record:
        return False
    value = record.get(field)
    if field == "severity":
        return has_severity(record)
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    return value is not None


def compute_summary(input_path: Path) -> dict:
    total_rows = 0
    matched_rows = 0
    multi_ghsa_rows = 0

    year_totals: dict[str, int] = defaultdict(int)
    year_matched: dict[str, int] = defaultdict(int)

    field_stats = {
        label: {
            "nvd_nonempty": 0,
            "matched_nvd_nonempty": 0,
            "matched_ghsa_nonempty": 0,
            "matched_both_nonempty": 0,
            "matched_nvd_only": 0,
            "matched_ghsa_only": 0,
            "matched_both_empty": 0,
        }
        for label in FIELD_LABELS.values()
    }

    with input_path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            total_rows += 1

            cve_id = row.get("cve_id") or ""
            year = cve_id.split("-")[1] if cve_id.startswith("CVE-") and len(cve_id.split("-")) > 2 else "unknown"
            year_totals[year] += 1

            nvd_record = row.get("nvd") or {}
            ghsa_records = row.get("ghsa") or []
            matched = len(ghsa_records) > 0
            if matched:
                matched_rows += 1
                year_matched[year] += 1
            if len(ghsa_records) > 1:
                multi_ghsa_rows += 1

            for raw_field, label in FIELD_LABELS.items():
                nvd_has = field_present(nvd_record, raw_field)
                if nvd_has:
                    field_stats[label]["nvd_nonempty"] += 1

                if not matched:
                    continue

                if nvd_has:
                    field_stats[label]["matched_nvd_nonempty"] += 1

                ghsa_has = any(field_present(ghsa_record, raw_field) for ghsa_record in ghsa_records)
                if ghsa_has:
                    field_stats[label]["matched_ghsa_nonempty"] += 1

                if nvd_has and ghsa_has:
                    field_stats[label]["matched_both_nonempty"] += 1
                elif nvd_has:
                    field_stats[label]["matched_nvd_only"] += 1
                elif ghsa_has:
                    field_stats[label]["matched_ghsa_only"] += 1
                else:
                    field_stats[label]["matched_both_empty"] += 1

    matched_rate = matched_rows / total_rows if total_rows else 0.0
    year_summary = {}
    for year in sorted(year_totals):
        total = year_totals[year]
        matched = year_matched.get(year, 0)
        year_summary[year] = {
            "total_rows": total,
            "matched_rows": matched,
            "matched_rate": round(matched / total, 6) if total else 0.0,
        }

    for label, stats in field_stats.items():
        stats["nvd_nonempty_rate"] = round(stats["nvd_nonempty"] / total_rows, 6) if total_rows else 0.0
        stats["matched_nvd_nonempty_rate"] = (
            round(stats["matched_nvd_nonempty"] / matched_rows, 6)
            if matched_rows
            else 0.0
        )
        stats["matched_ghsa_nonempty_rate"] = (
            round(stats["matched_ghsa_nonempty"] / matched_rows, 6) if matched_rows else 0.0
        )
        stats["matched_both_nonempty_rate"] = (
            round(stats["matched_both_nonempty"] / matched_rows, 6) if matched_rows else 0.0
        )
        stats["matched_nvd_only_rate"] = (
            round(stats["matched_nvd_only"] / matched_rows, 6) if matched_rows else 0.0
        )
        stats["matched_ghsa_only_rate"] = (
            round(stats["matched_ghsa_only"] / matched_rows, 6) if matched_rows else 0.0
        )
        stats["matched_both_empty_rate"] = (
            round(stats["matched_both_empty"] / matched_rows, 6) if matched_rows else 0.0
        )
        if stats["matched_nvd_nonempty"] != (
            stats["matched_both_nonempty"] + stats["matched_nvd_only"]
        ):
            raise AssertionError(f"{label}: inconsistent matched NVD coverage counts")
        if stats["matched_ghsa_nonempty"] != (
            stats["matched_both_nonempty"] + stats["matched_ghsa_only"]
        ):
            raise AssertionError(f"{label}: inconsistent matched GHSA coverage counts")
        if matched_rows != (
            stats["matched_both_nonempty"]
            + stats["matched_nvd_only"]
            + stats["matched_ghsa_only"]
            + stats["matched_both_empty"]
        ):
            raise AssertionError(f"{label}: matched coverage partition does not sum")

    return {
        "input_path": str(input_path),
        "total_rows": total_rows,
        "matched_rows": matched_rows,
        "unmatched_rows": total_rows - matched_rows,
        "matched_rate": round(matched_rate, 6),
        "rows_with_multiple_ghsa": multi_ghsa_rows,
        "rows_with_multiple_ghsa_rate": round(multi_ghsa_rows / matched_rows, 6) if matched_rows else 0.0,
        "year_summary": year_summary,
        "field_coverage": field_stats,
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ1 Bootstrap Field Coverage",
        "",
        "## Alignment Coverage",
        "",
        f"- Total aligned rows: {summary['total_rows']}",
        f"- Matched rows: {summary['matched_rows']}",
        f"- Unmatched rows: {summary['unmatched_rows']}",
        f"- Matched rate: {summary['matched_rate']:.4%}",
        f"- Rows with multiple GHSA records: {summary['rows_with_multiple_ghsa']}",
        (
            "- Multi-GHSA rate among matched rows: "
            f"{summary['rows_with_multiple_ghsa_rate']:.4%}"
        ),
        "",
        "## Matched Rate by CVE Year",
        "",
        "| Year | Total | Matched | Matched Rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for year, stats in summary["year_summary"].items():
        lines.append(
            f"| {year} | {stats['total_rows']} | {stats['matched_rows']} | {stats['matched_rate']:.4%} |"
        )

    lines.extend(
        [
            "",
            "## Field Coverage on Matched Rows",
            "",
            "| Field | NVD Non-empty | GHSA Non-empty | Both Non-empty | NVD Only | GHSA Only | Both Empty |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for field, stats in summary["field_coverage"].items():
        lines.append(
            "| "
            f"{field} | "
            f"{stats['matched_nvd_nonempty_rate']:.4%} | "
            f"{stats['matched_ghsa_nonempty_rate']:.4%} | "
            f"{stats['matched_both_nonempty_rate']:.4%} | "
            f"{stats['matched_nvd_only_rate']:.4%} | "
            f"{stats['matched_ghsa_only_rate']:.4%} | "
            f"{stats['matched_both_empty_rate']:.4%} |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    input_path = resolve_path(args.input)
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = compute_summary(input_path)
    json_path = output_dir / "bootstrap_field_coverage_summary.json"
    md_path = output_dir / "bootstrap_field_coverage_summary.md"

    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")

    print(f"Wrote JSON summary: {json_path}")
    print(f"Wrote Markdown summary: {md_path}")
    print(
        "Alignment coverage: "
        f"{summary['matched_rows']}/{summary['total_rows']} matched "
        f"({summary['matched_rate']:.4%})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
