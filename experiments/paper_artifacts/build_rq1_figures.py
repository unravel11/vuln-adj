#!/usr/bin/env python3
"""Build RQ1 paper figures/tables from deterministic discrepancy stats."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from xml.sax.saxutils import escape


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DISCREPANCY_STATS = (
    "data/processed/bootstrap/discrepancies/field_discrepancy_stats.json"
)
DEFAULT_FIGURE_DIR = "paper/cose/figures"
DEFAULT_TABLE_DIR = "paper/cose/tables"

FIELDS = ("severity", "affected_versions", "published", "references", "cwe_ids")
DISCREPANCY_TYPES = (
    ("equivalent", "EQ"),
    ("representation_discrepancy", "RD"),
    ("incomplete", "INC"),
    ("temporal_discrepancy", "TD"),
    ("factual_conflict", "FC"),
)
TYPE_COLORS = {
    "equivalent": "#edf7ed",
    "representation_discrepancy": "#e7f0fa",
    "incomplete": "#fff2cc",
    "temporal_discrepancy": "#f3e8ff",
    "factual_conflict": "#fde7e9",
}
TEXT_DARK = "#1f2937"
TEXT_MUTED = "#4b5563"
GRID = "#d1d5db"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build RQ1 heatmap/table artifacts for the COSE draft."
    )
    parser.add_argument("--discrepancy-stats", default=DEFAULT_DISCREPANCY_STATS)
    parser.add_argument("--figure-dir", default=DEFAULT_FIGURE_DIR)
    parser.add_argument("--table-dir", default=DEFAULT_TABLE_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(count: int, total: int) -> str:
    return f"{count / total * 100:.1f}%" if total else "0.0%"


def build_rows(stats: dict) -> list[dict]:
    processed_pairs = stats["processed_pairs"]
    rows = []
    for field in FIELDS:
        counts = stats["fields"][field]
        row = {"field": field, "processed_pairs": processed_pairs}
        for dtype, _label in DISCREPANCY_TYPES:
            count = counts.get(dtype, 0)
            row[dtype] = count
            row[f"{dtype}_rate"] = count / processed_pairs if processed_pairs else 0.0
        rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = ["field", "processed_pairs"]
    for dtype, _label in DISCREPANCY_TYPES:
        fieldnames.extend([dtype, f"{dtype}_rate"])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def markdown_table(rows: list[dict]) -> str:
    headers = ["Field"] + [label for _dtype, label in DISCREPANCY_TYPES]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] + ["---:" for _ in headers[1:]]) + " |",
    ]
    for row in rows:
        values = [row["field"]]
        total = row["processed_pairs"]
        for dtype, _label in DISCREPANCY_TYPES:
            values.append(f"{row[dtype]} ({pct(row[dtype], total)})")
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def write_markdown(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(
            [
                "# RQ1 Discrepancy Distribution Table",
                "",
                "Generated from deterministic field discrepancy stats. Counts are baseline outputs, not gold labels.",
                "",
                markdown_table(rows),
                "",
            ]
        ),
        encoding="utf-8",
    )


def color_for_rate(dtype: str, rate: float) -> str:
    if rate == 0:
        return "#f9fafb"
    base = TYPE_COLORS[dtype]
    # Keep direct SVG generation simple and deterministic: use opacity for heat.
    return base


def text_color_for_rate(rate: float) -> str:
    return TEXT_DARK if rate < 0.55 else "#111827"


def write_heatmap_svg(path: Path, rows: list[dict]) -> None:
    cell_w = 150
    cell_h = 74
    left_w = 190
    top_h = 92
    legend_h = 82
    width = left_w + cell_w * len(DISCREPANCY_TYPES) + 40
    height = top_h + cell_h * len(rows) + legend_h

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="Field by discrepancy type heatmap">',
        "<style>",
        "text { font-family: Arial, Helvetica, sans-serif; }",
        ".title { font-size: 22px; font-weight: 700; fill: #111827; }",
        ".subtitle { font-size: 13px; fill: #4b5563; }",
        ".header { font-size: 13px; font-weight: 700; fill: #111827; }",
        ".field { font-size: 13px; font-weight: 700; fill: #111827; }",
        ".count { font-size: 16px; font-weight: 700; }",
        ".rate { font-size: 12px; fill: #374151; }",
        ".legend { font-size: 12px; fill: #374151; }",
        "</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="20" y="30" class="title">RQ1 Field-Level Discrepancy Distribution</text>',
        '<text x="20" y="52" class="subtitle">Deterministic baseline over 8,066 aligned NVD-GHSA pairs; values are counts and row percentages, not gold labels.</text>',
    ]

    for col_idx, (_dtype, label) in enumerate(DISCREPANCY_TYPES):
        x = left_w + col_idx * cell_w
        parts.append(
            f'<text x="{x + cell_w / 2}" y="{top_h - 18}" text-anchor="middle" class="header">{escape(label)}</text>'
        )
    for row_idx, row in enumerate(rows):
        y = top_h + row_idx * cell_h
        field_label = row["field"]
        parts.append(
            f'<text x="20" y="{y + cell_h / 2 + 5}" class="field">{escape(field_label)}</text>'
        )
        total = row["processed_pairs"]
        for col_idx, (dtype, _label) in enumerate(DISCREPANCY_TYPES):
            x = left_w + col_idx * cell_w
            count = row[dtype]
            rate = count / total if total else 0.0
            opacity = 0.18 + min(rate, 1.0) * 0.72 if rate else 1.0
            color = color_for_rate(dtype, rate)
            parts.extend(
                [
                    f'<rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" fill="{color}" fill-opacity="{opacity:.3f}" stroke="{GRID}" stroke-width="1"/>',
                    f'<text x="{x + cell_w / 2}" y="{y + 31}" text-anchor="middle" class="count" fill="{text_color_for_rate(rate)}">{count:,}</text>',
                    f'<text x="{x + cell_w / 2}" y="{y + 51}" text-anchor="middle" class="rate">{pct(count, total)}</text>',
                ]
            )

    legend_y = top_h + cell_h * len(rows) + 34
    parts.append(
        f'<text x="20" y="{legend_y}" class="legend">EQ=equivalent, RD=representation discrepancy, INC=incomplete, TD=temporal discrepancy, FC=factual conflict.</text>'
    )
    parts.append(
        f'<text x="20" y="{legend_y + 22}" class="legend">Cell intensity scales within the shared denominator of 8,066 aligned pairs.</text>'
    )
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    stats_path = resolve_path(args.discrepancy_stats)
    figure_dir = resolve_path(args.figure_dir)
    table_dir = resolve_path(args.table_dir)
    figure_dir.mkdir(parents=True, exist_ok=True)
    table_dir.mkdir(parents=True, exist_ok=True)

    rows = build_rows(read_json(stats_path))
    csv_path = table_dir / "rq1_discrepancy_distribution.csv"
    md_path = table_dir / "rq1_discrepancy_distribution.md"
    svg_path = figure_dir / "rq1_discrepancy_heatmap.svg"
    write_csv(csv_path, rows)
    write_markdown(md_path, rows)
    write_heatmap_svg(svg_path, rows)

    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {svg_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
