#!/usr/bin/env python3
"""Build a 20% second-pass RQ2 annotation consistency sample."""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_OUTPUT_DIR = "data/annotations/rq2/consistency_review"
DEFAULT_SEED = 20260524
DEFAULT_FRACTION = 0.20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sample RQ2 rows for second-pass consistency annotation."
    )
    parser.add_argument("--input-path", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--fraction", type=float, default=DEFAULT_FRACTION)
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


def json_cell(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def compact_json(value, max_chars: int = 420) -> str:
    text = json_cell(value)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def review_row(row: dict) -> dict:
    return {
        "review_sample_id": f"rq2_consistency:{row['sample_id'].split(':')[-1]}",
        "original_sample_id": row["sample_id"],
        "source_line_number": row["source_line_number"],
        "cve_id": row["cve_id"],
        "nvd_source_id": row["nvd_source_id"],
        "ghsa_source_id": row["ghsa_source_id"],
        "field": row["field"],
        "baseline_status": row["baseline_status"],
        "baseline_note": row["baseline_note"],
        "nvd_value": row["nvd_value"],
        "ghsa_value": row["ghsa_value"],
        "field_context": row.get("field_context"),
        "package_names": row.get("package_names"),
        "reference_context": row.get("reference_context"),
        "review_annotation": {
            "reviewer_status": "",
            "reviewer_rationale": "",
            "reviewer_notes": "",
        },
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "review_sample_id",
        "original_sample_id",
        "source_line_number",
        "cve_id",
        "nvd_source_id",
        "ghsa_source_id",
        "field",
        "baseline_status",
        "baseline_note",
        "nvd_value_json",
        "ghsa_value_json",
        "field_context_json",
        "package_names_json",
        "reference_context_json",
        "reviewer_status",
        "reviewer_rationale",
        "reviewer_notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            review = row["review_annotation"]
            writer.writerow(
                {
                    "review_sample_id": row["review_sample_id"],
                    "original_sample_id": row["original_sample_id"],
                    "source_line_number": row["source_line_number"],
                    "cve_id": row["cve_id"],
                    "nvd_source_id": row["nvd_source_id"],
                    "ghsa_source_id": row["ghsa_source_id"],
                    "field": row["field"],
                    "baseline_status": row["baseline_status"],
                    "baseline_note": row["baseline_note"],
                    "nvd_value_json": compact_json(row["nvd_value"]),
                    "ghsa_value_json": compact_json(row["ghsa_value"]),
                    "field_context_json": compact_json(row["field_context"]),
                    "package_names_json": compact_json(row["package_names"]),
                    "reference_context_json": compact_json(row["reference_context"]),
                    "reviewer_status": review["reviewer_status"],
                    "reviewer_rationale": review["reviewer_rationale"],
                    "reviewer_notes": review["reviewer_notes"],
                }
            )


def write_readme(path: Path, manifest: dict) -> None:
    path.write_text(
        "\n".join(
            [
                "# RQ2 Consistency Review Sample",
                "",
                "This directory contains a 20% second-pass annotation sample for RQ2 discrepancy typing.",
                "",
                "The review files are blank templates. They are not agreement results.",
                "",
                "## Files",
                "",
                "- `discrepancy_typing_consistency_review.jsonl`: full review template.",
                "- `discrepancy_typing_consistency_review.csv`: spreadsheet-friendly review template.",
                "- `sample_manifest.json`: sampling configuration and per-field counts.",
                "",
                "## Review Columns",
                "",
                "- `reviewer_status`: independent second-pass label.",
                "- `reviewer_rationale`: short reason for the second-pass label.",
                "- `reviewer_notes`: optional notes.",
                "",
                "Use `docs/annotation_guidelines/rq2_discrepancy_typing.md` for label definitions.",
                "",
                "## Sampling Summary",
                "",
                f"- Seed: `{manifest['seed']}`",
                f"- Fraction: `{manifest['fraction']}`",
                f"- Sampled rows: `{manifest['sampled_count']}`",
                "",
            ]
        ),
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    input_path = resolve_path(args.input_path)
    output_dir = resolve_path(args.output_dir)
    rows = list(iter_jsonl(input_path))
    if not rows:
        raise ValueError(f"No rows found in {input_path}")
    if not 0 < args.fraction <= 1:
        raise ValueError("--fraction must be in (0, 1]")

    rng = random.Random(args.seed)
    by_field = defaultdict(list)
    for row in rows:
        by_field[row["field"]].append(row)

    selected = []
    strata = []
    for field in sorted(by_field):
        candidates = by_field[field]
        sample_size = max(1, round(len(candidates) * args.fraction))
        sampled = rng.sample(candidates, sample_size)
        selected.extend(review_row(row) for row in sampled)
        strata.append(
            {
                "field": field,
                "candidate_count": len(candidates),
                "sampled_count": sample_size,
            }
        )
    selected.sort(key=lambda row: row["review_sample_id"])

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "discrepancy_typing_consistency_review.jsonl"
    csv_path = output_dir / "discrepancy_typing_consistency_review.csv"
    manifest_path = output_dir / "sample_manifest.json"
    readme_path = output_dir / "README.md"

    manifest = {
        "input_path": str(input_path),
        "output_dir": str(output_dir),
        "seed": args.seed,
        "fraction": args.fraction,
        "candidate_count": len(rows),
        "sampled_count": len(selected),
        "strata": strata,
        "sampled_distribution": dict(Counter(row["field"] for row in selected)),
        "cautions": [
            "This is a second-pass annotation template, not a completed agreement result.",
            "Do not report inter-annotator agreement until reviewer_status and original manual_status are both filled.",
        ],
        "jsonl_path": str(jsonl_path),
        "csv_path": str(csv_path),
        "readme_path": str(readme_path),
    }

    write_jsonl(jsonl_path, selected)
    write_csv(csv_path, selected)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    write_readme(readme_path, manifest)
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {csv_path}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
