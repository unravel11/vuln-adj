#!/usr/bin/env python3
"""Evaluate RQ2 annotation consistency after second-pass labels are complete."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIMARY = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_REVIEW = (
    "data/annotations/rq2/consistency_review/"
    "discrepancy_typing_consistency_review.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate RQ2 primary/review annotation consistency."
    )
    parser.add_argument("--primary-path", default=DEFAULT_PRIMARY)
    parser.add_argument("--review-path", default=DEFAULT_REVIEW)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Evaluate completed review rows only. By default every review row must be complete.",
    )
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


def primary_status(row: dict) -> str:
    return (row.get("annotation") or {}).get("manual_status", "").strip()


def review_status(row: dict) -> str:
    return (row.get("review_annotation") or {}).get("reviewer_status", "").strip()


def load_primary(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate primary sample_id: {sample_id}")
        rows[sample_id] = row
    if not rows:
        raise ValueError(f"No primary rows found in {path}")
    return rows


def load_review(path: Path) -> list[dict]:
    rows = list(iter_jsonl(path))
    if not rows:
        raise ValueError(f"No review rows found in {path}")
    return rows


def validate(primary_rows: dict[str, dict], review_rows: list[dict], allow_partial: bool):
    pairs = []
    incomplete = []
    invalid = []
    for review in review_rows:
        sample_id = review["original_sample_id"]
        primary = primary_rows.get(sample_id)
        if not primary:
            raise ValueError(f"Review row references missing primary sample: {sample_id}")
        p_status = primary_status(primary)
        r_status = review_status(review)
        if p_status and p_status not in LABELS:
            invalid.append((sample_id, "primary", p_status))
        if r_status and r_status not in LABELS:
            invalid.append((sample_id, "review", r_status))
        if not p_status or not r_status:
            incomplete.append(sample_id)
            continue
        pairs.append((primary, review, p_status, r_status))

    if invalid:
        sample_id, side, value = invalid[0]
        raise ValueError(f"Invalid {side} label for {sample_id}: {value}")
    if incomplete and not allow_partial:
        raise ValueError(
            f"Consistency labels incomplete: {len(incomplete)}/{len(review_rows)} "
            "review rows lack primary manual_status or reviewer_status. Fill labels "
            "or rerun with --allow-partial."
        )
    if not pairs:
        raise ValueError("No completed primary/review label pairs available.")
    return pairs


def cohen_kappa(confusion: Counter, labels: tuple[str, ...], total: int) -> float:
    observed = sum(confusion[(label, label)] for label in labels) / total
    primary_counts = Counter()
    review_counts = Counter()
    for (primary, review), count in confusion.items():
        primary_counts[primary] += count
        review_counts[review] += count
    expected = sum(
        (primary_counts[label] / total) * (review_counts[label] / total)
        for label in labels
    )
    if expected == 1:
        return 1.0 if observed == 1 else 0.0
    return (observed - expected) / (1 - expected)


def evaluate(pairs: list[tuple[dict, dict, str, str]]) -> dict:
    confusion = Counter((p_status, r_status) for _p, _r, p_status, r_status in pairs)
    by_field = {}
    for field in sorted({primary["field"] for primary, *_rest in pairs}):
        field_pairs = [
            (primary, review, p_status, r_status)
            for primary, review, p_status, r_status in pairs
            if primary["field"] == field
        ]
        agree = sum(1 for _p, _r, p_status, r_status in field_pairs if p_status == r_status)
        by_field[field] = {
            "count": len(field_pairs),
            "agreement_rate": agree / len(field_pairs) if field_pairs else 0.0,
        }

    total = len(pairs)
    agreements = sum(1 for _p, _r, p_status, r_status in pairs if p_status == r_status)
    return {
        "label_source": "manual_status_vs_reviewer_status",
        "row_count": total,
        "agreement_count": agreements,
        "agreement_rate": agreements / total if total else 0.0,
        "cohen_kappa": cohen_kappa(confusion, LABELS, total),
        "per_field": by_field,
        "confusion_matrix": [
            {"manual_status": p_status, "reviewer_status": r_status, "count": count}
            for (p_status, r_status), count in sorted(confusion.items())
        ],
        "cautions": [
            "Agreement is meaningful only after independent manual_status and reviewer_status labels are complete.",
            "Rows excluded by --allow-partial must be reported if partial mode is used.",
        ],
    }


def render_markdown(metrics: dict) -> str:
    lines = [
        "# RQ2 Annotation Consistency",
        "",
        "Metrics compare primary `manual_status` labels with second-pass `reviewer_status` labels.",
        "",
        f"- Rows evaluated: `{metrics['row_count']}`",
        f"- Agreement count: `{metrics['agreement_count']}`",
        f"- Agreement rate: `{metrics['agreement_rate']:.4f}`",
        f"- Cohen's kappa: `{metrics['cohen_kappa']:.4f}`",
        "",
        "## Per-Field Agreement",
        "",
        "| Field | Count | Agreement |",
        "|---|---:|---:|",
    ]
    for field, values in metrics["per_field"].items():
        lines.append(f"| {field} | {values['count']} | {values['agreement_rate']:.4f} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    primary_path = resolve_path(args.primary_path)
    review_path = resolve_path(args.review_path)
    output_dir = resolve_path(args.output_dir)
    primary_rows = load_primary(primary_path)
    review_rows = load_review(review_path)
    pairs = validate(primary_rows, review_rows, allow_partial=args.allow_partial)
    metrics = evaluate(pairs)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_annotation_consistency.json"
    md_path = output_dir / "rq2_annotation_consistency.md"
    json_path.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
