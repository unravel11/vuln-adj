#!/usr/bin/env python3
"""Evaluate RQ2 discrepancy typing after manual labels are completed."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
ALLOWED_LABELS = (*LABELS, "uncertain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate deterministic RQ2 labels against completed manual labels."
    )
    parser.add_argument("--input-path", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow blank rows. The uncertain label is always accepted but excluded from five-class metrics.",
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


def load_rows(path: Path) -> list[dict]:
    rows = list(iter_jsonl(path))
    if not rows:
        raise ValueError(f"No rows found in {path}")
    return rows


def manual_status(row: dict) -> str:
    return (row.get("annotation") or {}).get("manual_status", "").strip()


def completed_rows(rows: list[dict]) -> list[dict]:
    return [row for row in rows if manual_status(row) in LABELS]


def validate_rows(rows: list[dict], allow_partial: bool) -> list[dict]:
    blank = [row for row in rows if not manual_status(row)]
    invalid = [
        row
        for row in rows
        if manual_status(row) and manual_status(row) not in ALLOWED_LABELS
    ]
    if invalid:
        examples = ", ".join(row["sample_id"] for row in invalid[:5])
        raise ValueError(f"Invalid manual_status values in rows: {examples}")
    if blank and not allow_partial:
        raise ValueError(
            f"Manual labels incomplete: {len(blank)}/{len(rows)} rows have blank "
            "manual_status. Fill labels or rerun with --allow-partial."
        )
    labeled = completed_rows(rows)
    if not labeled:
        raise ValueError("No completed manual_status labels available for evaluation.")
    return labeled


def precision_recall_f1(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def evaluate(rows: list[dict]) -> dict:
    confusion = Counter()
    by_field = defaultdict(list)
    for row in rows:
        gold = manual_status(row)
        pred = row["baseline_status"]
        confusion[(gold, pred)] += 1
        by_field[row["field"]].append(row)

    correct = sum(1 for row in rows if row["baseline_status"] == manual_status(row))
    per_label = {}
    for label in LABELS:
        tp = confusion[(label, label)]
        fp = sum(confusion[(gold, label)] for gold in LABELS if gold != label)
        fn = sum(confusion[(label, pred)] for pred in LABELS if pred != label)
        per_label[label] = precision_recall_f1(tp, fp, fn)

    per_field = {}
    for field, field_rows in sorted(by_field.items()):
        field_correct = sum(
            1 for row in field_rows if row["baseline_status"] == manual_status(row)
        )
        per_field[field] = {
            "count": len(field_rows),
            "accuracy": field_correct / len(field_rows) if field_rows else 0.0,
        }

    macro_f1 = sum(values["f1"] for values in per_label.values()) / len(LABELS)
    return {
        "label_source": "manual_status",
        "row_count": len(rows),
        "accuracy": correct / len(rows) if rows else 0.0,
        "macro_f1": macro_f1,
        "per_label": per_label,
        "per_field": per_field,
        "confusion_matrix": [
            {"manual_status": gold, "baseline_status": pred, "count": count}
            for (gold, pred), count in sorted(confusion.items())
        ],
        "cautions": [
            "Metrics are valid only if manual_status values were filled by human audit.",
            "Rows with uncertain manual_status are valid annotations but are excluded from five-class metrics.",
            "Rows with blank manual_status are excluded only when --allow-partial is used.",
        ],
    }


def render_markdown(metrics: dict) -> str:
    lines = [
        "# RQ2 Manual-Label Evaluation",
        "",
        "Metrics are computed against completed `manual_status` labels.",
        "",
        f"- Input rows: `{metrics['input_row_count']}`",
        f"- Rows evaluated: `{metrics['row_count']}`",
        f"- Uncertain rows excluded: `{metrics['excluded_uncertain_count']}`",
        f"- Blank rows excluded: `{metrics['excluded_blank_count']}`",
        f"- Accuracy: `{metrics['accuracy']:.4f}`",
        f"- Macro-F1: `{metrics['macro_f1']:.4f}`",
        "",
        "## Per-Label Metrics",
        "",
        "| Label | Precision | Recall | F1 |",
        "|---|---:|---:|---:|",
    ]
    for label, values in metrics["per_label"].items():
        lines.append(
            f"| {label} | {values['precision']:.4f} | {values['recall']:.4f} | {values['f1']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Per-Field Accuracy",
            "",
            "| Field | Count | Accuracy |",
            "|---|---:|---:|",
        ]
    )
    for field, values in metrics["per_field"].items():
        lines.append(f"| {field} | {values['count']} | {values['accuracy']:.4f} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    input_path = resolve_path(args.input_path)
    output_dir = resolve_path(args.output_dir)
    rows = load_rows(input_path)
    labeled = validate_rows(rows, allow_partial=args.allow_partial)
    metrics = evaluate(labeled)
    metrics.update(
        {
            "input_row_count": len(rows),
            "excluded_uncertain_count": sum(
                1 for row in rows if manual_status(row) == "uncertain"
            ),
            "excluded_blank_count": sum(1 for row in rows if not manual_status(row)),
            "allow_partial": args.allow_partial,
        }
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_manual_eval_metrics.json"
    md_path = output_dir / "rq2_manual_eval_metrics.md"
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
