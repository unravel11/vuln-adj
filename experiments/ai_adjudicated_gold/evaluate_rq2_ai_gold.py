#!/usr/bin/env python3
"""Evaluate RQ2 rule variants against the AI-adjudicated gold snapshot."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
ALL_LABELS = (*LABELS, "uncertain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--gold-input",
        default="data/annotations/ai_adjudicated_gold/rq2_primary.jsonl",
    )
    parser.add_argument(
        "--review-input",
        default="data/annotations/ai_adjudicated_gold/rq2_review.jsonl",
    )
    parser.add_argument(
        "--source-input", default="data/annotations/rq2/discrepancy_typing_seed.jsonl"
    )
    parser.add_argument(
        "--reference-changes",
        default="results/rq2_discrepancy_typing/reference_normalization_changed_cases.review.jsonl",
    )
    parser.add_argument(
        "--cwe-changes",
        default="results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_changed_cases.jsonl",
    )
    parser.add_argument(
        "--output-dir", default="results/ai_adjudicated_gold/rq2"
    )
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"{path}: duplicate {key}={value}")
        rows[value] = row
    return rows


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def prediction_metrics(records: list[dict], prediction_key: str) -> dict:
    determinate = [row for row in records if row["ai_gold_label"] != "uncertain"]
    confusion = Counter(
        (row["ai_gold_label"], row[prediction_key]) for row in determinate
    )
    gold_counts = Counter(row["ai_gold_label"] for row in determinate)
    pred_counts = Counter(row[prediction_key] for row in determinate)
    per_label = {}
    supported_f1 = []
    for label in LABELS:
        tp = confusion[(label, label)]
        fp = sum(confusion[(gold, label)] for gold in LABELS if gold != label)
        fn = sum(confusion[(label, pred)] for pred in LABELS if pred != label)
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall)
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": gold_counts[label],
            "predicted": pred_counts[label],
        }
        if gold_counts[label]:
            supported_f1.append(f1)
    correct = sum(
        row["ai_gold_label"] == row[prediction_key] for row in determinate
    )
    by_field = {}
    for field in sorted({row["field"] for row in determinate}):
        subset = [row for row in determinate if row["field"] == field]
        field_correct = sum(
            row["ai_gold_label"] == row[prediction_key] for row in subset
        )
        by_field[field] = {
            "determinate_rows": len(subset),
            "agreement_count": field_correct,
            "accuracy": safe_divide(field_correct, len(subset)),
        }
    return {
        "input_rows": len(records),
        "determinate_rows": len(determinate),
        "uncertain_rows_excluded": len(records) - len(determinate),
        "determinate_coverage": safe_divide(len(determinate), len(records)),
        "agreement_count": correct,
        "accuracy": safe_divide(correct, len(determinate)),
        "macro_f1_over_supported_ai_gold_labels": safe_divide(
            sum(supported_f1), len(supported_f1)
        ),
        "gold_label_counts": dict(sorted(gold_counts.items())),
        "predicted_label_counts": dict(sorted(pred_counts.items())),
        "per_label": per_label,
        "per_field": by_field,
        "confusion_matrix": [
            {"ai_gold_label": gold, "predicted_label": pred, "count": count}
            for (gold, pred), count in sorted(confusion.items())
        ],
    }


def cohen_kappa(left: list[str], right: list[str]) -> float | None:
    total = len(left)
    observed = safe_divide(sum(a == b for a, b in zip(left, right)), total)
    left_counts = Counter(left)
    right_counts = Counter(right)
    labels = set(left) | set(right)
    expected = sum(
        safe_divide(left_counts[label], total)
        * safe_divide(right_counts[label], total)
        for label in labels
    )
    if expected == 1.0:
        return None
    return safe_divide(observed - expected, 1.0 - expected)


def review_consistency(gold: dict[str, dict], reviews: dict[str, dict]) -> dict:
    pairs = []
    for review in reviews.values():
        original_id = review.get("original_sample_id")
        primary = gold.get(original_id)
        if primary is None:
            raise ValueError(f"review references unknown primary {original_id}")
        pairs.append(
            {
                "field": primary["field"],
                "primary": primary["annotation"]["discrepancy_label"],
                "review": review["annotation"]["discrepancy_label"],
            }
        )
    left = [row["primary"] for row in pairs]
    right = [row["review"] for row in pairs]
    by_field = {}
    for field in sorted({row["field"] for row in pairs}):
        subset = [row for row in pairs if row["field"] == field]
        by_field[field] = {
            "rows": len(subset),
            "agreement_count": sum(
                row["primary"] == row["review"] for row in subset
            ),
            "agreement_rate": safe_divide(
                sum(row["primary"] == row["review"] for row in subset), len(subset)
            ),
        }
    agreement = sum(a == b for a, b in zip(left, right))
    return {
        "row_count": len(pairs),
        "agreement_count": agreement,
        "agreement_rate": safe_divide(agreement, len(pairs)),
        "cohen_kappa": cohen_kappa(left, right),
        "same_model_family_not_human_inter_annotator_agreement": True,
        "per_field": by_field,
    }


def render_markdown(metrics: dict) -> str:
    lines = [
        "# RQ2 AI-Adjudicated Gold Diagnostic",
        "",
        "These results use AI-adjudicated gold with `label_is_human=false`; they are not human-gold performance.",
        "",
        "| Method | Determinate | Coverage | Accuracy | Macro-F1 |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for method, values in metrics["methods"].items():
        lines.append(
            f"| {method} | {values['determinate_rows']} | {values['determinate_coverage']:.4f} | "
            f"{values['accuracy']:.4f} | {values['macro_f1_over_supported_ai_gold_labels']:.4f} |"
        )
    consistency = metrics["same_model_consistency"]
    lines.extend(
        [
            "",
            f"Same-model review consistency after adjudication: {consistency['agreement_count']}/{consistency['row_count']} = {consistency['agreement_rate']:.4f}; kappa={consistency['cohen_kappa'] if consistency['cohen_kappa'] is not None else 'undefined'}.",
            "",
            "Production defaults remain unchanged. Reference and CWE variants are candidate diagnostics only.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    gold_path = resolve(args.gold_input)
    review_path = resolve(args.review_input)
    source_path = resolve(args.source_input)
    reference_path = resolve(args.reference_changes)
    cwe_path = resolve(args.cwe_changes)
    output_dir = resolve(args.output_dir)
    gold = load_unique(gold_path, "sample_id")
    reviews = load_unique(review_path, "sample_id")
    source = load_unique(source_path, "sample_id")
    if len(gold) != 300 or len(reviews) != 60 or set(gold) != set(source):
        raise ValueError("expected complete 300-row primary and 60-row review snapshots")
    for row in gold.values():
        if row.get("label_is_human") is not False:
            raise ValueError("AI gold row incorrectly claims human provenance")

    reference_changes = {
        row["cve_id"]: row["proposed_status"] for row in iter_jsonl(reference_path)
    }
    cwe_changes = {
        row["cve_id"]: row["taxonomy_v1_status"] for row in iter_jsonl(cwe_path)
    }
    records = []
    for sample_id, gold_row in gold.items():
        source_row = source[sample_id]
        current = source_row["baseline_status"]
        reference = (
            reference_changes.get(source_row["cve_id"], current)
            if source_row["field"] == "references"
            else current
        )
        cwe = (
            cwe_changes.get(source_row["cve_id"], current)
            if source_row["field"] == "cwe_ids"
            else current
        )
        combined = reference if source_row["field"] == "references" else cwe
        records.append(
            {
                "sample_id": sample_id,
                "cve_id": source_row["cve_id"],
                "field": source_row["field"],
                "ai_gold_label": gold_row["annotation"]["discrepancy_label"],
                "current": current,
                "reference_resource_identity_v1": reference,
                "cwe_taxonomy_v1": cwe,
                "combined_candidate_v1": combined,
            }
        )
    method_keys = (
        "current",
        "reference_resource_identity_v1",
        "cwe_taxonomy_v1",
        "combined_candidate_v1",
    )
    metrics = {
        "artifact_type": "rq2_ai_adjudicated_gold_diagnostic",
        "label_source": "ai_adjudicated_gold_v1",
        "gold_label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "production_default_changed": False,
        "eligible_for_final_paper_claim": False,
        "gold_input": str(gold_path),
        "review_input": str(review_path),
        "source_input": str(source_path),
        "method_change_sets": {
            "reference_resource_identity_v1_full_corpus_rows": len(reference_changes),
            "cwe_taxonomy_v1_full_corpus_rows": len(cwe_changes),
        },
        "methods": {
            key: prediction_metrics(records, key) for key in method_keys
        },
        "same_model_consistency": review_consistency(gold, reviews),
        "ai_gold_label_counts": dict(
            sorted(
                Counter(
                    row["annotation"]["discrepancy_label"] for row in gold.values()
                ).items()
            )
        ),
        "decision_origin_counts": dict(
            sorted(Counter(row["decision_origin"] for row in gold.values()).items())
        ),
        "requires_additional_review_count": sum(
            row["requires_additional_review"] for row in gold.values()
        ),
        "cautions": [
            "AI-adjudicated gold is not human-gold.",
            "The adjudication pass was targeted using baseline/candidate/repeatability disagreements and is selection-aware.",
            "The consistency pass uses the same model family and is not human inter-annotator agreement.",
            "Reference and CWE variants were designed after candidate error inspection and remain diagnostic.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_ai_gold_metrics.json"
    md_path = output_dir / "rq2_ai_gold_metrics.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
