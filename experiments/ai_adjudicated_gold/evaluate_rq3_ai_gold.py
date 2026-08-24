#!/usr/bin/env python3
"""Re-score RQ3 source-adjudication baselines against AI-adjudicated gold."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_LABELS = ("nvd", "ghsa", "both", "neither")
FIELDS = {
    "severity": {
        "gold": "data/annotations/ai_adjudicated_gold/rq3_severity.jsonl",
        "predictions": "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
        "expected_rows": 80,
    },
    "affected_versions": {
        "gold": "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl",
        "predictions": "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl",
        "expected_rows": 100,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", default="results/ai_adjudicated_gold/rq3"
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
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            yield row


def load_gold(path: Path, expected_rows: int) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in rows:
            raise ValueError(f"{path}: missing or duplicate sample_id={sample_id}")
        if row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: AI gold incorrectly claims human provenance")
        if row.get("eligible_for_human_gold_claim") is not False:
            raise ValueError(f"{sample_id}: AI gold incorrectly permits a human-gold claim")
        annotation = row.get("annotation")
        if not isinstance(annotation, dict):
            raise ValueError(f"{sample_id}: missing annotation")
        rows[sample_id] = row
    if len(rows) != expected_rows:
        raise ValueError(f"{path}: expected {expected_rows} rows, found {len(rows)}")
    return rows


def load_predictions(path: Path, sample_ids: set[str]) -> dict[str, list[dict]]:
    by_method = defaultdict(list)
    identities = set()
    for row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        method = row.get("method")
        predicted_source = row.get("predicted_source")
        if sample_id not in sample_ids:
            raise ValueError(f"{path}: prediction has unknown sample_id={sample_id}")
        if not method or predicted_source not in (*SOURCE_LABELS, "abstain"):
            raise ValueError(f"{path}: malformed prediction for {sample_id}")
        identity = (method, sample_id)
        if identity in identities:
            raise ValueError(f"{path}: duplicate method/sample prediction {identity}")
        identities.add(identity)
        by_method[method].append(row)
    for method, rows in by_method.items():
        method_ids = {row["sample_id"] for row in rows}
        if method_ids != sample_ids:
            missing = sorted(sample_ids - method_ids)
            raise ValueError(f"{path}: {method} missing samples {missing[:5]}")
    if not by_method:
        raise ValueError(f"{path}: no predictions")
    return dict(by_method)


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def method_metrics(gold: dict[str, dict], predictions: list[dict]) -> dict:
    determinate = {
        sample_id: row
        for sample_id, row in gold.items()
        if row.get("ai_gold_status") == "final_determinate"
    }
    records = []
    for prediction in predictions:
        sample_id = prediction["sample_id"]
        if sample_id not in determinate:
            continue
        gold_source = determinate[sample_id]["annotation"]["adjudicated_source"]
        if gold_source not in SOURCE_LABELS:
            raise ValueError(
                f"{sample_id}: final_determinate row has invalid source {gold_source}"
            )
        records.append(
            {
                "sample_id": sample_id,
                "gold_source": gold_source,
                "predicted_source": prediction["predicted_source"],
            }
        )

    confusion = Counter(
        (row["gold_source"], row["predicted_source"]) for row in records
    )
    gold_counts = Counter(row["gold_source"] for row in records)
    prediction_counts = Counter(row["predicted_source"] for row in records)
    f1_values = []
    per_label = {}
    for label in SOURCE_LABELS:
        tp = confusion[(label, label)]
        fp = sum(
            confusion[(gold_label, label)]
            for gold_label in SOURCE_LABELS
            if gold_label != label
        )
        fn = sum(
            confusion[(label, predicted_label)]
            for predicted_label in (*SOURCE_LABELS, "abstain")
            if predicted_label != label
        )
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall)
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": gold_counts[label],
            "predicted": prediction_counts[label],
        }
        if gold_counts[label]:
            f1_values.append(f1)

    correct = sum(
        row["gold_source"] == row["predicted_source"] for row in records
    )
    covered = [row for row in records if row["predicted_source"] != "abstain"]
    covered_correct = sum(
        row["gold_source"] == row["predicted_source"] for row in covered
    )
    return {
        "input_rows": len(gold),
        "ai_gold_determinate_rows": len(records),
        "ai_gold_abstain_rows_excluded": len(gold) - len(records),
        "ai_gold_determinate_coverage": safe_divide(len(records), len(gold)),
        "agreement_count": correct,
        "accuracy_on_ai_gold_determinate": safe_divide(correct, len(records)),
        "macro_f1_over_supported_ai_gold_sources": safe_divide(
            sum(f1_values), len(f1_values)
        ),
        "prediction_non_abstain_count": len(covered),
        "prediction_non_abstain_coverage_on_determinate": safe_divide(
            len(covered), len(records)
        ),
        "selective_accuracy_when_prediction_non_abstain": safe_divide(
            covered_correct, len(covered)
        ),
        "gold_source_counts": dict(sorted(gold_counts.items())),
        "predicted_source_counts": dict(sorted(prediction_counts.items())),
        "per_label": per_label,
        "confusion_matrix": [
            {
                "ai_gold_source": gold_source,
                "predicted_source": predicted_source,
                "count": count,
            }
            for (gold_source, predicted_source), count in sorted(confusion.items())
        ],
    }


def render_markdown(metrics: dict) -> str:
    lines = [
        "# RQ3 AI-Adjudicated Gold Diagnostic",
        "",
        "These results use AI-adjudicated gold with `label_is_human=false`; they are not human-gold performance.",
    ]
    for field, field_result in metrics["fields"].items():
        lines.extend(
            [
                "",
                f"## {field}",
                "",
                "| Method | Determinate | Gold coverage | Accuracy | Macro-F1 | Prediction coverage | Selective accuracy |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for method, values in field_result["methods"].items():
            lines.append(
                f"| {method} | {values['ai_gold_determinate_rows']} | "
                f"{values['ai_gold_determinate_coverage']:.4f} | "
                f"{values['accuracy_on_ai_gold_determinate']:.4f} | "
                f"{values['macro_f1_over_supported_ai_gold_sources']:.4f} | "
                f"{values['prediction_non_abstain_coverage_on_determinate']:.4f} | "
                f"{values['selective_accuracy_when_prediction_non_abstain']:.4f} |"
            )
    lines.extend(
        [
            "",
            "Production defaults remain unchanged. These baselines and variants are diagnostic only.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve(args.output_dir)
    fields = {}
    for field, spec in FIELDS.items():
        gold_path = resolve(spec["gold"])
        prediction_path = resolve(spec["predictions"])
        gold = load_gold(gold_path, spec["expected_rows"])
        predictions = load_predictions(prediction_path, set(gold))
        fields[field] = {
            "gold_input": str(gold_path),
            "prediction_input": str(prediction_path),
            "ai_gold_status_counts": dict(
                sorted(Counter(row["ai_gold_status"] for row in gold.values()).items())
            ),
            "ai_gold_discrepancy_label_counts": dict(
                sorted(
                    Counter(
                        row["annotation"]["discrepancy_label"]
                        for row in gold.values()
                    ).items()
                )
            ),
            "methods": {
                method: method_metrics(gold, rows)
                for method, rows in sorted(predictions.items())
            },
        }

    metrics = {
        "artifact_type": "rq3_ai_adjudicated_gold_diagnostic",
        "label_source": "ai_adjudicated_gold_v1",
        "gold_label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "production_default_changed": False,
        "fields": fields,
        "cautions": [
            "AI-adjudicated gold is not human-gold.",
            "Rows marked final_abstain are excluded from primary method metrics.",
            "The same model family contributed candidate creation and risk adjudication.",
            "The prediction files retain legacy silver-label columns, but this evaluator ignores them and re-scores only predicted_source.",
            "Affected-version evidence rules remain lexical or conservative parsed-range baselines, not complete semantic adjudicators.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq3_ai_gold_metrics.json"
    md_path = output_dir / "rq3_ai_gold_metrics.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
