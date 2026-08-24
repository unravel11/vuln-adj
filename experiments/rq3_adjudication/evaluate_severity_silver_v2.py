#!/usr/bin/env python3
"""Evaluate baseline RQ3 severity adjudication methods against silver_v2."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE_INPUT = (
    "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl"
)
DEFAULT_SILVER_INPUT = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"

SOURCE_VALUES = ("nvd", "ghsa", "both", "neither", "abstain")
SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "none": "none",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate RQ3 severity adjudication baselines against silver_v2."
    )
    parser.add_argument(
        "--evidence-input",
        default=DEFAULT_EVIDENCE_INPUT,
        help="Evidence-enriched sample JSONL.",
    )
    parser.add_argument(
        "--silver-input",
        default=DEFAULT_SILVER_INPUT,
        help="silver_v2 LLM annotation JSONL.",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for metrics and per-sample predictions.",
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


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate sample_id in {path}: {sample_id}")
        rows[sample_id] = row
    return rows


def canonical_severity(value: str | None) -> str:
    if value is None:
        return ""
    return SEVERITY_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())


def severity_terms(severity: dict | None) -> dict[str, str]:
    severity = severity or {}
    label = canonical_severity(severity.get("canonical_label") or severity.get("label"))
    display_label = canonical_severity(severity.get("label"))
    score = severity.get("score")
    return {
        "label": label,
        "display_label": display_label,
        "score": "" if score is None else str(score),
        "vector": str(severity.get("vector") or "").strip(),
    }


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


def label_present(text: str, label: str) -> bool:
    if not label:
        return False
    aliases = [label]
    if label == "medium":
        aliases.append("moderate")
    return any(re.search(rf"\b{re.escape(alias)}\b", text) for alias in aliases)


def score_present(text: str, score: str) -> bool:
    if not score:
        return False
    escaped = re.escape(score)
    return bool(re.search(rf"(?<!\d){escaped}(?!\d)", text))


def build_support_terms(row: dict) -> dict[str, dict[str, str]]:
    return {
        "nvd": severity_terms(row.get("nvd_context", {}).get("severity")),
        "ghsa": severity_terms(row.get("ghsa_context", {}).get("severity")),
    }


def evidence_support(row: dict) -> dict[str, dict]:
    terms_by_source = build_support_terms(row)
    support = {
        "nvd": {"score": 0, "matched_urls": [], "matched_terms": []},
        "ghsa": {"score": 0, "matched_urls": [], "matched_terms": []},
    }
    seen_matches: set[tuple[str, str, str]] = set()

    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
            continue
        text = normalize_text(" ".join([record.get("title", ""), record.get("text_snippet", "")]))
        url = record.get("url", "")
        for source, terms in terms_by_source.items():
            vector = terms["vector"]
            if vector and vector.lower() in text:
                add_match(support, seen_matches, source, url, "vector", 5)
            if score_present(text, terms["score"]) and label_present(text, terms["label"]):
                add_match(support, seen_matches, source, url, "score+label", 3)
            elif score_present(text, terms["score"]):
                add_match(support, seen_matches, source, url, "score", 2)
            elif label_present(text, terms["label"]):
                add_match(support, seen_matches, source, url, "label", 1)

    return support


def add_match(
    support: dict[str, dict],
    seen_matches: set[tuple[str, str, str]],
    source: str,
    url: str,
    term: str,
    weight: int,
) -> None:
    key = (source, url, term)
    if key in seen_matches:
        return
    seen_matches.add(key)
    support[source]["score"] += weight
    support[source]["matched_urls"].append(url)
    support[source]["matched_terms"].append(term)


def predict_evidence_score(row: dict) -> dict:
    support = evidence_support(row)
    nvd_supported = support["nvd"]["score"] >= 3
    ghsa_supported = support["ghsa"]["score"] >= 3

    if nvd_supported and ghsa_supported:
        prediction = "both"
    elif nvd_supported:
        prediction = "nvd"
    elif ghsa_supported:
        prediction = "ghsa"
    else:
        prediction = "abstain"

    return {
        "predicted_source": prediction,
        "support": support,
        "rule": "score>=3 from fetched title/text_snippet; both if both sides supported",
    }


def predict_prefer(source: str) -> Callable[[dict], dict]:
    def predictor(row: dict) -> dict:
        return {"predicted_source": source, "rule": f"always prefer {source.upper()}"}

    return predictor


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def predict_latest_published(row: dict) -> dict:
    nvd_time = parse_datetime(row.get("nvd_context", {}).get("published"))
    ghsa_time = parse_datetime(row.get("ghsa_context", {}).get("published"))
    if nvd_time and ghsa_time:
        if nvd_time > ghsa_time:
            prediction = "nvd"
        elif ghsa_time > nvd_time:
            prediction = "ghsa"
        else:
            prediction = "both"
    elif nvd_time:
        prediction = "nvd"
    elif ghsa_time:
        prediction = "ghsa"
    else:
        prediction = "abstain"
    return {
        "predicted_source": prediction,
        "rule": "choose side with later source publication timestamp",
    }


def source_metrics(records: list[dict]) -> dict:
    total = len(records)
    correct = sum(row["predicted_source"] == row["silver_source"] for row in records)
    pred_counts = Counter(row["predicted_source"] for row in records)
    gold_counts = Counter(row["silver_source"] for row in records)
    labels = sorted(set(SOURCE_VALUES) | set(pred_counts) | set(gold_counts))
    per_label = {}
    f1_values = []
    for label in labels:
        tp = sum(
            row["predicted_source"] == label and row["silver_source"] == label
            for row in records
        )
        fp = sum(
            row["predicted_source"] == label and row["silver_source"] != label
            for row in records
        )
        fn = sum(
            row["predicted_source"] != label and row["silver_source"] == label
            for row in records
        )
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
            f1_values.append(f1)

    abstained = pred_counts["abstain"]
    covered_records = [row for row in records if row["predicted_source"] != "abstain"]
    covered_correct = sum(
        row["predicted_source"] == row["silver_source"] for row in covered_records
    )
    return {
        "total": total,
        "accuracy": safe_divide(correct, total),
        "macro_f1_over_supported_silver_labels": safe_divide(sum(f1_values), len(f1_values)),
        "coverage_non_abstain": safe_divide(total - abstained, total),
        "accuracy_when_non_abstain": safe_divide(covered_correct, len(covered_records)),
        "predicted_source_counts": dict(sorted(pred_counts.items())),
        "silver_source_counts": dict(sorted(gold_counts.items())),
        "per_label": per_label,
    }


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def main() -> int:
    args = parse_args()
    evidence_path = resolve_path(args.evidence_input)
    silver_path = resolve_path(args.silver_input)
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence_rows = load_by_sample_id(evidence_path)
    silver_rows = load_by_sample_id(silver_path)
    if set(evidence_rows) != set(silver_rows):
        missing_silver = sorted(set(evidence_rows) - set(silver_rows))
        missing_evidence = sorted(set(silver_rows) - set(evidence_rows))
        raise ValueError(
            "Evidence and silver sample_id sets differ: "
            f"missing_silver={missing_silver[:5]}, missing_evidence={missing_evidence[:5]}"
        )

    predictors: dict[str, Callable[[dict], dict]] = {
        "prefer_nvd": predict_prefer("nvd"),
        "prefer_ghsa": predict_prefer("ghsa"),
        "latest_published": predict_latest_published,
        "evidence_score_baseline": predict_evidence_score,
    }
    predictions_by_method: dict[str, list[dict]] = {name: [] for name in predictors}

    for sample_id in sorted(evidence_rows):
        row = evidence_rows[sample_id]
        silver_annotation = silver_rows[sample_id]["llm_annotation"]
        silver_source = silver_annotation["adjudicated_source"]
        for method_name, predictor in predictors.items():
            prediction = predictor(row)
            predictions_by_method[method_name].append(
                {
                    "sample_id": sample_id,
                    "cve_id": row["cve_id"],
                    "method": method_name,
                    "silver_source": silver_source,
                    "silver_label": silver_annotation["llm_label"],
                    "predicted_source": prediction["predicted_source"],
                    "is_correct": prediction["predicted_source"] == silver_source,
                    "rule": prediction["rule"],
                    "prediction_detail": {
                        key: value
                        for key, value in prediction.items()
                        if key not in {"predicted_source", "rule"}
                    },
                }
            )

    all_predictions = [
        row for records in predictions_by_method.values() for row in records
    ]
    predictions_path = output_dir / "severity_silver_v2_predictions.jsonl"
    with predictions_path.open("w", encoding="utf-8") as handle:
        for row in all_predictions:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    metrics = {
        "task": "rq3_severity_adjudication_against_silver_v2",
        "evidence_input": str(evidence_path),
        "silver_input": str(silver_path),
        "predictions_path": str(predictions_path),
        "sample_count": len(evidence_rows),
        "silver_label_is_gold": False,
        "methods": {
            method_name: source_metrics(records)
            for method_name, records in predictions_by_method.items()
        },
    }
    metrics_path = output_dir / "severity_silver_v2_eval_metrics.json"
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
