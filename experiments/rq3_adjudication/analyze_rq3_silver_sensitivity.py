#!/usr/bin/env python3
"""Analyze RQ3 silver-label baseline sensitivity to simple thresholds.

This diagnostic varies only the deterministic thresholds used by the existing
severity evidence-score and affected_versions version-token baselines. It is a
silver-label robustness view, not a human-gold performance result.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.rq3_adjudication.evaluate_affected_versions_silver_v2 import (
    DEFAULT_EVIDENCE_INPUT as DEFAULT_AFFECTED_EVIDENCE,
)
from experiments.rq3_adjudication.evaluate_affected_versions_silver_v2 import (
    DEFAULT_SILVER_INPUT as DEFAULT_AFFECTED_SILVER,
)
from experiments.rq3_adjudication.evaluate_affected_versions_silver_v2 import (
    evidence_support as affected_evidence_support,
)
from experiments.rq3_adjudication.evaluate_affected_versions_silver_v2 import (
    load_by_sample_id as load_affected_by_sample_id,
)
from experiments.rq3_adjudication.evaluate_affected_versions_silver_v2 import (
    source_metrics as affected_source_metrics,
)
from experiments.rq3_adjudication.evaluate_severity_silver_v2 import (
    DEFAULT_EVIDENCE_INPUT as DEFAULT_SEVERITY_EVIDENCE,
)
from experiments.rq3_adjudication.evaluate_severity_silver_v2 import (
    DEFAULT_SILVER_INPUT as DEFAULT_SEVERITY_SILVER,
)
from experiments.rq3_adjudication.evaluate_severity_silver_v2 import (
    evidence_support as severity_evidence_support,
)
from experiments.rq3_adjudication.evaluate_severity_silver_v2 import (
    load_by_sample_id as load_severity_by_sample_id,
)
from experiments.rq3_adjudication.evaluate_severity_silver_v2 import (
    source_metrics as severity_source_metrics,
)


DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"
SEVERITY_THRESHOLDS = (1, 2, 3, 4, 5, 6)
AFFECTED_TOKEN_THRESHOLDS = (1, 2, 3)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build silver-only RQ3 threshold sensitivity diagnostics."
    )
    parser.add_argument("--severity-evidence", default=DEFAULT_SEVERITY_EVIDENCE)
    parser.add_argument("--severity-silver", default=DEFAULT_SEVERITY_SILVER)
    parser.add_argument("--affected-evidence", default=DEFAULT_AFFECTED_EVIDENCE)
    parser.add_argument("--affected-silver", default=DEFAULT_AFFECTED_SILVER)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def predict_from_scores(nvd_score: int, ghsa_score: int, threshold: int) -> str:
    nvd_supported = nvd_score >= threshold
    ghsa_supported = ghsa_score >= threshold
    if nvd_supported and ghsa_supported:
        return "both"
    if nvd_supported:
        return "nvd"
    if ghsa_supported:
        return "ghsa"
    return "abstain"


def build_prediction(
    *,
    sample_id: str,
    cve_id: str,
    field: str,
    method: str,
    threshold: int,
    silver_annotation: dict,
    predicted_source: str,
    support: dict,
) -> dict:
    silver_source = silver_annotation["adjudicated_source"]
    return {
        "sample_id": sample_id,
        "cve_id": cve_id,
        "field": field,
        "method": method,
        "threshold": threshold,
        "silver_source": silver_source,
        "silver_label": silver_annotation["llm_label"],
        "predicted_source": predicted_source,
        "is_correct": predicted_source == silver_source,
        "support_scores": {
            "nvd": support["nvd"]["score"],
            "ghsa": support["ghsa"]["score"],
        },
    }


def load_matching_rows(
    evidence_path: Path,
    silver_path: Path,
    loader,
) -> tuple[dict[str, dict], dict[str, dict]]:
    evidence_rows = loader(evidence_path)
    silver_rows = loader(silver_path)
    if set(evidence_rows) != set(silver_rows):
        missing_silver = sorted(set(evidence_rows) - set(silver_rows))
        missing_evidence = sorted(set(silver_rows) - set(evidence_rows))
        raise ValueError(
            "Evidence and silver sample_id sets differ: "
            f"missing_silver={missing_silver[:5]}, "
            f"missing_evidence={missing_evidence[:5]}"
        )
    return evidence_rows, silver_rows


def summarize_thresholds(
    predictions_by_threshold: dict[int, list[dict]],
    *,
    source_metrics,
) -> dict:
    metrics_by_threshold = {}
    for threshold, predictions in predictions_by_threshold.items():
        metrics = source_metrics(predictions)
        correct = sum(1 for row in predictions if row["is_correct"])
        prediction_counts = Counter(row["predicted_source"] for row in predictions)
        metrics_by_threshold[str(threshold)] = {
            "threshold": threshold,
            "accuracy": metrics["accuracy"],
            "macro_f1_over_supported_silver_labels": metrics[
                "macro_f1_over_supported_silver_labels"
            ],
            "coverage_non_abstain": metrics["coverage_non_abstain"],
            "accuracy_when_non_abstain": metrics["accuracy_when_non_abstain"],
            "correct_count": correct,
            "prediction_counts": dict(sorted(prediction_counts.items())),
            "source_metrics": metrics,
        }
    return metrics_by_threshold


def choose_best_threshold(metrics_by_threshold: dict[str, dict]) -> dict:
    ranked = sorted(
        metrics_by_threshold.values(),
        key=lambda row: (
            row["accuracy"],
            row["macro_f1_over_supported_silver_labels"],
            row["coverage_non_abstain"],
        ),
        reverse=True,
    )
    return ranked[0] if ranked else {}


def instability_summary(predictions_by_threshold: dict[int, list[dict]]) -> dict:
    by_sample: dict[str, set[str]] = {}
    for predictions in predictions_by_threshold.values():
        for row in predictions:
            by_sample.setdefault(row["sample_id"], set()).add(row["predicted_source"])
    changed = {
        sample_id: sorted(values)
        for sample_id, values in sorted(by_sample.items())
        if len(values) > 1
    }
    return {
        "samples_with_prediction_change": len(changed),
        "sample_count": len(by_sample),
        "prediction_change_rate": safe_divide(len(changed), len(by_sample)),
        "first_changed_samples": [
            {"sample_id": sample_id, "predicted_sources": values}
            for sample_id, values in list(changed.items())[:10]
        ],
    }


def severity_sweep(evidence_path: Path, silver_path: Path) -> dict:
    evidence_rows, silver_rows = load_matching_rows(
        evidence_path, silver_path, load_severity_by_sample_id
    )
    predictions_by_threshold: dict[int, list[dict]] = {
        threshold: [] for threshold in SEVERITY_THRESHOLDS
    }
    support_by_sample = {}

    for sample_id in sorted(evidence_rows):
        row = evidence_rows[sample_id]
        support = severity_evidence_support(row)
        support_by_sample[sample_id] = {
            "nvd": support["nvd"]["score"],
            "ghsa": support["ghsa"]["score"],
        }
        silver_annotation = silver_rows[sample_id]["llm_annotation"]
        for threshold in SEVERITY_THRESHOLDS:
            predicted_source = predict_from_scores(
                support["nvd"]["score"], support["ghsa"]["score"], threshold
            )
            predictions_by_threshold[threshold].append(
                build_prediction(
                    sample_id=sample_id,
                    cve_id=row["cve_id"],
                    field="severity",
                    method="evidence_score_baseline_threshold_sweep",
                    threshold=threshold,
                    silver_annotation=silver_annotation,
                    predicted_source=predicted_source,
                    support=support,
                )
            )

    metrics_by_threshold = summarize_thresholds(
        predictions_by_threshold, source_metrics=severity_source_metrics
    )
    return {
        "field": "severity",
        "method_family": "evidence_score_baseline",
        "threshold_parameter": "minimum evidence score per source",
        "sample_count": len(evidence_rows),
        "silver_label_is_gold": False,
        "thresholds": list(SEVERITY_THRESHOLDS),
        "baseline_threshold": 3,
        "metrics_by_threshold": metrics_by_threshold,
        "best_threshold_by_silver_accuracy": choose_best_threshold(metrics_by_threshold),
        "instability": instability_summary(predictions_by_threshold),
        "support_score_distribution": score_distribution(support_by_sample),
    }


def affected_sweep(evidence_path: Path, silver_path: Path) -> dict:
    evidence_rows, silver_rows = load_matching_rows(
        evidence_path, silver_path, load_affected_by_sample_id
    )
    predictions_by_threshold: dict[int, list[dict]] = {
        threshold: [] for threshold in AFFECTED_TOKEN_THRESHOLDS
    }
    support_by_sample = {}

    for sample_id in sorted(evidence_rows):
        row = evidence_rows[sample_id]
        support = affected_evidence_support(row)
        support_by_sample[sample_id] = {
            "nvd": support["nvd"]["score"],
            "ghsa": support["ghsa"]["score"],
        }
        silver_annotation = silver_rows[sample_id]["llm_annotation"]
        for threshold in AFFECTED_TOKEN_THRESHOLDS:
            predicted_source = predict_from_scores(
                support["nvd"]["score"], support["ghsa"]["score"], threshold
            )
            predictions_by_threshold[threshold].append(
                build_prediction(
                    sample_id=sample_id,
                    cve_id=row["cve_id"],
                    field="affected_versions",
                    method="version_token_support_baseline_threshold_sweep",
                    threshold=threshold,
                    silver_annotation=silver_annotation,
                    predicted_source=predicted_source,
                    support=support,
                )
            )

    metrics_by_threshold = summarize_thresholds(
        predictions_by_threshold, source_metrics=affected_source_metrics
    )
    return {
        "field": "affected_versions",
        "method_family": "version_token_support_baseline",
        "threshold_parameter": "minimum matched version-token occurrences per source",
        "sample_count": len(evidence_rows),
        "silver_label_is_gold": False,
        "thresholds": list(AFFECTED_TOKEN_THRESHOLDS),
        "baseline_threshold": 1,
        "metrics_by_threshold": metrics_by_threshold,
        "best_threshold_by_silver_accuracy": choose_best_threshold(metrics_by_threshold),
        "instability": instability_summary(predictions_by_threshold),
        "support_score_distribution": score_distribution(support_by_sample),
    }


def score_distribution(support_by_sample: dict[str, dict[str, int]]) -> dict:
    nvd_scores = Counter(row["nvd"] for row in support_by_sample.values())
    ghsa_scores = Counter(row["ghsa"] for row in support_by_sample.values())
    paired_scores = Counter(
        f"nvd={row['nvd']},ghsa={row['ghsa']}"
        for row in support_by_sample.values()
    )
    return {
        "nvd": {str(score): count for score, count in sorted(nvd_scores.items())},
        "ghsa": {str(score): count for score, count in sorted(ghsa_scores.items())},
        "paired_top10": dict(paired_scores.most_common(10)),
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ3 Silver Baseline Sensitivity",
        "",
        "This artifact varies deterministic baseline thresholds against evidence-aware LLM silver labels. It is not a human-gold performance result.",
        "",
        f"- Severity samples: {summary['fields']['severity']['sample_count']}",
        f"- Affected_versions samples: {summary['fields']['affected_versions']['sample_count']}",
        f"- Silver labels are gold: {summary['silver_label_is_gold']}",
        "",
    ]
    for field, field_summary in summary["fields"].items():
        lines.extend(
            [
                f"## {field}",
                "",
                f"- Method family: `{field_summary['method_family']}`",
                f"- Threshold parameter: {field_summary['threshold_parameter']}",
                f"- Baseline threshold: {field_summary['baseline_threshold']}",
                f"- Samples with prediction changes across thresholds: {field_summary['instability']['samples_with_prediction_change']}/{field_summary['instability']['sample_count']} ({field_summary['instability']['prediction_change_rate']:.1%})",
                "",
                table(
                    [
                        "Threshold",
                        "Accuracy",
                        "Macro-F1",
                        "Coverage",
                        "Selective accuracy",
                        "Predictions",
                    ],
                    [
                        [
                            str(values["threshold"]),
                            f"{values['accuracy']:.3f}",
                            f"{values['macro_f1_over_supported_silver_labels']:.3f}",
                            f"{values['coverage_non_abstain']:.3f}",
                            f"{values['accuracy_when_non_abstain']:.3f}",
                            compact_counts(values["prediction_counts"]),
                        ]
                        for values in field_summary["metrics_by_threshold"].values()
                    ],
                ),
                "",
            ]
        )
    lines.extend(
        [
            "Caution: threshold choices were inspected against silver labels only. These diagnostics are useful for robustness and audit planning, not for final gold-backed claims.",
            "",
        ]
    )
    return "\n".join(lines)


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] + ["---:" for _ in headers[1:]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def compact_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    severity = severity_sweep(
        resolve_path(args.severity_evidence), resolve_path(args.severity_silver)
    )
    affected = affected_sweep(
        resolve_path(args.affected_evidence), resolve_path(args.affected_silver)
    )
    summary = {
        "artifact": "rq3_silver_baseline_sensitivity",
        "silver_label_is_gold": False,
        "metric_scope": "silver_label_threshold_diagnostic_only",
        "source_paths": {
            "severity_evidence": str(resolve_path(args.severity_evidence)),
            "severity_silver": str(resolve_path(args.severity_silver)),
            "affected_versions_evidence": str(resolve_path(args.affected_evidence)),
            "affected_versions_silver": str(resolve_path(args.affected_silver)),
        },
        "cautions": [
            "This is a silver-label threshold sensitivity diagnostic, not a human-gold performance result.",
            "The severity sweep varies the evidence-score threshold only.",
            "The affected_versions sweep varies the version-token support threshold only; it is not semantic version-range adjudication.",
        ],
        "fields": {
            "severity": severity,
            "affected_versions": affected,
        },
    }

    json_path = output_dir / "rq3_silver_baseline_sensitivity.json"
    md_path = output_dir / "rq3_silver_baseline_sensitivity.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
