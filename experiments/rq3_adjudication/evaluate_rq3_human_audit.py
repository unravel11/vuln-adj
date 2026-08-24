#!/usr/bin/env python3
"""Evaluate RQ3 adjudication baselines against completed human-audit labels.

The script is intentionally guarded: draft or blank templates do not produce
metric files. Use --allow-partial only after deciding that final rows may be
evaluated as a labeled subset.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable

from evaluate_affected_versions_silver_v2 import (
    predict_canonical_version_token_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_contextual_canonical_version_claim_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_contextual_version_claim_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_latest_published as predict_affected_latest_published,
)
from evaluate_affected_versions_silver_v2 import (
    predict_package_gated_canonical_token_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_package_gated_contextual_canonical_version_claim_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_package_gated_contextual_version_claim_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_package_gated_token_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_package_range_evidence,
)
from evaluate_affected_versions_silver_v2 import (
    predict_repository_crosswalk_package_gated_canonical_token_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_repository_crosswalk_package_gated_token_support,
)
from evaluate_affected_versions_silver_v2 import (
    predict_prefer as predict_affected_prefer,
)
from evaluate_affected_versions_silver_v2 import (
    predict_version_token_support,
)
from evaluate_severity_silver_v2 import predict_evidence_score
from evaluate_severity_silver_v2 import (
    predict_latest_published as predict_severity_latest_published,
)
from evaluate_severity_silver_v2 import predict_prefer as predict_severity_prefer


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"

DATASETS = {
    "severity": {
        "audit_input": "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
        "evidence_input": "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
        "expected_rows": 80,
    },
    "affected_versions": {
        "audit_input": "data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.jsonl",
        "evidence_input": "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        "expected_rows": 100,
    },
}

VALID_AUDIT_STATUSES = {"draft", "final", "exclude"}
VALID_HUMAN_LABELS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
VALID_FALSE_POSITIVE = {"yes", "no", "uncertain"}
VALID_SOURCES = {"nvd", "ghsa", "both", "neither", "abstain", "uncertain"}
VALID_REVIEW_STATUS = {"not_reviewed", "reviewed", "needs_revision"}
VALID_VERSION_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
    "not_applicable",
}
SOURCE_VALUES = ("nvd", "ghsa", "both", "neither", "abstain", "uncertain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate RQ3 baselines against completed human-audit labels."
    )
    parser.add_argument(
        "--field",
        choices=sorted(DATASETS),
        required=True,
        help="RQ3 field to evaluate.",
    )
    parser.add_argument("--audit-input", help="Human-audit JSONL. Defaults by field.")
    parser.add_argument("--evidence-input", help="Evidence JSONL. Defaults by field.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Evaluate final rows even if draft rows remain.",
    )
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    yield line_number, json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for line_number, row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id:
            raise ValueError(f"{path}:{line_number}: missing sample_id")
        if sample_id in rows:
            raise ValueError(f"{path}:{line_number}: duplicate sample_id {sample_id}")
        rows[sample_id] = row
    return rows


def normalized(value) -> str:
    return str(value or "").strip().lower()


def parse_audited_at(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def evidence_url_set(row: dict) -> set[str]:
    urls = set()
    for record in row.get("evidence_context", {}).get("records", []):
        url = record.get("url")
        if url:
            urls.add(url)
    for context_key in ("nvd_context", "ghsa_context"):
        for url in row.get(context_key, {}).get("references", []) or []:
            urls.add(url)
    return urls


def is_traceable_url(url: str, source_urls: set[str]) -> bool:
    return url in source_urls or url.startswith("added-by-human:")


def validate_final_row(field: str, audit_row: dict, evidence_row: dict) -> list[str]:
    errors = []
    human = audit_row.get("human_audit")
    if not isinstance(human, dict):
        return [f"{audit_row.get('sample_id')}: missing human_audit object"]

    for key in ("cve_id", "field", "nvd_source_id", "ghsa_source_id"):
        if audit_row.get(key) != evidence_row.get(key):
            errors.append(
                f"{audit_row.get('sample_id')}: {key} does not match source evidence"
            )

    human_label = normalized(human.get("human_label"))
    false_positive = normalized(human.get("is_baseline_false_positive"))
    adjudicated_source = normalized(human.get("adjudicated_source"))
    review_status = normalized(human.get("review_status"))
    annotator_id = str(human.get("annotator_id") or "").strip()
    reviewer_id = str(human.get("reviewer_id") or "").strip()

    if human_label not in VALID_HUMAN_LABELS:
        errors.append(f"{audit_row['sample_id']}: invalid human_label={human_label!r}")
    if false_positive not in VALID_FALSE_POSITIVE:
        errors.append(
            f"{audit_row['sample_id']}: invalid is_baseline_false_positive={false_positive!r}"
        )
    if adjudicated_source not in VALID_SOURCES:
        errors.append(
            f"{audit_row['sample_id']}: invalid adjudicated_source={adjudicated_source!r}"
        )
    if not annotator_id:
        errors.append(f"{audit_row['sample_id']}: annotator_id is required")
    if not parse_audited_at(str(human.get("audited_at") or "")):
        errors.append(f"{audit_row['sample_id']}: audited_at must be an ISO date/time")
    if review_status not in VALID_REVIEW_STATUS:
        errors.append(
            f"{audit_row['sample_id']}: invalid review_status={review_status!r}"
        )
    elif review_status != "reviewed":
        errors.append(
            f"{audit_row['sample_id']}: final rows require review_status='reviewed'"
        )
    if not reviewer_id:
        errors.append(f"{audit_row['sample_id']}: reviewer_id is required")
    elif annotator_id and reviewer_id == annotator_id:
        errors.append(
            f"{audit_row['sample_id']}: reviewer_id must differ from annotator_id"
        )

    if field == "affected_versions":
        reasoning_type = normalized(human.get("version_reasoning_type"))
        if reasoning_type not in VALID_VERSION_REASONING:
            errors.append(
                f"{audit_row['sample_id']}: invalid version_reasoning_type={reasoning_type!r}"
            )

    uncertain = human_label == "uncertain" or adjudicated_source in {"abstain", "uncertain"}
    evidence_urls = human.get("evidence_urls")
    if evidence_urls is None:
        evidence_urls = []
    if not isinstance(evidence_urls, list) or not all(
        isinstance(url, str) and url.strip() for url in evidence_urls
    ):
        errors.append(f"{audit_row['sample_id']}: evidence_urls must be a list of strings")
    elif not uncertain:
        if not evidence_urls:
            errors.append(f"{audit_row['sample_id']}: evidence_urls are required")
        source_urls = evidence_url_set(evidence_row)
        untraceable = [
            url for url in evidence_urls if not is_traceable_url(url, source_urls)
        ]
        if untraceable:
            errors.append(
                f"{audit_row['sample_id']}: untraceable evidence_urls={untraceable[:3]}"
            )
        if len(str(human.get("evidence_notes") or "").strip()) < 10:
            errors.append(f"{audit_row['sample_id']}: evidence_notes are required")

    if "llm_annotation" in audit_row:
        errors.append(
            f"{audit_row['sample_id']}: llm_annotation must not be the authoritative field"
        )

    return errors


def validate_inputs(
    field: str,
    audit_rows: dict[str, dict],
    evidence_rows: dict[str, dict],
    *,
    allow_partial: bool,
) -> tuple[list[dict], dict]:
    spec = DATASETS[field]
    errors = []
    status_counts = Counter()
    final_rows = []

    if len(audit_rows) != spec["expected_rows"]:
        errors.append(
            f"expected {spec['expected_rows']} audit rows for {field}, found {len(audit_rows)}"
        )

    missing_evidence = sorted(set(audit_rows) - set(evidence_rows))
    extra_evidence = sorted(set(evidence_rows) - set(audit_rows))
    if missing_evidence:
        errors.append(f"audit sample_ids missing from evidence: {missing_evidence[:5]}")
    if extra_evidence:
        errors.append(f"evidence sample_ids missing from audit: {extra_evidence[:5]}")

    for sample_id, row in sorted(audit_rows.items()):
        if row.get("field") != field:
            errors.append(f"{sample_id}: field={row.get('field')!r}, expected {field!r}")
        human = row.get("human_audit") or {}
        status = normalized(human.get("audit_status"))
        status_counts[status or "<blank>"] += 1
        if status not in VALID_AUDIT_STATUSES:
            errors.append(f"{sample_id}: invalid audit_status={status!r}")
            continue
        if status == "final":
            evidence_row = evidence_rows.get(sample_id)
            if evidence_row:
                errors.extend(validate_final_row(field, row, evidence_row))
                final_rows.append(row)
            continue
        if status == "exclude":
            continue
        if not allow_partial:
            errors.append(
                f"{sample_id}: audit_status={status!r}; default evaluation requires final/exclude rows only"
            )

    if not final_rows:
        errors.append("no final human-audit rows are available for evaluation")

    summary = {
        "audit_row_count": len(audit_rows),
        "evidence_row_count": len(evidence_rows),
        "status_counts": dict(sorted(status_counts.items())),
        "final_row_count": len(final_rows),
        "allow_partial": allow_partial,
    }
    if errors:
        raise ValueError(json.dumps({"errors": errors[:50], "summary": summary}, indent=2))
    return final_rows, summary


def predictors_for_field(field: str) -> dict[str, Callable[[dict], dict]]:
    if field == "severity":
        return {
            "prefer_nvd": predict_severity_prefer("nvd"),
            "prefer_ghsa": predict_severity_prefer("ghsa"),
            "latest_published": predict_severity_latest_published,
            "evidence_score_baseline": predict_evidence_score,
        }
    return {
        "prefer_nvd": predict_affected_prefer("nvd"),
        "prefer_ghsa": predict_affected_prefer("ghsa"),
        "latest_published": predict_affected_latest_published,
        "version_token_support_baseline": predict_version_token_support,
        "canonical_version_token_support_baseline": predict_canonical_version_token_support,
        "contextual_version_claim_baseline": predict_contextual_version_claim_support,
        "contextual_canonical_version_claim_baseline": predict_contextual_canonical_version_claim_support,
        "package_gated_contextual_version_claim_baseline": predict_package_gated_contextual_version_claim_support,
        "package_gated_contextual_canonical_version_claim_baseline": predict_package_gated_contextual_canonical_version_claim_support,
        "package_gated_token_baseline": predict_package_gated_token_support,
        "package_gated_canonical_token_baseline": predict_package_gated_canonical_token_support,
        "repository_crosswalk_package_gated_token_baseline": predict_repository_crosswalk_package_gated_token_support,
        "repository_crosswalk_package_gated_canonical_token_baseline": predict_repository_crosswalk_package_gated_canonical_token_support,
        "package_range_evidence_baseline": predict_package_range_evidence,
    }


def safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def source_metrics(records: list[dict]) -> dict:
    total = len(records)
    correct = sum(row["predicted_source"] == row["human_source"] for row in records)
    pred_counts = Counter(row["predicted_source"] for row in records)
    gold_counts = Counter(row["human_source"] for row in records)
    labels = sorted(set(SOURCE_VALUES) | set(pred_counts) | set(gold_counts))
    per_label = {}
    f1_values = []
    for label in labels:
        tp = sum(
            row["predicted_source"] == label and row["human_source"] == label
            for row in records
        )
        fp = sum(
            row["predicted_source"] == label and row["human_source"] != label
            for row in records
        )
        fn = sum(
            row["predicted_source"] != label and row["human_source"] == label
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
        row["predicted_source"] == row["human_source"] for row in covered_records
    )
    return {
        "total": total,
        "accuracy": safe_divide(correct, total),
        "macro_f1_over_supported_human_labels": safe_divide(
            sum(f1_values), len(f1_values)
        ),
        "coverage_non_abstain": safe_divide(total - abstained, total),
        "accuracy_when_non_abstain": safe_divide(covered_correct, len(covered_records)),
        "predicted_source_counts": dict(sorted(pred_counts.items())),
        "human_source_counts": dict(sorted(gold_counts.items())),
        "per_label": per_label,
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_metrics_md(path: Path, metrics: dict) -> None:
    lines = [
        f"# RQ3 {metrics['field']} Human-Audit Evaluation",
        "",
        "These metrics are computed only over rows with `audit_status=final`.",
        "",
        f"- Audit input: `{metrics['audit_input']}`",
        f"- Evidence input: `{metrics['evidence_input']}`",
        f"- Final rows: `{metrics['final_row_count']}`",
        f"- Allow partial: `{metrics['allow_partial']}`",
        "",
        "| Method | Accuracy | Macro-F1 | Coverage |",
        "| --- | ---: | ---: | ---: |",
    ]
    for method, values in metrics["methods"].items():
        lines.append(
            "| {method} | {accuracy:.4f} | {macro_f1:.4f} | {coverage:.4f} |".format(
                method=method,
                accuracy=values["accuracy"],
                macro_f1=values["macro_f1_over_supported_human_labels"],
                coverage=values["coverage_non_abstain"],
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    spec = DATASETS[args.field]
    audit_path = resolve_path(args.audit_input or spec["audit_input"])
    evidence_path = resolve_path(args.evidence_input or spec["evidence_input"])
    output_dir = resolve_path(args.output_dir)

    audit_rows = load_by_sample_id(audit_path)
    evidence_rows = load_by_sample_id(evidence_path)
    try:
        final_rows, validation_summary = validate_inputs(
            args.field, audit_rows, evidence_rows, allow_partial=args.allow_partial
        )
    except ValueError as exc:
        print("RQ3 human-audit evaluation refused; no metric files were written.")
        print(str(exc))
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    predictors = predictors_for_field(args.field)
    predictions_by_method: dict[str, list[dict]] = {name: [] for name in predictors}

    for audit_row in final_rows:
        sample_id = audit_row["sample_id"]
        evidence_row = evidence_rows[sample_id]
        human = audit_row["human_audit"]
        human_source = normalized(human["adjudicated_source"])
        for method_name, predictor in predictors.items():
            prediction = predictor(evidence_row)
            predictions_by_method[method_name].append(
                {
                    "sample_id": sample_id,
                    "cve_id": audit_row["cve_id"],
                    "field": args.field,
                    "method": method_name,
                    "human_source": human_source,
                    "human_label": normalized(human["human_label"]),
                    "is_baseline_false_positive": normalized(
                        human["is_baseline_false_positive"]
                    ),
                    "predicted_source": prediction["predicted_source"],
                    "is_correct": prediction["predicted_source"] == human_source,
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
    prefix = f"{args.field}_gold_audit"
    predictions_path = output_dir / f"{prefix}_predictions.jsonl"
    write_jsonl(predictions_path, all_predictions)

    metrics = {
        "task": f"rq3_{args.field}_adjudication_against_human_audit",
        "field": args.field,
        "audit_input": str(audit_path),
        "evidence_input": str(evidence_path),
        "predictions_path": str(predictions_path),
        "label_source": "human_audit_final_rows",
        "gold_label_is_human": True,
        "human_review_gate": {
            "review_status": "reviewed",
            "reviewer_id_required": True,
            "independent_reviewer_required": True,
        },
        "allow_partial": args.allow_partial,
        "audit_row_count": validation_summary["audit_row_count"],
        "final_row_count": validation_summary["final_row_count"],
        "audit_status_counts": validation_summary["status_counts"],
        "methods": {
            method_name: source_metrics(records)
            for method_name, records in predictions_by_method.items()
        },
    }
    metrics_path = output_dir / f"{prefix}_eval_metrics.json"
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_metrics_md(output_dir / f"{prefix}_eval_metrics.md", metrics)

    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
