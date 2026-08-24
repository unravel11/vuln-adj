#!/usr/bin/env python3
"""Evaluate AI expert-candidate labels without presenting them as human-gold."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RQ3_EXPERIMENT_DIR = PROJECT_ROOT / "experiments" / "rq3_adjudication"
sys.path.insert(0, str(RQ3_EXPERIMENT_DIR))

from evaluate_rq3_human_audit import predictors_for_field  # noqa: E402


LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)
SOURCES = ("nvd", "ghsa", "both", "neither", "abstain")
VERSION_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
    "not_applicable",
}

DEFAULTS = {
    "rq2_primary": "data/annotations/expert_candidate/raw/rq2_primary.jsonl",
    "rq2_review": "data/annotations/expert_candidate/raw/rq2_review.jsonl",
    "rq3_severity": "data/annotations/expert_candidate/raw/rq3_severity.jsonl",
    "rq3_affected": "data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl",
    "rq2_source": "data/annotations/rq2/discrepancy_typing_seed.jsonl",
    "rq2_review_source": (
        "data/annotations/rq2/consistency_review/"
        "discrepancy_typing_consistency_review.jsonl"
    ),
    "severity_evidence": (
        "data/annotations/rq3/silver_v2/"
        "severity_fc_adjudication_seed.evidence.jsonl"
    ),
    "affected_evidence": (
        "data/annotations/rq3/silver_v2/"
        "affected_versions_fc_manual_check.evidence.jsonl"
    ),
    "severity_silver": (
        "data/annotations/rq3/silver_v2/llm_silver_v2/"
        "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
    ),
    "affected_silver": (
        "data/annotations/rq3/silver_v2/llm_silver_v2/"
        "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
    ),
    "output_dir": "results/expert_candidate_validation",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, default in DEFAULTS.items():
        parser.add_argument(f"--{name.replace('_', '-')}", default=default)
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Evaluate available candidate rows while preserving partial-result warnings.",
    )
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc


def load_by(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row.get(key)
        if not value:
            raise ValueError(f"{path}: row missing {key}")
        if value in rows:
            raise ValueError(f"{path}: duplicate {key}={value}")
        rows[value] = row
    if not rows:
        raise ValueError(f"No rows in {path}")
    return rows


def validate_candidates(
    path: Path, expected_count: int, *, allow_partial: bool
) -> dict[str, dict]:
    if not path.exists():
        if allow_partial:
            return {}
        raise FileNotFoundError(path)
    rows = load_by(path, "sample_id")
    if len(rows) > expected_count:
        raise ValueError(f"{path}: expected at most {expected_count} rows, found {len(rows)}")
    if len(rows) != expected_count and not allow_partial:
        raise ValueError(f"{path}: expected {expected_count} rows, found {len(rows)}")
    for sample_id, row in rows.items():
        if row.get("label_is_human") is not False:
            raise ValueError(f"{path}: {sample_id} must set label_is_human=false")
        if row.get("annotator_type") != "ai_security_expert":
            raise ValueError(f"{path}: {sample_id} has invalid annotator_type")
        annotation = row.get("annotation") or {}
        if annotation.get("discrepancy_label") not in LABELS:
            raise ValueError(f"{path}: {sample_id} has invalid discrepancy_label")
        if annotation.get("adjudicated_source") not in SOURCES:
            raise ValueError(f"{path}: {sample_id} has invalid adjudicated_source")
    return rows


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def classification_metrics(records: list[dict], gold_key: str, pred_key: str) -> dict:
    labels = sorted(
        set(LABELS)
        | {record[gold_key] for record in records}
        | {record[pred_key] for record in records}
    )
    gold_counts = Counter(record[gold_key] for record in records)
    pred_counts = Counter(record[pred_key] for record in records)
    per_label = {}
    supported_f1 = []
    for label in labels:
        tp = sum(
            record[gold_key] == label and record[pred_key] == label
            for record in records
        )
        fp = sum(
            record[gold_key] != label and record[pred_key] == label
            for record in records
        )
        fn = sum(
            record[gold_key] == label and record[pred_key] != label
            for record in records
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
            supported_f1.append(f1)
    correct = sum(record[gold_key] == record[pred_key] for record in records)
    return {
        "row_count": len(records),
        "agreement": safe_divide(correct, len(records)),
        "macro_f1_over_supported_candidate_labels": safe_divide(
            sum(supported_f1), len(supported_f1)
        ),
        "candidate_label_counts": dict(sorted(gold_counts.items())),
        "predicted_label_counts": dict(sorted(pred_counts.items())),
        "per_label": per_label,
    }


def cohen_kappa(confusion: Counter, labels: tuple[str, ...], total: int) -> float:
    observed = safe_divide(sum(confusion[(label, label)] for label in labels), total)
    left = Counter()
    right = Counter()
    for (left_label, right_label), count in confusion.items():
        left[left_label] += count
        right[right_label] += count
    expected = sum(
        safe_divide(left[label], total) * safe_divide(right[label], total)
        for label in labels
    )
    if expected == 1:
        return 1.0 if observed == 1 else 0.0
    return safe_divide(observed - expected, 1 - expected)


def rq2_metrics(
    primary_candidates: dict[str, dict],
    review_candidates: dict[str, dict],
    primary_source: dict[str, dict],
    review_source: dict[str, dict],
) -> dict:
    if not set(primary_candidates).issubset(primary_source):
        raise ValueError("RQ2 primary candidates contain unknown source sample_ids")

    records = []
    for sample_id, candidate_row in primary_candidates.items():
        source = primary_source[sample_id]
        candidate = candidate_row["annotation"]
        records.append(
            {
                "sample_id": sample_id,
                "field": source["field"],
                "candidate_label": candidate["discrepancy_label"],
                "baseline_label": source["baseline_status"],
            }
        )
    determinate = [record for record in records if record["candidate_label"] != "uncertain"]
    baseline_metrics = classification_metrics(
        determinate, "candidate_label", "baseline_label"
    )
    baseline_metrics["total_candidate_rows"] = len(records)
    baseline_metrics["determinate_coverage"] = safe_divide(len(determinate), len(records))

    repeatability_records = []
    for review_sample_id, review_candidate in review_candidates.items():
        review = review_source.get(review_sample_id)
        if not review:
            raise ValueError(f"Unknown RQ2 review source row {review_sample_id}")
        original_id = review["original_sample_id"]
        if original_id not in primary_candidates:
            continue
        repeatability_records.append(
            {
                "original_sample_id": original_id,
                "field": review["field"],
                "primary_label": primary_candidates[original_id]["annotation"][
                    "discrepancy_label"
                ],
                "review_label": review_candidate["annotation"][
                    "discrepancy_label"
                ],
            }
        )
    confusion = Counter(
        (record["primary_label"], record["review_label"])
        for record in repeatability_records
    )
    agreement_count = sum(
        record["primary_label"] == record["review_label"]
        for record in repeatability_records
    )
    repeatability = {
        "row_count": len(repeatability_records),
        "agreement_count": agreement_count,
        "agreement_rate": safe_divide(agreement_count, len(repeatability_records)),
        "cohen_kappa_same_model_repeatability": cohen_kappa(
            confusion, LABELS, len(repeatability_records)
        ),
        "independent_human_annotators": False,
        "caution": "This is same-model repeatability across separate passes, not human inter-annotator agreement.",
    }
    return {
        "baseline_vs_expert_candidate": baseline_metrics,
        "same_model_repeatability": repeatability,
        "candidate_needs_human_review": sum(
            bool(row["annotation"].get("needs_human_review"))
            for row in primary_candidates.values()
        ),
    }


def source_metrics(records: list[dict]) -> dict:
    labels = sorted(
        set(SOURCES)
        | {record["candidate_source"] for record in records}
        | {record["predicted_source"] for record in records}
    )
    candidate_counts = Counter(record["candidate_source"] for record in records)
    pred_counts = Counter(record["predicted_source"] for record in records)
    per_label = {}
    supported_f1 = []
    for label in labels:
        tp = sum(
            record["candidate_source"] == label
            and record["predicted_source"] == label
            for record in records
        )
        fp = sum(
            record["candidate_source"] != label
            and record["predicted_source"] == label
            for record in records
        )
        fn = sum(
            record["candidate_source"] == label
            and record["predicted_source"] != label
            for record in records
        )
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall)
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": candidate_counts[label],
            "predicted": pred_counts[label],
        }
        if candidate_counts[label]:
            supported_f1.append(f1)
    correct = sum(
        record["candidate_source"] == record["predicted_source"]
        for record in records
    )
    non_abstain = [record for record in records if record["predicted_source"] != "abstain"]
    non_abstain_correct = sum(
        record["candidate_source"] == record["predicted_source"]
        for record in non_abstain
    )
    return {
        "total": len(records),
        "agreement_vs_expert_candidate": safe_divide(correct, len(records)),
        "macro_f1_over_supported_candidate_sources": safe_divide(
            sum(supported_f1), len(supported_f1)
        ),
        "coverage_non_abstain": safe_divide(len(non_abstain), len(records)),
        "agreement_when_non_abstain": safe_divide(
            non_abstain_correct, len(non_abstain)
        ),
        "candidate_source_counts": dict(sorted(candidate_counts.items())),
        "predicted_source_counts": dict(sorted(pred_counts.items())),
        "per_label": per_label,
    }


def rq3_metrics(
    field: str,
    candidates: dict[str, dict],
    evidence_rows: dict[str, dict],
    silver_rows: dict[str, dict],
) -> tuple[dict, list[dict]]:
    if not set(candidates).issubset(evidence_rows) or not set(candidates).issubset(
        silver_rows
    ):
        raise ValueError(f"RQ3 {field} candidates contain unknown sample_ids")
    validate_rq3_candidate_contract(field, candidates, evidence_rows)
    predictions_by_method = {
        name: [] for name in predictors_for_field(field)
    }
    prediction_rows = []
    candidate_silver_label_agreement = 0
    candidate_silver_source_agreement = 0
    for sample_id, candidate_row in candidates.items():
        annotation = candidate_row["annotation"]
        silver = silver_rows[sample_id]["llm_annotation"]
        candidate_silver_label_agreement += (
            annotation["discrepancy_label"] == silver["llm_label"]
        )
        candidate_silver_source_agreement += (
            annotation["adjudicated_source"] == silver["adjudicated_source"]
        )
        for method, predictor in predictors_for_field(field).items():
            prediction = predictor(evidence_rows[sample_id])
            record = {
                "sample_id": sample_id,
                "cve_id": annotation["cve_id"],
                "field": field,
                "method": method,
                "candidate_label": annotation["discrepancy_label"],
                "candidate_source": annotation["adjudicated_source"],
                "predicted_source": prediction["predicted_source"],
                "is_correct_vs_candidate": (
                    prediction["predicted_source"] == annotation["adjudicated_source"]
                ),
                "rule": prediction["rule"],
            }
            predictions_by_method[method].append(record)
            prediction_rows.append(record)

    metrics = {
        "row_count": len(candidates),
        "candidate_contract_validated": True,
        "candidate_label_counts": dict(
            sorted(
                Counter(
                    row["annotation"]["discrepancy_label"]
                    for row in candidates.values()
                ).items()
            )
        ),
        "candidate_source_counts": dict(
            sorted(
                Counter(
                    row["annotation"]["adjudicated_source"]
                    for row in candidates.values()
                ).items()
            )
        ),
        "candidate_needs_human_review": sum(
            bool(row["annotation"].get("needs_human_review"))
            for row in candidates.values()
        ),
        "agreement_with_silver_v2": {
            "discrepancy_label": safe_divide(
                candidate_silver_label_agreement, len(candidates)
            ),
            "adjudicated_source": safe_divide(
                candidate_silver_source_agreement, len(candidates)
            ),
            "same_model_family_not_independent_human_review": True,
        },
        "methods": {
            method: source_metrics(records)
            for method, records in predictions_by_method.items()
        },
    }
    return metrics, prediction_rows


def validate_rq3_candidate_contract(
    field: str,
    candidates: dict[str, dict],
    evidence_rows: dict[str, dict],
) -> None:
    errors = []
    for sample_id, candidate in sorted(candidates.items()):
        annotation = candidate.get("annotation") or {}
        evidence = evidence_rows[sample_id]
        if annotation.get("sample_id") != sample_id:
            errors.append(f"{sample_id}: annotation sample_id mismatch")
        if annotation.get("cve_id") != evidence.get("cve_id"):
            errors.append(f"{sample_id}: annotation cve_id mismatch")
        if annotation.get("field") != field or evidence.get("field") != field:
            errors.append(f"{sample_id}: field mismatch")

        evidence_urls = annotation.get("evidence_urls")
        if not isinstance(evidence_urls, list) or not all(
            isinstance(url, str) and url.strip() for url in evidence_urls
        ):
            errors.append(f"{sample_id}: evidence_urls must be nonblank strings")
            evidence_urls = []
        allowed_urls = {
            record.get("url")
            for record in (evidence.get("evidence_context") or {}).get("records", [])
            if record.get("url")
        }
        untraceable = sorted(set(evidence_urls) - allowed_urls)
        if untraceable:
            errors.append(
                f"{sample_id}: untraceable evidence_urls={untraceable[:3]}"
            )

        source = annotation.get("adjudicated_source")
        if source != "abstain":
            if not evidence_urls:
                errors.append(f"{sample_id}: non-abstain decision requires evidence_urls")
            if len(str(annotation.get("evidence_notes") or "").strip()) < 10:
                errors.append(f"{sample_id}: non-abstain decision requires evidence_notes")

        reasoning_type = annotation.get("version_reasoning_type")
        if field == "affected_versions":
            if reasoning_type not in VERSION_REASONING - {"not_applicable"}:
                errors.append(
                    f"{sample_id}: invalid affected_versions reasoning={reasoning_type!r}"
                )
        elif reasoning_type != "not_applicable":
            errors.append(f"{sample_id}: non-version field requires not_applicable")

        if (
            annotation.get("discrepancy_label") == "uncertain"
            or annotation.get("confidence") == "low"
        ) and annotation.get("needs_human_review") is not True:
            errors.append(f"{sample_id}: uncertain/low candidate requires human review")

    if errors:
        raise ValueError(
            f"RQ3 {field} candidate contract errors: " + "; ".join(errors[:20])
        )


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def render_markdown(metrics: dict) -> str:
    lines = [
        "# Expert-Candidate Validation",
        "",
        "These are AI security-expert candidate diagnostics, not human-gold results.",
        "",
    ]
    rq2 = metrics.get("rq2")
    if rq2:
        lines.extend(
            [
                "## RQ2",
                "",
                f"- Candidate rows: `{rq2['baseline_vs_expert_candidate']['total_candidate_rows']}`",
                f"- Determinate coverage: `{rq2['baseline_vs_expert_candidate']['determinate_coverage']:.4f}`",
                f"- Baseline agreement vs candidate: `{rq2['baseline_vs_expert_candidate']['agreement']:.4f}`",
                f"- Macro-F1 vs candidate: `{rq2['baseline_vs_expert_candidate']['macro_f1_over_supported_candidate_labels']:.4f}`",
                f"- Same-model repeatability rows: `{rq2['same_model_repeatability']['row_count']}`",
                f"- Same-model repeatability: `{rq2['same_model_repeatability']['agreement_rate']:.4f}`",
                f"- Same-model kappa: `{rq2['same_model_repeatability']['cohen_kappa_same_model_repeatability']:.4f}`",
                "",
            ]
        )
    for field in ("severity", "affected_versions"):
        section = metrics["rq3"].get(field)
        if not section:
            lines.extend(
                [f"## RQ3 {field}", "", "- Candidate data unavailable.", ""]
            )
            continue
        lines.extend(
            [
                f"## RQ3 {field}",
                "",
                f"- Candidate rows: `{section['row_count']}`",
                f"- Needs human review: `{section['candidate_needs_human_review']}`",
                f"- Candidate/silver label agreement: `{section['agreement_with_silver_v2']['discrepancy_label']:.4f}`",
                f"- Candidate/silver source agreement: `{section['agreement_with_silver_v2']['adjudicated_source']:.4f}`",
                "",
                "| Method | Agreement vs candidate | Macro-F1 | Coverage |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for method, values in section["methods"].items():
            lines.append(
                f"| {method} | {values['agreement_vs_expert_candidate']:.4f} | "
                f"{values['macro_f1_over_supported_candidate_sources']:.4f} | "
                f"{values['coverage_non_abstain']:.4f} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Boundary",
            "",
            "- `label_is_human=false`",
            "- `author_review_required=true`",
            "- Do not report these values as human inter-annotator agreement or gold-backed performance.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        name: resolve_path(getattr(args, name))
        for name in DEFAULTS
    }
    output_dir = paths["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)

    rq2_primary = validate_candidates(
        paths["rq2_primary"], 300, allow_partial=args.allow_partial
    )
    rq2_review = validate_candidates(
        paths["rq2_review"], 60, allow_partial=args.allow_partial
    )
    rq3_severity = validate_candidates(
        paths["rq3_severity"], 80, allow_partial=args.allow_partial
    )
    rq3_affected = validate_candidates(
        paths["rq3_affected"], 100, allow_partial=args.allow_partial
    )

    severity_metrics = None
    severity_predictions = []
    if rq3_severity:
        severity_metrics, severity_predictions = rq3_metrics(
            "severity",
            rq3_severity,
            load_by(paths["severity_evidence"], "sample_id"),
            load_by(paths["severity_silver"], "sample_id"),
        )
    affected_metrics = None
    affected_predictions = []
    if rq3_affected:
        affected_metrics, affected_predictions = rq3_metrics(
            "affected_versions",
            rq3_affected,
            load_by(paths["affected_evidence"], "sample_id"),
            load_by(paths["affected_silver"], "sample_id"),
        )
    metrics = {
        "artifact_type": "ai_security_expert_candidate_validation",
        "label_is_human": False,
        "author_review_required": True,
        "candidate_status": "unreviewed_partial" if args.allow_partial else "unreviewed",
        "allow_partial": args.allow_partial,
        "input_paths": {name: str(path) for name, path in paths.items()},
        "rq2": (
            rq2_metrics(
                rq2_primary,
                rq2_review,
                load_by(paths["rq2_source"], "sample_id"),
                load_by(paths["rq2_review_source"], "review_sample_id"),
            )
            if rq2_primary
            else None
        ),
        "rq3": {},
        "cautions": [
            "Candidate labels were generated by an AI security-expert pass, not humans.",
            "RQ2 repeatability uses the same model family and is not inter-annotator agreement.",
            "RQ3 comparison with silver_v2 is not an independent human validation.",
            "Author review and explicit sign-off are required before any human-gold claim.",
        ],
    }
    if severity_metrics:
        metrics["rq3"]["severity"] = severity_metrics
    if affected_metrics:
        metrics["rq3"]["affected_versions"] = affected_metrics
    metrics_path = output_dir / "expert_candidate_metrics.json"
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "expert_candidate_metrics.md").write_text(
        render_markdown(metrics), encoding="utf-8"
    )
    write_jsonl(
        output_dir / "rq3_expert_candidate_predictions.jsonl",
        severity_predictions + affected_predictions,
    )
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
