#!/usr/bin/env python3
"""Build COSE manuscript tables from reproducible project artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DISCREPANCY_STATS = (
    "data/processed/bootstrap/discrepancies/field_discrepancy_stats.json"
)
DEFAULT_RQ1_COVERAGE = (
    "results/rq1_discrepancy_distribution/bootstrap_field_coverage_summary.json"
)
DEFAULT_RQ2_DIAGNOSTICS = (
    "results/rq2_discrepancy_typing/rq2_typing_diagnostics.json"
)
DEFAULT_RQ2_SAMPLE_COVERAGE = (
    "results/rq2_discrepancy_typing/rq2_sample_coverage.json"
)
DEFAULT_RQ3_METRICS = "results/rq3_adjudication/severity_silver_v2_eval_metrics.json"
DEFAULT_RQ3_PREDICTIONS = "results/rq3_adjudication/severity_silver_v2_predictions.jsonl"
DEFAULT_AFFECTED_RQ3_METRICS = (
    "results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json"
)
DEFAULT_AFFECTED_RQ3_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_RQ3_EVIDENCE = (
    "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl"
)
DEFAULT_RQ3_MANIFEST = (
    "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence_manifest.json"
)
DEFAULT_AFFECTED_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_AFFECTED_MANIFEST = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence_manifest.json"
)
DEFAULT_AFFECTED_SILVER = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
)
DEFAULT_RQ3_ERROR_MODES = "results/rq3_adjudication/rq3_silver_error_modes.json"
DEFAULT_AFFECTED_ALIGNMENT = (
    "results/rq3_adjudication/affected_versions_alignment_diagnostics.json"
)
DEFAULT_RQ3_SENSITIVITY = (
    "results/rq3_adjudication/rq3_silver_baseline_sensitivity.json"
)
DEFAULT_EVIDENCE_RELIABILITY = (
    "results/rq3_adjudication/evidence_source_reliability.json"
)
DEFAULT_RQ3_AUDIT_READINESS = (
    "results/rq3_adjudication/rq3_human_audit_readiness.json"
)
DEFAULT_OUTPUT_DIR = "results/paper_cose"

DISCREPANCY_TYPES = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build markdown/JSON COSE paper tables from existing results."
    )
    parser.add_argument("--discrepancy-stats", default=DEFAULT_DISCREPANCY_STATS)
    parser.add_argument("--rq1-coverage", default=DEFAULT_RQ1_COVERAGE)
    parser.add_argument("--rq2-diagnostics", default=DEFAULT_RQ2_DIAGNOSTICS)
    parser.add_argument("--rq2-sample-coverage", default=DEFAULT_RQ2_SAMPLE_COVERAGE)
    parser.add_argument("--rq3-metrics", default=DEFAULT_RQ3_METRICS)
    parser.add_argument("--rq3-predictions", default=DEFAULT_RQ3_PREDICTIONS)
    parser.add_argument("--affected-rq3-metrics", default=DEFAULT_AFFECTED_RQ3_METRICS)
    parser.add_argument(
        "--affected-rq3-predictions", default=DEFAULT_AFFECTED_RQ3_PREDICTIONS
    )
    parser.add_argument("--rq3-evidence", default=DEFAULT_RQ3_EVIDENCE)
    parser.add_argument("--rq3-manifest", default=DEFAULT_RQ3_MANIFEST)
    parser.add_argument("--affected-evidence", default=DEFAULT_AFFECTED_EVIDENCE)
    parser.add_argument("--affected-manifest", default=DEFAULT_AFFECTED_MANIFEST)
    parser.add_argument("--affected-silver", default=DEFAULT_AFFECTED_SILVER)
    parser.add_argument("--rq3-error-modes", default=DEFAULT_RQ3_ERROR_MODES)
    parser.add_argument("--affected-alignment", default=DEFAULT_AFFECTED_ALIGNMENT)
    parser.add_argument("--rq3-sensitivity", default=DEFAULT_RQ3_SENSITIVITY)
    parser.add_argument("--evidence-reliability", default=DEFAULT_EVIDENCE_RELIABILITY)
    parser.add_argument("--rq3-audit-readiness", default=DEFAULT_RQ3_AUDIT_READINESS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def pct(count: int | float, total: int | float, digits: int = 1) -> str:
    if not total:
        return f"{0:.{digits}f}%"
    return f"{count / total * 100:.{digits}f}%"


def metric(value: float) -> str:
    return f"{value:.3f}"


def table(headers: list[str], rows: list[list[str]]) -> str:
    align = ["---"] + ["---:" for _ in headers[1:]]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(align) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def claim_boundary_rows() -> list[dict]:
    return [
        {
            "rq": "RQ1",
            "artifact": "field_discrepancy_stats; RQ1 coverage summary",
            "label_source": "deterministic field rules",
            "allowed_claim": "baseline discrepancy distribution across aligned NVD-GHSA fields",
            "not_claimed": "gold discrepancy labels or source correctness",
        },
        {
            "rq": "RQ2",
            "artifact": "typing diagnostics; blank annotation seed and consistency template",
            "label_source": "deterministic rule triggers plus blank human-label templates",
            "allowed_claim": "rule-trigger coverage and annotation-readiness diagnostics",
            "not_claimed": "typing accuracy, precision, recall, macro-F1, or agreement",
        },
        {
            "rq": "RQ3 severity",
            "artifact": "severity silver-v2 evidence and predictions",
            "label_source": "evidence-aware LLM silver labels",
            "allowed_claim": "silver-label evidence-availability and baseline diagnostics",
            "not_claimed": "human-gold adjudication performance or final source truth",
        },
        {
            "rq": "RQ3 affected_versions",
            "artifact": "affected_versions silver-v2, alignment, sensitivity diagnostics",
            "label_source": "evidence-aware LLM silver labels plus structural diagnostics",
            "allowed_claim": "token-support and structural manual-audit prioritization",
            "not_claimed": "semantic version-range adjudication or validated false-positive rate",
        },
    ]


def build_claim_boundary_table() -> tuple[str, list[dict]]:
    rows = claim_boundary_rows()
    md_rows = [
        [
            row["rq"],
            row["artifact"],
            row["label_source"],
            row["allowed_claim"],
            row["not_claimed"],
        ]
        for row in rows
    ]
    headers = ["RQ", "Artifact", "Label source", "Allowed claim", "Not claimed"]
    return table(headers, md_rows), rows


def build_discrepancy_table(stats: dict) -> tuple[str, list[dict]]:
    processed_pairs = stats["processed_pairs"]
    summary_rows = []
    md_rows = []
    for field in sorted(stats["fields"]):
        field_counts = stats["fields"][field]
        output_row = {"field": field, "total_pairs": processed_pairs}
        md_row = [field]
        for dtype in DISCREPANCY_TYPES:
            count = field_counts.get(dtype, 0)
            output_row[dtype] = count
            output_row[f"{dtype}_rate"] = count / processed_pairs if processed_pairs else 0.0
            md_row.append(f"{count} ({pct(count, processed_pairs, digits=2)})")
        summary_rows.append(output_row)
        md_rows.append(md_row)

    headers = [
        "Field",
        "Equivalent",
        "Representation",
        "Incomplete",
        "Temporal",
        "Factual conflict",
    ]
    return table(headers, md_rows), summary_rows


def build_coverage_table(coverage: dict) -> tuple[str, list[dict]]:
    rows = []
    md_rows = []
    for field, values in coverage["field_coverage"].items():
        row = {
            "field": field,
            "nvd_nonempty_rate": values["nvd_nonempty_rate"],
            "ghsa_nonempty_rate": values["matched_ghsa_nonempty_rate"],
            "both_nonempty_rate": values["matched_both_nonempty_rate"],
            "nvd_only_rate": values["matched_nvd_only_rate"],
            "ghsa_only_rate": values["matched_ghsa_only_rate"],
        }
        rows.append(row)
        md_rows.append(
            [
                field,
                pct(values["nvd_nonempty_rate"], 1),
                pct(values["matched_ghsa_nonempty_rate"], 1),
                pct(values["matched_both_nonempty_rate"], 1),
                pct(values["matched_nvd_only_rate"], 1),
                pct(values["matched_ghsa_only_rate"], 1),
            ]
        )
    headers = ["Field", "NVD", "GHSA", "Both", "NVD only", "GHSA only"]
    return table(headers, md_rows), rows


def build_dataset_field_coverage_table(coverage: dict) -> tuple[str, list[dict]]:
    field_labels = {
        "severity": "severity",
        "published_date": "published/date",
        "references": "references",
        "affected": "affected_versions",
        "cwe": "cwe_ids",
    }
    rows = []
    md_rows = []
    for source_field, field in field_labels.items():
        values = coverage["field_coverage"][source_field]
        row = {
            "field": field,
            "nvd_nonempty": values["nvd_nonempty"],
            "ghsa_nonempty": values["matched_ghsa_nonempty"],
            "both_nonempty": values["matched_both_nonempty"],
            "nvd_only": values["matched_nvd_only"],
            "ghsa_only": values["matched_ghsa_only"],
            "both_empty": values["matched_both_empty"],
        }
        rows.append(row)
        md_rows.append(
            [
                field,
                str(values["nvd_nonempty"]),
                str(values["matched_ghsa_nonempty"]),
                str(values["matched_both_nonempty"]),
                str(values["matched_nvd_only"]),
                str(values["matched_ghsa_only"]),
                str(values["matched_both_empty"]),
            ]
        )
    headers = [
        "Field",
        "NVD nonempty",
        "GHSA nonempty",
        "Both nonempty",
        "NVD only",
        "GHSA only",
        "Both empty",
    ]
    return table(headers, md_rows), rows


def build_rq3_table(metrics: dict) -> tuple[str, list[dict]]:
    rows = []
    md_rows = []
    method_order = [
        "prefer_nvd",
        "prefer_ghsa",
        "latest_published",
        "evidence_score_baseline",
        "version_token_support_baseline",
        "canonical_version_token_support_baseline",
        "package_gated_token_baseline",
        "package_gated_canonical_token_baseline",
        "package_range_evidence_baseline",
    ]
    for method_name in method_order:
        if method_name not in metrics["methods"]:
            continue
        values = metrics["methods"][method_name]
        row = {
            "method": method_name,
            "accuracy": values["accuracy"],
            "macro_f1": values["macro_f1_over_supported_silver_labels"],
            "coverage_non_abstain": values["coverage_non_abstain"],
            "accuracy_when_non_abstain": values["accuracy_when_non_abstain"],
            "predicted_source_counts": values["predicted_source_counts"],
        }
        rows.append(row)
        md_rows.append(
            [
                method_name,
                metric(values["accuracy"]),
                metric(values["macro_f1_over_supported_silver_labels"]),
                metric(values["coverage_non_abstain"]),
                metric(values["accuracy_when_non_abstain"]),
            ]
        )
    headers = [
        "Method",
        "Silver-label agreement",
        "Macro-F1 vs silver",
        "Coverage",
        "Selective agreement",
    ]
    return table(headers, md_rows), rows


def summarize_predictions(prediction_path: Path) -> dict:
    by_method = defaultdict(list)
    for row in iter_jsonl(prediction_path):
        by_method[row["method"]].append(row)

    summaries = {}
    for method, rows in sorted(by_method.items()):
        confusion = Counter(
            f"{row['silver_source']}->{row['predicted_source']}" for row in rows
        )
        errors = [
            {
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "silver_source": row["silver_source"],
                "predicted_source": row["predicted_source"],
                "silver_label": row["silver_label"],
            }
            for row in rows
            if not row["is_correct"]
        ]
        summaries[method] = {
            "confusion": dict(sorted(confusion.items())),
            "error_count": len(errors),
            "first_errors": errors[:10],
        }
    return summaries


def summarize_evidence(evidence_path: Path, manifest: dict) -> dict:
    sample_fetch_statuses = Counter()
    ok_record_counts = []
    host_counts = Counter()
    samples_with_ok = 0
    samples = 0
    for row in iter_jsonl(evidence_path):
        samples += 1
        ok_records = 0
        for record in row.get("evidence_context", {}).get("records", []):
            status = record.get("fetch_status") or "missing"
            sample_fetch_statuses[status] += 1
            if status == "ok":
                ok_records += 1
                host_counts[record.get("host") or ""] += 1
        ok_record_counts.append(ok_records)
        if ok_records:
            samples_with_ok += 1

    return {
        "sample_count": samples,
        "samples_with_ok_evidence": samples_with_ok,
        "samples_with_ok_evidence_rate": samples_with_ok / samples if samples else 0.0,
        "ok_records_min": min(ok_record_counts) if ok_record_counts else 0,
        "ok_records_max": max(ok_record_counts) if ok_record_counts else 0,
        "ok_records_mean": (
            sum(ok_record_counts) / len(ok_record_counts) if ok_record_counts else 0.0
        ),
        "fetch_status_counts_from_manifest": manifest.get("fetch_status_counts", {}),
        "fetch_status_counts_from_rows": dict(sorted(sample_fetch_statuses.items())),
        "top_ok_hosts": host_counts.most_common(10),
    }


def summarize_llm_silver(annotation_path: Path) -> dict:
    count_fields = (
        "llm_label",
        "is_baseline_false_positive",
        "adjudicated_source",
        "confidence",
    )
    counters = {field: Counter() for field in count_fields}
    sample_ids = Counter()
    missing_annotation = 0
    rows_with_missing_required = 0
    total = 0

    for row in iter_jsonl(annotation_path):
        total += 1
        sample_id = row.get("sample_id")
        if sample_id:
            sample_ids[sample_id] += 1
        annotation = row.get("llm_annotation")
        if not isinstance(annotation, dict):
            missing_annotation += 1
            rows_with_missing_required += 1
            continue
        missing = [field for field in count_fields if not annotation.get(field)]
        if missing:
            rows_with_missing_required += 1
        for field in count_fields:
            counters[field][annotation.get(field) or "missing"] += 1

    duplicate_sample_ids = {
        sample_id: count for sample_id, count in sample_ids.items() if count > 1
    }
    return {
        "path": str(annotation_path),
        "total_rows": total,
        "unique_sample_ids": len(sample_ids),
        "duplicate_sample_ids": duplicate_sample_ids,
        "missing_annotation_rows": missing_annotation,
        "rows_with_missing_required_fields": rows_with_missing_required,
        "llm_label": dict(sorted(counters["llm_label"].items())),
        "is_baseline_false_positive": dict(
            sorted(counters["is_baseline_false_positive"].items())
        ),
        "adjudicated_source": dict(sorted(counters["adjudicated_source"].items())),
        "confidence": dict(sorted(counters["confidence"].items())),
    }


def build_affected_versions_structural_table(
    affected_alignment: dict | None,
) -> tuple[str | None, list[dict] | None]:
    if not affected_alignment:
        return None, None
    counts = affected_alignment.get("diagnostic_counts", {})
    row_specs = [
        (
            "Package-name profile",
            "No exact or leaf-level package-name overlap",
            counts.get("package_category", {}).get("no_package_name_overlap", 0),
            "package-identity audit risk",
        ),
        (
            "Package-name profile",
            "Exact package overlap",
            counts.get("package_category", {}).get("exact_package_overlap", 0),
            "lower package-name ambiguity",
        ),
        (
            "Package-name profile",
            "Leaf package overlap only",
            counts.get("package_category", {}).get("leaf_package_overlap_only", 0),
            "namespace/package normalization needed",
        ),
        (
            "Version-shape profile",
            "NVD point versions vs GHSA ranges",
            counts.get("version_shape_category", {}).get("nvd_points_vs_ghsa_ranges", 0),
            "range-shape audit risk",
        ),
        (
            "Version-token overlap",
            "No shared version tokens",
            counts.get("token_overlap", {}).get("no_shared_version_tokens", 0),
            "token-support fragility",
        ),
        (
            "Combined diagnostic",
            "Package mismatch",
            counts.get("combined_category", {}).get("package_mismatch", 0),
            "manual-audit prioritization",
        ),
    ]
    rows = [
        {
            "dimension": dimension,
            "profile": profile,
            "samples": samples,
            "interpretation": interpretation,
        }
        for dimension, profile, samples, interpretation in row_specs
    ]
    md_rows = [
        [row["dimension"], row["profile"], str(row["samples"]), row["interpretation"]]
        for row in rows
    ]
    headers = ["Dimension", "Diagnostic profile", "Samples", "Interpretation"]
    return table(headers, md_rows), rows


def render_summary(
    discrepancy_md: str,
    coverage_md: str,
    claim_boundary_md: str,
    dataset_field_coverage_md: str,
    rq2_diagnostics: dict | None,
    rq2_sample_coverage: dict | None,
    rq3_md: str,
    evidence_summary: dict,
    affected_evidence_summary: dict | None,
    affected_silver_summary: dict | None,
    prediction_summary: dict,
    coverage: dict,
    metrics: dict,
    affected_rq3_md: str | None,
    affected_rq3_rows: list[dict] | None,
    affected_rq3_metrics: dict | None,
    rq3_error_modes: dict | None,
    affected_alignment: dict | None,
    affected_structural_md: str | None,
    rq3_sensitivity: dict | None,
    evidence_reliability: dict | None,
    rq3_audit_readiness: dict | None,
) -> str:
    lines = [
        "# COSE Paper Artifact Tables",
        "",
        "These tables are generated from repository artifacts. RQ3 labels are evidence-aware LLM silver labels, not human gold labels.",
        "",
        "## Dataset Coverage",
        "",
        f"- Normalized NVD records: {coverage['total_rows']}",
        f"- CVE-ID aligned NVD-GHSA pairs: {coverage['matched_rows']} ({coverage['matched_rate']:.3%})",
        f"- Rows with multiple GHSA records: {coverage['rows_with_multiple_ghsa']}",
        "",
        coverage_md,
        "",
        "## Claim Boundary Matrix",
        "",
        "This matrix records which claims each current artifact supports. It is intended to prevent deterministic baselines, blank annotation templates, or silver labels from being read as human gold.",
        "",
        claim_boundary_md,
        "",
        "## Manuscript Field Coverage Table",
        "",
        "This compact table is promoted into the manuscript setup section. Counts are measured over the 100,032 normalized NVD records for the NVD column and over the 8,066 CVE-ID aligned NVD-GHSA pairs for GHSA/Both/one-sided columns.",
        "",
        dataset_field_coverage_md,
        "",
        "## Field-Level Discrepancy Distribution",
        "",
        discrepancy_md,
        "",
    ]

    if rq2_diagnostics:
        lines.extend(
            [
                "## RQ2 Typing Diagnostics",
                "",
                "This is a baseline rule-trigger diagnostic, not a gold-label accuracy result.",
                "",
                f"- Field instances: {rq2_diagnostics['field_instance_count']}",
                f"- Binary-different instances: {rq2_diagnostics['overall']['binary_different']}",
                f"- Non-conflict differences among binary-different instances: {rq2_diagnostics['overall']['non_conflict_different']} ({rq2_diagnostics['overall']['non_conflict_different_rate_among_binary_different']:.1%})",
                f"- Factual conflicts among binary-different instances: {rq2_diagnostics['overall']['factual_conflict']} ({rq2_diagnostics['overall']['factual_conflict_rate_among_binary_different']:.1%})",
                "",
                "Top deterministic rule triggers:",
                "",
                table(
                    ["Field", "Status", "Rule note", "Count"],
                    [
                        [
                            item["field"],
                            item["status"],
                            item["note"],
                            str(item["count"]),
                        ]
                        for item in rq2_diagnostics.get("rule_triggers", [])[:8]
                    ],
                ),
                "",
            ]
        )

    if rq2_sample_coverage:
        primary = rq2_sample_coverage["primary_seed"]
        review = rq2_sample_coverage["consistency_review"]
        trigger = rq2_sample_coverage["rule_trigger_coverage"]
        lines.extend(
            [
                "## RQ2 Annotation Sample Readiness",
                "",
                "This is a blank annotation-template readiness diagnostic, not a gold-label evaluation or agreement result.",
                "",
                f"- Primary seed rows: {primary['row_count']}",
                f"- Blank primary manual labels: {primary['blank_manual_status_rows']}/{primary['row_count']}",
                f"- Primary field coverage: {', '.join(f'{field}={count}' for field, count in primary['field_counts'].items())}",
                f"- Nonzero field/status candidate strata sampled: {primary['sampled_nonzero_candidate_strata']}/{primary['nonzero_candidate_strata']}",
                f"- Distinct primary sampled rule triggers: {primary['distinct_sampled_rule_triggers']}",
                f"- Consistency review rows: {review['row_count']}",
                f"- Blank reviewer labels: {review['blank_reviewer_status_rows']}/{review['row_count']}",
                f"- Top full-corpus rule triggers covered by primary seed: {trigger['covered_top_triggers']}/{trigger['top_trigger_count']}",
                "",
                table(
                    ["Status", "Primary rows"],
                    [
                        [status, str(primary["status_counts"].get(status, 0))]
                        for status in DISCREPANCY_TYPES
                    ],
                ),
                "",
            ]
        )

    lines.extend(
        [
        "## RQ3 Severity Silver-Label Diagnostic Comparison",
        "",
        f"- Samples: {metrics['sample_count']}",
        f"- Silver labels are gold: {metrics['silver_label_is_gold']}",
        f"- Samples with at least one fetched evidence record: {evidence_summary['samples_with_ok_evidence']}/{evidence_summary['sample_count']} ({evidence_summary['samples_with_ok_evidence_rate']:.1%})",
        f"- Mean successful evidence records per sample: {evidence_summary['ok_records_mean']:.2f}",
        "",
        rq3_md,
        "",
        "## RQ3 Evidence Fetch Status",
        "",
        table(
            ["Status", "Count"],
            [
                [status, str(count)]
                for status, count in sorted(
                    evidence_summary["fetch_status_counts_from_manifest"].items()
                )
            ],
        ),
        "",
        ]
    )

    if affected_evidence_summary:
        lines.extend(
            [
                "## Affected Versions Evidence Availability",
                "",
                "This section reports evidence availability for the affected_versions silver-label sample. It is not an adjudication metric.",
                "",
                f"- Samples: {affected_evidence_summary['sample_count']}",
                f"- Samples with at least one fetched evidence record: {affected_evidence_summary['samples_with_ok_evidence']}/{affected_evidence_summary['sample_count']} ({affected_evidence_summary['samples_with_ok_evidence_rate']:.1%})",
                f"- Mean successful evidence records per sample: {affected_evidence_summary['ok_records_mean']:.2f}",
                "",
                table(
                    ["Status", "Count"],
                    [
                        [status, str(count)]
                        for status, count in sorted(
                            affected_evidence_summary["fetch_status_counts_from_manifest"].items()
                        )
                    ],
                ),
                "",
            ]
        )

    if evidence_reliability:
        lines.extend(
            [
                "## RQ3 Evidence Source Reliability",
                "",
                "This diagnostic characterizes fetched evidence source classes and reference provenance. Silver-only prediction cross-tabs are audit-risk diagnostics, not human-gold error analysis.",
                "",
            ]
        )
        for field, field_summary in evidence_reliability.get("fields", {}).items():
            record_summary = field_summary["record_summary"]
            sample_summary = field_summary["sample_summary"]
            lines.extend(
                [
                    f"### {field}",
                    "",
                    f"- Samples: {field_summary['sample_count']}",
                    f"- OK text records: {record_summary['ok_text_records']}/{record_summary['record_count']} ({record_summary['ok_text_rate']:.1%})",
                    f"- Samples with at least one OK text record: {sample_summary['samples_with_ok_text']}/{field_summary['sample_count']} ({sample_summary['samples_with_ok_text_rate']:.1%})",
                    "",
                    "Source-class fetch profile:",
                    "",
                    table(
                        ["Class", "Records", "OK text", "OK rate"],
                        [
                            [
                                label,
                                str(values["records"]),
                                str(values["ok_text_records"]),
                                f"{values['ok_text_rate']:.1%}",
                            ]
                            for label, values in record_summary[
                                "by_source_class"
                            ].items()
                            if values["records"]
                        ],
                    ),
                    "",
                    "Reference provenance:",
                    "",
                    table(
                        ["Provenance", "Records", "OK text", "OK rate"],
                        [
                            [
                                label,
                                str(values["records"]),
                                str(values["ok_text_records"]),
                                f"{values['ok_text_rate']:.1%}",
                            ]
                            for label, values in record_summary[
                                "by_provenance"
                            ].items()
                            if values["records"]
                        ],
                    ),
                    "",
                ]
            )

    if affected_silver_summary:
        lines.extend(
            [
                "## Affected Versions Silver Label Distribution",
                "",
                "These are evidence-aware LLM silver labels, not human gold labels. The section below reports a separate silver-only diagnostic comparison.",
                "",
                f"- Rows: {affected_silver_summary['total_rows']}",
                f"- Unique sample IDs: {affected_silver_summary['unique_sample_ids']}",
                f"- Rows with missing required fields: {affected_silver_summary['rows_with_missing_required_fields']}",
                "",
                "LLM discrepancy labels:",
                "",
                table(
                    ["Label", "Count"],
                    [
                        [label, str(count)]
                        for label, count in affected_silver_summary["llm_label"].items()
                    ],
                ),
                "",
                "Baseline false-positive flags:",
                "",
                table(
                    ["Flag", "Count"],
                    [
                        [flag, str(count)]
                        for flag, count in affected_silver_summary[
                            "is_baseline_false_positive"
                        ].items()
                    ],
                ),
                "",
                "Adjudicated source labels:",
                "",
                table(
                    ["Source", "Count"],
                    [
                        [source, str(count)]
                        for source, count in affected_silver_summary[
                            "adjudicated_source"
                        ].items()
                    ],
                ),
                "",
                "Confidence labels:",
                "",
                table(
                    ["Confidence", "Count"],
                    [
                        [confidence, str(count)]
                        for confidence, count in affected_silver_summary[
                            "confidence"
                        ].items()
                    ],
                ),
                "",
            ]
        )

    if affected_rq3_metrics and affected_rq3_md:
        lines.extend(
            [
                "## RQ3 Affected Versions Silver-Label Diagnostic Comparison",
                "",
                "These diagnostic comparisons are computed against evidence-aware LLM silver labels, not human gold. The version-token baseline is a simple text-matching baseline, not a semantic version-range adjudicator.",
                "",
                f"- Samples: {affected_rq3_metrics['sample_count']}",
                f"- Silver labels are gold: {affected_rq3_metrics['silver_label_is_gold']}",
                f"- Adjudicable positive conflicts: {affected_rq3_metrics.get('candidate_miner_diagnostic', {}).get('adjudicable_positive_conflict', 0)}",
                f"- Adjudicable negative/non-conflicts: {affected_rq3_metrics.get('candidate_miner_diagnostic', {}).get('adjudicable_negative_non_conflict', 0)}",
                f"- Manual-review or excluded rows: {affected_rq3_metrics.get('candidate_miner_diagnostic', {}).get('manual_review_or_excluded', 0)}",
                "",
                affected_rq3_md,
                "",
            ]
            )

    if rq3_audit_readiness:
        lines.extend(
            [
                "## RQ3 Human-Audit Readiness",
                "",
                "This diagnostic summarizes blank human-audit templates and evidence coverage. It is not a gold-label evaluation and writes no adjudication metrics.",
                "",
                table(
                    [
                        "Field",
                        "Rows",
                        "Final",
                        "Draft",
                        "Blank required",
                        "OK evidence",
                        "Ready",
                    ],
                    [
                        [
                            field,
                            str(values["audit_row_count"]),
                            str(values["final_row_count"]),
                            str(values["draft_row_count"]),
                            str(values["blank_required_human_field_rows"]),
                            f"{values['samples_with_ok_evidence']}/{values['audit_row_count']}",
                            str(values["ready_for_gold_evaluation"]),
                        ]
                        for field, values in rq3_audit_readiness.get("fields", {}).items()
                    ],
                ),
                "",
            ]
        )
        for field, values in rq3_audit_readiness.get("fields", {}).items():
            lines.extend(
                [
                    f"### {field} audit worklist signals",
                    "",
                    table(
                        ["Reason", "Rows"],
                        [
                            [reason, str(count)]
                            for reason, count in values.get(
                                "priority_reason_counts", {}
                            ).items()
                        ],
                    ),
                    "",
                ]
            )

    if rq3_error_modes:
        lines.extend(
            [
                "## RQ3 Silver Error-Mode Diagnostic",
                "",
                "This diagnostic groups baseline mismatches against evidence-aware LLM silver labels. It is not a human-gold error analysis.",
                "",
            ]
        )
        for field, summary in rq3_error_modes.get("fields", {}).items():
            lines.extend(
                [
                    f"### {field}",
                    "",
                    f"- Method: `{summary['method']}`",
                    f"- Silver-label mismatches: {summary['error_count']}/{summary['sample_count']} ({summary['error_rate']:.1%})",
                    "",
                    table(
                        ["Silver->predicted", "Errors"],
                        [
                            [pair, str(count)]
                            for pair, count in summary.get(
                                "confusion_errors_only", {}
                            ).items()
                        ],
                    ),
                    "",
                ]
            )
            if field == "affected_versions":
                lines.extend(
                    [
                        "Affected-version diagnostic profiles among silver-label mismatches:",
                        "",
                        table(
                            ["Package-name profile", "Errors"],
                            [
                                [label, str(count)]
                                for label, count in summary.get(
                                    "package_overlap_error_counts", {}
                                ).items()
                            ],
                        ),
                        "",
                        table(
                            ["Version-shape profile", "Errors"],
                            [
                                [label, str(count)]
                                for label, count in summary.get(
                                    "version_shape_error_counts", {}
                                ).items()
                            ],
                        ),
                        "",
                    ]
                )

    if affected_alignment:
        counts = affected_alignment.get("diagnostic_counts", {})
        lines.extend(
            [
                "## Affected Versions Alignment Diagnostic",
                "",
                "This diagnostic characterizes package-name and version-shape alignment in the affected_versions silver sample. It is not a semantic version-range adjudicator and does not use human gold.",
                "",
                f"- Samples: {affected_alignment['sample_count']}",
                f"- Silver labels are gold: {affected_alignment['silver_label_is_gold']}",
                "",
                "Package-name profiles:",
                "",
                table(
                    ["Profile", "Samples"],
                    [
                        [label, str(count)]
                        for label, count in counts.get("package_category", {}).items()
                    ],
                ),
                "",
                "Version-shape profiles:",
                "",
                table(
                    ["Profile", "Samples"],
                    [
                        [label, str(count)]
                        for label, count in counts.get("version_shape_category", {}).items()
                    ],
                ),
                "",
                "Combined diagnostic categories:",
                "",
                table(
                    ["Category", "Samples"],
                    [
                        [label, str(count)]
                        for label, count in counts.get("combined_category", {}).items()
                    ],
                ),
                "",
                "Version-token overlap:",
                "",
                table(
                    ["Overlap", "Samples"],
                    [
                        [label, str(count)]
                        for label, count in counts.get("token_overlap", {}).items()
                    ],
                ),
                "",
            ]
        )
        if affected_structural_md:
            lines.extend(
                [
                    "Manuscript structural diagnostic table:",
                    "",
                    affected_structural_md,
                    "",
                ]
            )

    if rq3_sensitivity:
        lines.extend(
            [
                "## RQ3 Silver Baseline Sensitivity",
                "",
                "This diagnostic varies deterministic baseline thresholds against evidence-aware LLM silver labels. It is not human-gold performance tuning.",
                "",
            ]
        )
        for field, field_summary in rq3_sensitivity.get("fields", {}).items():
            lines.extend(
                [
                    f"### {field}",
                    "",
                    f"- Method family: `{field_summary['method_family']}`",
                    f"- Baseline threshold: {field_summary['baseline_threshold']}",
                    f"- Samples with prediction changes across thresholds: {field_summary['instability']['samples_with_prediction_change']}/{field_summary['instability']['sample_count']} ({field_summary['instability']['prediction_change_rate']:.1%})",
                    "",
                    table(
                        [
                            "Threshold",
                            "Silver-label agreement",
                            "Macro-F1 vs silver",
                            "Coverage",
                            "Predictions",
                        ],
                        [
                            [
                                str(values["threshold"]),
                                metric(values["accuracy"]),
                                metric(
                                    values[
                                        "macro_f1_over_supported_silver_labels"
                                    ]
                                ),
                                metric(values["coverage_non_abstain"]),
                                ", ".join(
                                    f"{label}={count}"
                                    for label, count in values[
                                        "prediction_counts"
                                    ].items()
                                ),
                            ]
                            for values in field_summary[
                                "metrics_by_threshold"
                            ].values()
                        ],
                    ),
                    "",
                ]
            )

    lines.extend(
        [
        "## RQ3 Evidence Baseline Error Sketch",
        "",
        ]
    )

    baseline = prediction_summary.get("evidence_score_baseline", {})
    lines.extend(
        [
            f"- Error count: {baseline.get('error_count', 0)}",
            "- Confusion pairs are `silver_source->predicted_source`:",
            "",
            table(
                ["Pair", "Count"],
                [[pair, str(count)] for pair, count in baseline.get("confusion", {}).items()],
            ),
            "",
            "First error examples:",
            "",
            table(
                ["Sample", "CVE", "Silver", "Predicted"],
                [
                    [
                        row["sample_id"],
                        row["cve_id"],
                        row["silver_source"],
                        row["predicted_source"],
                    ]
                    for row in baseline.get("first_errors", [])[:8]
                ],
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    discrepancy_stats = read_json(resolve_path(args.discrepancy_stats))
    coverage = read_json(resolve_path(args.rq1_coverage))
    rq2_diagnostics_path = resolve_path(args.rq2_diagnostics)
    rq2_sample_coverage_path = resolve_path(args.rq2_sample_coverage)
    rq2_diagnostics = (
        read_json(rq2_diagnostics_path) if rq2_diagnostics_path.exists() else None
    )
    rq2_sample_coverage = (
        read_json(rq2_sample_coverage_path)
        if rq2_sample_coverage_path.exists()
        else None
    )
    metrics = read_json(resolve_path(args.rq3_metrics))
    manifest = read_json(resolve_path(args.rq3_manifest))
    affected_evidence_path = resolve_path(args.affected_evidence)
    affected_manifest_path = resolve_path(args.affected_manifest)
    affected_silver_path = resolve_path(args.affected_silver)
    rq3_error_modes_path = resolve_path(args.rq3_error_modes)
    affected_alignment_path = resolve_path(args.affected_alignment)
    rq3_sensitivity_path = resolve_path(args.rq3_sensitivity)
    evidence_reliability_path = resolve_path(args.evidence_reliability)
    rq3_audit_readiness_path = resolve_path(args.rq3_audit_readiness)

    discrepancy_md, discrepancy_rows = build_discrepancy_table(discrepancy_stats)
    coverage_md, coverage_rows = build_coverage_table(coverage)
    claim_boundary_md, claim_boundary_rows_out = build_claim_boundary_table()
    dataset_field_coverage_md, dataset_field_coverage_rows = (
        build_dataset_field_coverage_table(coverage)
    )
    rq3_md, rq3_rows = build_rq3_table(metrics)
    affected_rq3_metrics_path = resolve_path(args.affected_rq3_metrics)
    affected_rq3_predictions_path = resolve_path(args.affected_rq3_predictions)
    affected_rq3_metrics = None
    affected_rq3_md = None
    affected_rq3_rows = None
    if affected_rq3_metrics_path.exists():
        affected_rq3_metrics = read_json(affected_rq3_metrics_path)
        affected_rq3_md, affected_rq3_rows = build_rq3_table(affected_rq3_metrics)
    evidence_summary = summarize_evidence(resolve_path(args.rq3_evidence), manifest)
    affected_evidence_summary = None
    if affected_evidence_path.exists() and affected_manifest_path.exists():
        affected_evidence_summary = summarize_evidence(
            affected_evidence_path,
            read_json(affected_manifest_path),
        )
    affected_silver_summary = None
    if affected_silver_path.exists():
        affected_silver_summary = summarize_llm_silver(affected_silver_path)
    rq3_error_modes = read_json(rq3_error_modes_path) if rq3_error_modes_path.exists() else None
    affected_alignment = (
        read_json(affected_alignment_path) if affected_alignment_path.exists() else None
    )
    affected_structural_md, affected_structural_rows = (
        build_affected_versions_structural_table(affected_alignment)
    )
    rq3_sensitivity = (
        read_json(rq3_sensitivity_path) if rq3_sensitivity_path.exists() else None
    )
    evidence_reliability = (
        read_json(evidence_reliability_path)
        if evidence_reliability_path.exists()
        else None
    )
    rq3_audit_readiness = (
        read_json(rq3_audit_readiness_path)
        if rq3_audit_readiness_path.exists()
        else None
    )
    prediction_summary = summarize_predictions(resolve_path(args.rq3_predictions))

    artifact = {
        "source_paths": {
            "discrepancy_stats": str(resolve_path(args.discrepancy_stats)),
            "rq1_coverage": str(resolve_path(args.rq1_coverage)),
            "rq2_diagnostics": str(rq2_diagnostics_path),
            "rq2_sample_coverage": str(rq2_sample_coverage_path),
            "rq3_metrics": str(resolve_path(args.rq3_metrics)),
            "rq3_predictions": str(resolve_path(args.rq3_predictions)),
            "affected_versions_rq3_metrics": str(affected_rq3_metrics_path),
            "affected_versions_rq3_predictions": str(affected_rq3_predictions_path),
            "rq3_evidence": str(resolve_path(args.rq3_evidence)),
            "rq3_manifest": str(resolve_path(args.rq3_manifest)),
            "affected_versions_evidence": str(affected_evidence_path),
            "affected_versions_manifest": str(affected_manifest_path),
            "affected_versions_silver": str(affected_silver_path),
            "rq3_error_modes": str(rq3_error_modes_path),
            "affected_versions_alignment": str(affected_alignment_path),
            "rq3_silver_baseline_sensitivity": str(rq3_sensitivity_path),
            "evidence_source_reliability": str(evidence_reliability_path),
            "rq3_human_audit_readiness": str(rq3_audit_readiness_path),
        },
        "cautions": [
            "RQ3 labels are evidence-aware LLM silver labels, not human gold labels.",
            "The evidence_score_baseline is a deterministic text-matching baseline.",
            "Affected_versions has silver-only baseline metrics, not gold-backed adjudication metrics.",
            "Affected_versions RQ3 metrics are silver-only and use a simple token-matching baseline.",
            "RQ2 diagnostics describe deterministic rule triggers, not typing accuracy.",
            "RQ2 sample coverage describes blank annotation-template readiness, not accuracy or agreement.",
            "RQ3 sensitivity diagnostics are silver-only threshold checks, not tuned human-gold performance.",
            "Evidence source reliability diagnostics describe fetch/source-class availability, not source truth.",
            "RQ3 human-audit readiness describes blank template status and worklist signals, not gold-backed metrics.",
        ],
        "coverage": coverage_rows,
        "claim_boundaries": claim_boundary_rows_out,
        "manuscript_field_coverage": dataset_field_coverage_rows,
        "discrepancy_distribution": discrepancy_rows,
        "rq2_typing_diagnostics": rq2_diagnostics,
        "rq2_sample_coverage": rq2_sample_coverage,
        "rq3_severity_silver": rq3_rows,
        "rq3_affected_versions_silver": affected_rq3_rows,
        "rq3_evidence_summary": evidence_summary,
        "affected_versions_evidence_summary": affected_evidence_summary,
        "affected_versions_silver_summary": affected_silver_summary,
        "rq3_silver_error_modes": rq3_error_modes,
        "affected_versions_alignment_diagnostic": affected_alignment,
        "affected_versions_structural_diagnostic_table": affected_structural_rows,
        "rq3_silver_baseline_sensitivity": rq3_sensitivity,
        "evidence_source_reliability": evidence_reliability,
        "rq3_human_audit_readiness": rq3_audit_readiness,
        "rq3_prediction_summary": prediction_summary,
    }
    json_path = output_dir / "cose_artifact_tables.json"
    md_path = output_dir / "cose_artifact_tables.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(
        render_summary(
            discrepancy_md,
            coverage_md,
            claim_boundary_md,
            dataset_field_coverage_md,
            rq2_diagnostics,
            rq2_sample_coverage,
            rq3_md,
            evidence_summary,
            affected_evidence_summary,
            affected_silver_summary,
            prediction_summary,
            coverage,
            metrics,
            affected_rq3_md,
            affected_rq3_rows,
            affected_rq3_metrics,
            rq3_error_modes,
            affected_alignment,
            affected_structural_md,
            rq3_sensitivity,
            evidence_reliability,
            rq3_audit_readiness,
        ),
        encoding="utf-8",
    )

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
