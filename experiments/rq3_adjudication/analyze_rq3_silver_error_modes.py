#!/usr/bin/env python3
"""Analyze RQ3 silver-label prediction error modes.

This diagnostic summarizes where the current silver-only baselines succeed,
fail, or abstain. It does not create human-gold performance claims.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_JSON = "results/rq3_adjudication/rq3_silver_error_modes.json"
DEFAULT_OUTPUT_MD = "results/rq3_adjudication/rq3_silver_error_modes.md"

DATASETS = {
    "severity": {
        "method": "evidence_score_baseline",
        "predictions": "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
        "evidence": "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
        ),
    },
    "affected_versions": {
        "method": "version_token_support_baseline",
        "predictions": "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl",
        "evidence": "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        "silver": (
            "data/annotations/rq3/silver_v2/llm_silver_v2/"
            "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
        ),
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze RQ3 silver error modes.")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
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


def summarize_evidence(row: dict) -> dict:
    status_counts = Counter()
    ok_hosts = Counter()
    ok_records = 0
    candidate_count = row.get("evidence_context", {}).get("candidate_url_count", 0)
    for record in row.get("evidence_context", {}).get("records", []):
        status = record.get("fetch_status") or "missing"
        status_counts[status] += 1
        if status == "ok":
            ok_records += 1
            ok_hosts[record.get("host") or ""] += 1
    return {
        "candidate_url_count": candidate_count,
        "ok_record_count": ok_records,
        "fetch_status_counts": dict(sorted(status_counts.items())),
        "ok_hosts": dict(sorted(ok_hosts.items())),
        "ok_host_count": len(ok_hosts),
    }


def support_summary(prediction: dict) -> dict:
    detail = prediction.get("prediction_detail", {})
    support = detail.get("support", {})
    result = {}
    for source in ("nvd", "ghsa"):
        source_support = support.get(source, {})
        matched_urls = source_support.get("matched_urls", []) or []
        matched_terms = source_support.get("matched_terms", []) or []
        matched_tokens = source_support.get("matched_tokens", []) or []
        result[source] = {
            "score": source_support.get("score", 0),
            "matched_url_count": len(set(matched_urls)),
            "matched_terms": dict(sorted(Counter(matched_terms).items())),
            "matched_token_count": len(set(matched_tokens)),
        }
    return result


def package_overlap(row: dict) -> dict:
    nvd_names = {str(value).lower() for value in row.get("nvd_context", {}).get("package_names", [])}
    ghsa_names = {str(value).lower() for value in row.get("ghsa_context", {}).get("package_names", [])}
    nvd_leaf = {value.split("/")[-1].split(":")[-1] for value in nvd_names}
    ghsa_leaf = {value.split("/")[-1].split(":")[-1] for value in ghsa_names}
    exact = sorted(nvd_names & ghsa_names)
    leaf = sorted(nvd_leaf & ghsa_leaf)
    return {
        "nvd_package_count": len(nvd_names),
        "ghsa_package_count": len(ghsa_names),
        "exact_overlap_count": len(exact),
        "leaf_overlap_count": len(leaf),
        "has_exact_overlap": bool(exact),
        "has_leaf_overlap": bool(leaf),
    }


def version_shape(values: list[dict]) -> Counter:
    counts = Counter()
    for item in values or []:
        has_point = bool(item.get("version"))
        has_range = any(
            item.get(key)
            for key in (
                "version_start_including",
                "version_start_excluding",
                "version_end_including",
                "version_end_excluding",
                "fixed",
                "introduced",
            )
        )
        if has_point and has_range:
            counts["mixed_point_and_range"] += 1
        elif has_point:
            counts["point_version"] += 1
        elif has_range:
            counts["range_bound"] += 1
        else:
            counts["empty_span"] += 1
    return counts


def affected_version_profile(row: dict) -> dict:
    nvd_shape = version_shape(row.get("nvd_value") or [])
    ghsa_shape = version_shape(row.get("ghsa_value") or [])
    return {
        "package_overlap": package_overlap(row),
        "nvd_shape_counts": dict(sorted(nvd_shape.items())),
        "ghsa_shape_counts": dict(sorted(ghsa_shape.items())),
        "nvd_span_count": sum(nvd_shape.values()),
        "ghsa_span_count": sum(ghsa_shape.values()),
        "nvd_has_only_point_versions": bool(nvd_shape)
        and not any(key != "point_version" for key in nvd_shape),
        "ghsa_has_range_bounds": bool(ghsa_shape.get("range_bound") or ghsa_shape.get("mixed_point_and_range")),
    }


def prediction_rows(path: Path, method: str) -> list[dict]:
    return [row for row in iter_jsonl(path) if row.get("method") == method]


def analyze_field(field: str, spec: dict) -> dict:
    evidence_rows = load_by_sample_id(resolve_path(spec["evidence"]))
    silver_rows = load_by_sample_id(resolve_path(spec["silver"]))
    predictions = prediction_rows(resolve_path(spec["predictions"]), spec["method"])

    by_sample = {}
    confusion = Counter()
    error_confusion = Counter()
    label_counts = Counter()
    label_error_counts = Counter()
    confidence_counts = Counter()
    confidence_error_counts = Counter()
    abstain_counts = Counter()
    evidence_bins = Counter()
    evidence_error_bins = Counter()
    host_bins = Counter()
    host_error_bins = Counter()
    support_gap_bins = Counter()
    support_gap_error_bins = Counter()
    false_positive_counts = Counter()
    false_positive_error_counts = Counter()
    eval_subset_counts = Counter()
    eval_subset_error_counts = Counter()
    package_overlap_counts = Counter()
    package_overlap_error_counts = Counter()
    version_shape_counts = Counter()
    version_shape_error_counts = Counter()
    error_examples = []

    for prediction in predictions:
        sample_id = prediction["sample_id"]
        evidence_row = evidence_rows[sample_id]
        silver_annotation = silver_rows[sample_id]["llm_annotation"]
        evidence = summarize_evidence(evidence_row)
        support = support_summary(prediction)
        is_error = not prediction["is_correct"]
        pair = f"{prediction['silver_source']}->{prediction['predicted_source']}"
        label = prediction.get("silver_label") or silver_annotation.get("llm_label") or "missing"
        confidence = prediction.get("confidence") or silver_annotation.get("confidence") or "missing"
        false_positive = (
            prediction.get("is_baseline_false_positive")
            or silver_annotation.get("is_baseline_false_positive")
            or "missing"
        )
        eval_subset = prediction.get("eval_subset") or "not_applicable"
        ok_bin = evidence_count_bin(evidence["ok_record_count"])
        host_bin = host_count_bin(evidence["ok_host_count"])
        support_gap = int(support["nvd"]["score"] or 0) - int(support["ghsa"]["score"] or 0)
        support_bin = support_gap_bin(support_gap)

        confusion[pair] += 1
        label_counts[label] += 1
        confidence_counts[confidence] += 1
        false_positive_counts[false_positive] += 1
        eval_subset_counts[eval_subset] += 1
        evidence_bins[ok_bin] += 1
        host_bins[host_bin] += 1
        support_gap_bins[support_bin] += 1
        if prediction["predicted_source"] == "abstain":
            abstain_counts[prediction["silver_source"]] += 1

        affected_profile = None
        if field == "affected_versions":
            affected_profile = affected_version_profile(evidence_row)
            overlap_key = package_overlap_key(affected_profile["package_overlap"])
            shape_key = affected_shape_key(affected_profile)
            package_overlap_counts[overlap_key] += 1
            version_shape_counts[shape_key] += 1

        if is_error:
            error_confusion[pair] += 1
            label_error_counts[label] += 1
            confidence_error_counts[confidence] += 1
            false_positive_error_counts[false_positive] += 1
            eval_subset_error_counts[eval_subset] += 1
            evidence_error_bins[ok_bin] += 1
            host_error_bins[host_bin] += 1
            support_gap_error_bins[support_bin] += 1
            if affected_profile:
                package_overlap_error_counts[package_overlap_key(affected_profile["package_overlap"])] += 1
                version_shape_error_counts[affected_shape_key(affected_profile)] += 1
            if len(error_examples) < 12:
                error_examples.append(
                    {
                        "sample_id": sample_id,
                        "cve_id": prediction["cve_id"],
                        "silver_source": prediction["silver_source"],
                        "predicted_source": prediction["predicted_source"],
                        "silver_label": label,
                        "confidence": confidence,
                        "ok_record_count": evidence["ok_record_count"],
                        "ok_host_count": evidence["ok_host_count"],
                        "support": support,
                    }
                )

        by_sample[sample_id] = {
            "sample_id": sample_id,
            "cve_id": prediction["cve_id"],
            "field": field,
            "method": spec["method"],
            "silver_source": prediction["silver_source"],
            "predicted_source": prediction["predicted_source"],
            "is_correct": prediction["is_correct"],
            "silver_label": label,
            "confidence": confidence,
            "is_baseline_false_positive": false_positive,
            "eval_subset": eval_subset,
            "evidence": evidence,
            "support": support,
            "affected_versions_profile": affected_profile,
        }

    total = len(predictions)
    errors = sum(1 for row in predictions if not row["is_correct"])
    return {
        "field": field,
        "method": spec["method"],
        "silver_label_is_gold": False,
        "sample_count": total,
        "error_count": errors,
        "error_rate": errors / total if total else 0.0,
        "accuracy_against_silver": (total - errors) / total if total else 0.0,
        "confusion_all": dict(sorted(confusion.items())),
        "confusion_errors_only": dict(sorted(error_confusion.items())),
        "predicted_abstain_by_silver_source": dict(sorted(abstain_counts.items())),
        "silver_label_counts": dict(sorted(label_counts.items())),
        "silver_label_error_counts": dict(sorted(label_error_counts.items())),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "confidence_error_counts": dict(sorted(confidence_error_counts.items())),
        "false_positive_flag_counts": dict(sorted(false_positive_counts.items())),
        "false_positive_flag_error_counts": dict(sorted(false_positive_error_counts.items())),
        "eval_subset_counts": dict(sorted(eval_subset_counts.items())),
        "eval_subset_error_counts": dict(sorted(eval_subset_error_counts.items())),
        "evidence_ok_record_bins": dict(sorted(evidence_bins.items())),
        "evidence_ok_record_error_bins": dict(sorted(evidence_error_bins.items())),
        "evidence_ok_host_bins": dict(sorted(host_bins.items())),
        "evidence_ok_host_error_bins": dict(sorted(host_error_bins.items())),
        "support_score_gap_bins": dict(sorted(support_gap_bins.items())),
        "support_score_gap_error_bins": dict(sorted(support_gap_error_bins.items())),
        "package_overlap_counts": dict(sorted(package_overlap_counts.items())),
        "package_overlap_error_counts": dict(sorted(package_overlap_error_counts.items())),
        "version_shape_counts": dict(sorted(version_shape_counts.items())),
        "version_shape_error_counts": dict(sorted(version_shape_error_counts.items())),
        "first_error_examples": error_examples,
        "samples": [by_sample[sample_id] for sample_id in sorted(by_sample)],
    }


def evidence_count_bin(count: int) -> str:
    if count == 0:
        return "0"
    if count <= 2:
        return "1-2"
    if count <= 5:
        return "3-5"
    return "6+"


def host_count_bin(count: int) -> str:
    if count == 0:
        return "0"
    if count == 1:
        return "1"
    if count <= 3:
        return "2-3"
    return "4+"


def support_gap_bin(gap: int) -> str:
    if gap <= -5:
        return "ghsa_leads_5+"
    if gap < 0:
        return "ghsa_leads_1-4"
    if gap == 0:
        return "tie"
    if gap < 5:
        return "nvd_leads_1-4"
    return "nvd_leads_5+"


def package_overlap_key(overlap: dict) -> str:
    if overlap["has_exact_overlap"]:
        return "exact_package_overlap"
    if overlap["has_leaf_overlap"]:
        return "leaf_package_overlap_only"
    return "no_package_name_overlap"


def affected_shape_key(profile: dict) -> str:
    if profile["nvd_has_only_point_versions"] and profile["ghsa_has_range_bounds"]:
        return "nvd_points_vs_ghsa_ranges"
    if profile["nvd_span_count"] != profile["ghsa_span_count"]:
        return "span_count_mismatch"
    return "other_shape"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---", *["---:" for _ in headers[1:]]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_markdown(artifact: dict) -> str:
    lines = [
        "# RQ3 Silver Error-Mode Diagnostic",
        "",
        "This artifact analyzes deterministic baselines against evidence-aware LLM silver labels. It is not a human-gold evaluation.",
        "",
    ]
    for field, summary in artifact["fields"].items():
        lines.extend(
            [
                f"## {field}",
                "",
                f"- Method: `{summary['method']}`",
                f"- Samples: `{summary['sample_count']}`",
                f"- Errors against silver labels: `{summary['error_count']}` (`{summary['error_rate']:.1%}`)",
                "",
                "Error confusion pairs:",
                "",
                table(
                    ["Silver->Predicted", "Errors"],
                    [
                        [pair, str(count)]
                        for pair, count in summary["confusion_errors_only"].items()
                    ],
                ),
                "",
                "Errors by silver label:",
                "",
                table(
                    ["Label", "Errors"],
                    [
                        [label, str(count)]
                        for label, count in summary["silver_label_error_counts"].items()
                    ],
                ),
                "",
                "Errors by evidence host-count bin:",
                "",
                table(
                    ["OK host bin", "Errors"],
                    [
                        [label, str(count)]
                        for label, count in summary["evidence_ok_host_error_bins"].items()
                    ],
                ),
                "",
            ]
        )
        if field == "affected_versions":
            lines.extend(
                [
                    "Affected-version profile among errors:",
                    "",
                    table(
                        ["Package overlap", "Errors"],
                        [
                            [label, str(count)]
                            for label, count in summary[
                                "package_overlap_error_counts"
                            ].items()
                        ],
                    ),
                    "",
                    table(
                        ["Version shape", "Errors"],
                        [
                            [label, str(count)]
                            for label, count in summary[
                                "version_shape_error_counts"
                            ].items()
                        ],
                    ),
                    "",
                ]
            )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    artifact = {
        "schema_version": 1,
        "silver_label_is_gold": False,
        "task": "rq3_silver_error_mode_diagnostic",
        "cautions": [
            "This is a diagnostic over evidence-aware LLM silver labels, not human gold.",
            "Error counts describe mismatch with silver labels and do not prove real-world baseline errors.",
            "Affected_versions profiles are deterministic characterization, not semantic version adjudication.",
        ],
        "fields": {
            field: analyze_field(field, spec) for field, spec in DATASETS.items()
        },
    }

    output_json = resolve_path(args.output_json)
    output_md = resolve_path(args.output_md)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output_md.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {output_json}")
    print(f"Wrote {output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
