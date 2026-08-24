#!/usr/bin/env python3
"""Diagnose construct failures from RQ2 contract calibration v1."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import build_rq2_typing_contract_calibration as builder


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v1/source_rows.jsonl"
)
DEFAULT_CASES = (
    "results/holdout/rq2_typing_v1/contract_calibration_v1/dual_review_consensus.jsonl"
)
DEFAULT_SUMMARY = (
    "results/holdout/rq2_typing_v1/contract_calibration_v1/summary.json"
)
DEFAULT_MERGE_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v1/merge_manifest.json"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v1/failure_analysis"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--cases", default=DEFAULT_CASES)
    parser.add_argument("--summary", default=DEFAULT_SUMMARY)
    parser.add_argument("--merge-manifest", default=DEFAULT_MERGE_MANIFEST)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def cvss_version(value: dict | None) -> str | None:
    vector = str((value or {}).get("vector") or "")
    match = re.match(r"CVSS:([0-9]+(?:\.[0-9]+)?)/", vector)
    return match.group(1) if match else None


def has_prerelease_token(values: object) -> bool:
    text = json.dumps(values, ensure_ascii=False)
    return bool(
        re.search(
            r"(?i)(?:^|[.\-])(rc|milestone|alpha|beta)[.\-]?\d*", text
        )
    )


def concrete_singletons(values: object) -> bool:
    range_keys = (
        "introduced",
        "fixed",
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
    )
    return bool(values) and isinstance(values, list) and all(
        isinstance(value, dict)
        and value.get("version") not in {None, "", "*", "-"}
        and not any(value.get(key) not in {None, ""} for key in range_keys)
        for value in values
    )


def contains_range(values: object) -> bool:
    range_keys = (
        "introduced",
        "fixed",
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
    )
    return bool(values) and isinstance(values, list) and any(
        isinstance(value, dict)
        and any(value.get(key) not in {None, ""} for key in range_keys)
        for value in values
    )


def failure_bucket(source: dict, case: dict) -> str:
    if source["field"] == "severity":
        left_version = cvss_version(source.get("nvd_value"))
        right_version = cvss_version(source.get("ghsa_value"))
        if left_version and right_version and left_version != right_version:
            return "cross_cvss_version_noncomparable_vectors"
        return "same_version_severity_contract"

    labels = {
        case["reviewer_a"]["discrepancy_label"],
        case["reviewer_b"]["discrepancy_label"],
    }
    if "uncertain" in labels:
        return "unresolved_artifact_identity"
    values = [source.get("nvd_value"), source.get("ghsa_value")]
    if has_prerelease_token(values):
        return "prerelease_boundary_semantics"
    if (
        concrete_singletons(source.get("nvd_value"))
        and contains_range(source.get("ghsa_value"))
    ) or (
        concrete_singletons(source.get("ghsa_value"))
        and contains_range(source.get("nvd_value"))
    ):
        return "singleton_vs_interval_subset"
    return "other_affected_construct"


def validate_inputs(
    source_path: Path,
    cases_path: Path,
    summary_path: Path,
    merge_manifest_path: Path,
) -> dict:
    manifest = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_typing_contract_calibration_merge_manifest":
        raise ValueError("unexpected calibration merge manifest")
    outputs = manifest.get("outputs") or {}
    expected = {
        "cases": cases_path,
        "summary": summary_path,
    }
    for name, path in expected.items():
        entry = outputs.get(name) or {}
        if Path(entry.get("path", "")) != path:
            raise ValueError(f"merge manifest path mismatch for {name}")
        if builder.sha256(path) != entry.get("sha256"):
            raise ValueError(f"merge manifest hash mismatch for {name}")
    source_manifest_path = Path(
        (manifest.get("inputs") or {}).get("sealed_manifest", {}).get("path", "")
    )
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    source_entry = (source_manifest.get("outputs") or {}).get("source_rows") or {}
    if Path(source_entry.get("path", "")) != source_path:
        raise ValueError("source path differs from sealed calibration manifest")
    if builder.sha256(source_path) != source_entry.get("sha256"):
        raise ValueError("source hash differs from sealed calibration manifest")
    return manifest


def analyze(source_rows: list[dict], cases: list[dict], summary: dict) -> tuple[dict, list[dict]]:
    if len(source_rows) != builder.EXPECTED_CALIBRATION_ROWS:
        raise ValueError("unexpected calibration source row count")
    if len(cases) != builder.EXPECTED_CALIBRATION_ROWS:
        raise ValueError("unexpected calibration case row count")
    source_by_id = {row["sample_id"]: row for row in source_rows}
    if len(source_by_id) != len(source_rows):
        raise ValueError("duplicate calibration source sample ID")
    if set(source_by_id) != {row.get("sample_id") for row in cases}:
        raise ValueError("source and calibration case IDs differ")

    failures = []
    for case in cases:
        left = case["reviewer_a"]["discrepancy_label"]
        right = case["reviewer_b"]["discrepancy_label"]
        expected = case["expected_label"]
        if left == right == expected:
            continue
        source = source_by_id[case["sample_id"]]
        failures.append(
            {
                "artifact_type": "rq2_typing_contract_calibration_failure_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "sample_id": case["sample_id"],
                "cve_id": case["cve_id"],
                "field": case["field"],
                "calibration_stratum": case["calibration_stratum"],
                "failure_bucket": failure_bucket(source, case),
                "expected_label": expected,
                "prior_non_human_consensus_label": case[
                    "prior_non_human_consensus_label"
                ],
                "reviewer_a_label": left,
                "reviewer_b_label": right,
                "strict_consensus": case["strict_consensus"],
                "new_consensus_label": case["consensus_label"],
                "reviewer_a_rationale": case["reviewer_a"]["rationale"],
                "reviewer_b_rationale": case["reviewer_b"]["rationale"],
            }
        )

    strict = [case for case in cases if case["strict_consensus"]]
    prior_replicated = sum(
        case["consensus_label"] == case["prior_non_human_consensus_label"]
        for case in strict
    )
    different_vector = [
        case
        for case in cases
        if case["calibration_stratum"]
        == "severity_different_vector_one_missing_score"
    ]
    same_version = [
        case
        for case in different_vector
        if cvss_version(source_by_id[case["sample_id"]].get("nvd_value"))
        == cvss_version(source_by_id[case["sample_id"]].get("ghsa_value"))
    ]
    cross_version = [case for case in different_vector if case not in same_version]
    metrics = {
        "artifact_type": "rq2_typing_contract_calibration_failure_analysis",
        "analysis_boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "post_hoc": True,
            "production_comparator_changed": False,
            "valid_for_confirmatory_performance_claim": False,
        },
        "calibration": {
            "rows": summary["rows"],
            "exact_label_agreement": summary["exact_label_agreement"],
            "exact_label_agreement_rate": summary["exact_label_agreement_rate"],
            "cohen_kappa": summary["cohen_kappa"],
            "strict_consensus_rows": summary["strict_consensus_rows"],
            "strict_consensus_coverage": summary["strict_consensus_coverage"],
            "gate_status": summary["gate"]["status"],
        },
        "repeatability": {
            "strict_rows": len(strict),
            "prior_non_human_consensus_replicated_rows": prior_replicated,
            "prior_non_human_consensus_replication_rate": prior_replicated / len(strict),
            "all_row_lower_bound_replication_rate": prior_replicated / len(cases),
        },
        "failures": {
            "rows": len(failures),
            "reviewer_disagreement_rows": sum(
                failure["reviewer_a_label"] != failure["reviewer_b_label"]
                for failure in failures
            ),
            "strict_expected_mismatch_rows": sum(
                failure["strict_consensus"]
                and failure["new_consensus_label"] != failure["expected_label"]
                for failure in failures
            ),
            "bucket_counts": dict(sorted(Counter(
                failure["failure_bucket"] for failure in failures
            ).items())),
        },
        "post_hoc_hypotheses": {
            "same_cvss_version_different_vectors": {
                "rows": len(same_version),
                "strict_factual_conflict_rows": sum(
                    case["strict_consensus"]
                    and case["consensus_label"] == "factual_conflict"
                    for case in same_version
                ),
                "interpretation": (
                    "Candidate rule: compare base metrics only within the same CVSS "
                    "version; this slice was identified after calibration and requires "
                    "a disjoint validation packet."
                ),
            },
            "cross_cvss_version_vectors": {
                "rows": len(cross_version),
                "strict_representation_rows": sum(
                    case["strict_consensus"]
                    and case["consensus_label"] == "representation_discrepancy"
                    for case in cross_version
                ),
                "interpretation": (
                    "Cross-version vectors are not component-wise comparable without "
                    "a documented crosswalk; one observed row is exploratory only."
                ),
            },
            "affected_versions": {
                "interpretation": (
                    "Artifact identity, prerelease ordering, and singleton-versus-range "
                    "subset semantics require separate contract clauses and disjoint "
                    "validation."
                )
            },
        },
        "decision": {
            "status": "no_go_affected_construct_unstable",
            "candidate_profile_freeze_allowed": False,
            "new_time_cohort_allowed": False,
            "production_switch_allowed": False,
            "human_gold_claim_allowed": False,
            "required_next_evidence": [
                "a disjoint calibration packet for same-version versus cross-version CVSS vectors",
                "artifact-identity evidence for CPE product to ecosystem package mappings",
                "explicit prerelease ordering and singleton-versus-interval subset rules",
                "real-person review and author sign-off before any human-gold claim",
            ],
        },
    }
    return metrics, failures


def render_markdown(metrics: dict) -> str:
    calibration = metrics["calibration"]
    repeatability = metrics["repeatability"]
    failures = metrics["failures"]
    lines = [
        "# RQ2 Contract Calibration v1 Failure Analysis",
        "",
        "> Post-hoc, non-human construct diagnosis. The production comparator is unchanged.",
        "",
        f"- Calibration gate: `{calibration['gate_status']}`",
        f"- Exact A/B agreement: `{calibration['exact_label_agreement']}/{calibration['rows']}` (`{calibration['exact_label_agreement_rate']:.4f}`)",
        f"- Strict consensus: `{calibration['strict_consensus_rows']}/{calibration['rows']}` (`{calibration['strict_consensus_coverage']:.4f}`)",
        f"- Prior non-human consensus replicated among strict rows: `{repeatability['prior_non_human_consensus_replicated_rows']}/{repeatability['strict_rows']}` (`{repeatability['prior_non_human_consensus_replication_rate']:.4f}`)",
        f"- Diagnostic failures: `{failures['rows']}`; reviewer disagreements `{failures['reviewer_disagreement_rows']}`, strict expected-label mismatches `{failures['strict_expected_mismatch_rows']}`",
        "",
        "## Failure buckets",
        "",
    ]
    for bucket, count in failures["bucket_counts"].items():
        lines.append(f"- `{bucket}`: `{count}`")
    lines.extend(
        [
            "",
            "The failure buckets motivate a disjoint v2 calibration. They do not validate a revised rule on this same packet.",
            "",
            f"Decision: `{metrics['decision']['status']}`. Human-gold and production switching remain disallowed.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    cases_path = resolve(args.cases)
    summary_path = resolve(args.summary)
    merge_manifest_path = resolve(args.merge_manifest)
    output_dir = resolve(args.output_dir)
    validate_inputs(source_path, cases_path, summary_path, merge_manifest_path)
    metrics, failures = analyze(
        list(builder.iter_jsonl(source_path)),
        list(builder.iter_jsonl(cases_path)),
        json.loads(summary_path.read_text(encoding="utf-8")),
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    metrics_path = output_dir / "diagnostic.json"
    cases_output_path = output_dir / "failure_cases.jsonl"
    markdown_path = output_dir / "diagnostic.md"
    builder.write_jsonl(cases_output_path, failures)
    metrics_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(f"Wrote {metrics_path}")
    print(f"Decision: {metrics['decision']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
