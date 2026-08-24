#!/usr/bin/env python3
"""Validate and merge disjoint RQ2 contract calibration v2 reviews."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_typing_contract_calibration_v2 as builder
import merge_rq2_typing_contract_calibration as v1_merge
import merge_rq2_typing_holdout_reviews as holdout_merge


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2"
)
MIN_OVERALL_EXACT_AGREEMENT = 0.85
MIN_OVERALL_STRICT_COVERAGE = 0.80
MIN_FIXED_STRATUM_EXPECTED_RATE = 0.80
MIN_OPEN_STRATUM_STRICT_COVERAGE = 0.80
FIXED_EXPECTED_LABELS = {
    "severity_same_cvss_version_different_vector": "factual_conflict",
    "severity_cross_cvss_version_different_vector": "representation_discrepancy",
    "severity_exact_or_prefix_one_missing_score_repeat": "incomplete",
    "affected_one_sided_unbounded_repeat": "incomplete",
}
OPEN_AFFECTED_STRATA = {
    "affected_same_normalized_range_package_mismatch",
    "affected_singleton_vs_interval",
    "affected_prerelease_boundary",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def validate_manifest(manifest: dict, manifest_path: Path) -> None:
    if manifest.get("schema_version") != builder.SCHEMA_VERSION:
        raise ValueError("unexpected v2 calibration schema_version")
    if manifest.get("artifact_type") != builder.ARTIFACT_TYPE:
        raise ValueError("unexpected v2 calibration artifact_type")
    if manifest.get("label_is_human") is not False:
        raise ValueError("v2 calibration must remain non-human")
    if manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("v2 calibration cannot claim human-gold eligibility")
    if manifest.get("development_calibration_only") is not True:
        raise ValueError("v2 calibration must remain development-only")
    if manifest.get("disjoint_from_v1") is not True:
        raise ValueError("v2 calibration must be disjoint from v1")
    if manifest.get("selected_rows") != builder.EXPECTED_CALIBRATION_ROWS:
        raise ValueError("unexpected v2 calibration row count")
    if manifest.get("stratum_targets") != builder.STRATUM_TARGETS:
        raise ValueError("v2 stratum targets drifted")
    if manifest_path.stat().st_mtime_ns < manifest["sealed_at_ns"]:
        raise ValueError("v2 manifest timestamp precedes its seal")
    for section in ("inputs", "outputs"):
        for name, item in manifest.get(section, {}).items():
            path = Path(item["path"])
            if not path.is_file() or builder.v1.sha256(path) != item["sha256"]:
                raise ValueError(f"v2 manifest hash mismatch for {section}.{name}")


def summarize_stratum(rows: list[dict], expected: str | None) -> dict:
    exact = sum(
        row["reviewer_a"]["discrepancy_label"]
        == row["reviewer_b"]["discrepancy_label"]
        for row in rows
    )
    strict_rows = [row for row in rows if row["strict_consensus"]]
    result = {
        "rows": len(rows),
        "expected_label": expected,
        "reviewer_a_label_counts": dict(sorted(Counter(
            row["reviewer_a"]["discrepancy_label"] for row in rows
        ).items())),
        "reviewer_b_label_counts": dict(sorted(Counter(
            row["reviewer_b"]["discrepancy_label"] for row in rows
        ).items())),
        "exact_label_agreement": exact,
        "exact_label_agreement_rate": exact / len(rows),
        "strict_consensus_rows": len(strict_rows),
        "strict_consensus_coverage": len(strict_rows) / len(rows),
        "strict_label_counts": dict(sorted(Counter(
            row["consensus_label"] for row in strict_rows
        ).items())),
        "prior_consensus_replicated_rows": sum(
            row["strict_consensus"]
            and row["consensus_label"] == row["prior_non_human_consensus_label"]
            for row in rows
        ),
    }
    if expected is not None:
        strict_expected = sum(
            row["strict_consensus"] and row["consensus_label"] == expected
            for row in rows
        )
        result["strict_expected_rows"] = strict_expected
        result["strict_expected_rate"] = strict_expected / len(rows)
    else:
        result["strict_expected_rows"] = None
        result["strict_expected_rate"] = None
    return result


def build_gate(overall: dict, strata: dict[str, dict]) -> dict:
    checks = {
        "overall_exact_agreement": (
            overall["exact_label_agreement_rate"] >= MIN_OVERALL_EXACT_AGREEMENT
        ),
        "overall_strict_coverage": (
            overall["strict_consensus_coverage"] >= MIN_OVERALL_STRICT_COVERAGE
        ),
    }
    for stratum in sorted(FIXED_EXPECTED_LABELS):
        checks[f"{stratum}.strict_expected_rate"] = (
            strata[stratum]["strict_expected_rate"]
            >= MIN_FIXED_STRATUM_EXPECTED_RATE
        )
    for stratum in sorted(OPEN_AFFECTED_STRATA):
        checks[f"{stratum}.strict_consensus_coverage"] = (
            strata[stratum]["strict_consensus_coverage"]
            >= MIN_OPEN_STRATUM_STRICT_COVERAGE
        )
    passed = all(checks.values())
    return {
        "status": (
            "ai_contract_v2_candidate_ready_non_human_only"
            if passed
            else "no_go_ai_contract_v2_unstable"
        ),
        "passed": passed,
        "thresholds": {
            "minimum_overall_exact_agreement": MIN_OVERALL_EXACT_AGREEMENT,
            "minimum_overall_strict_coverage": MIN_OVERALL_STRICT_COVERAGE,
            "minimum_fixed_stratum_expected_rate": MIN_FIXED_STRATUM_EXPECTED_RATE,
            "minimum_open_stratum_strict_coverage": MIN_OPEN_STRATUM_STRICT_COVERAGE,
        },
        "checks": checks,
        "scope": "non_human_development_calibration_only",
        "partial_contract_candidate_freeze_allowed": passed,
        "new_non_human_time_cohort_allowed": passed,
        "production_switch_allowed": False,
        "human_gold_claim_allowed": False,
        "confirmatory_performance_claim_allowed": False,
        "human_signed_rows": 0,
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ2 Typing Contract Calibration v2",
        "",
        "> Disjoint, non-human development calibration of the refined field contract.",
        "",
        f"- Rows: `{summary['rows']}`",
        f"- Exact agreement: `{summary['exact_label_agreement']}/{summary['rows']}` (`{summary['exact_label_agreement_rate']:.4f}`)",
        f"- Cohen's kappa: `{summary['cohen_kappa']}`",
        f"- Strict consensus: `{summary['strict_consensus_rows']}/{summary['rows']}` (`{summary['strict_consensus_coverage']:.4f}`)",
        f"- Gate: `{summary['gate']['status']}`",
        "",
        "| Stratum | Rows | Exact | Strict | Expected | Strict expected |",
        "|---|---:|---:|---:|---|---:|",
    ]
    for name, values in sorted(summary["strata"].items()):
        lines.append(
            f"| {name} | {values['rows']} | {values['exact_label_agreement']} | "
            f"{values['strict_consensus_rows']} | {values['expected_label'] or 'case-specific'} | "
            f"{values['strict_expected_rows'] if values['strict_expected_rows'] is not None else '-'} |"
        )
    lines.extend(
        [
            "",
            "The open affected-version strata test reviewer stability only; they do not impose a single label across semantically different cases.",
            "Passing remains non-human evidence and cannot authorize production or human-gold claims.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest(manifest, manifest_path)
    source_path = Path(manifest["outputs"]["source_rows"]["path"])
    blind_a_path = Path(manifest["outputs"]["blind_worklist_a"]["path"])
    blind_b_path = Path(manifest["outputs"]["blind_worklist_b"]["path"])
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    protocol = manifest["review_protocol"]
    reviewer_a_path = Path(protocol["reviewer_a_output"])
    reviewer_b_path = Path(protocol["reviewer_b_output"])
    for path in (reviewer_a_path, reviewer_b_path):
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"reviewer output predates v2 seal: {path}")
    if reviewer_a_path == reviewer_b_path or builder.v1.sha256(
        reviewer_a_path
    ) == builder.v1.sha256(reviewer_b_path):
        raise ValueError("v2 reviewer outputs must be distinct")

    source = v1_merge.load_unique(source_path)
    blind_a = v1_merge.load_unique(blind_a_path)
    blind_b = v1_merge.load_unique(blind_b_path)
    review_a = v1_merge.load_unique(reviewer_a_path)
    review_b = v1_merge.load_unique(reviewer_b_path)
    sample_ids = list(source)
    if not all(set(rows) == set(sample_ids) for rows in (
        blind_a, blind_b, review_a, review_b
    )):
        raise ValueError("v2 source/blind/reviewer sample IDs differ")
    if list(blind_a) != sample_ids or list(blind_b) != list(reversed(sample_ids)):
        raise ValueError("v2 worklist order drifted")

    merged = []
    labels_a = []
    labels_b = []
    manifest_hash = builder.v1.sha256(manifest_path)
    for sample_id in sample_ids:
        source_row = source[sample_id]
        if blind_a[sample_id] != blind_b[sample_id]:
            raise ValueError(f"{sample_id}: v2 reviewers received different raw input")
        left = holdout_merge.validate_review(
            review_a[sample_id], blind_a[sample_id],
            expected_pass_id=protocol["reviewer_a_pass_id"],
            expected_input_path=blind_a_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=protocol["execution_contract"],
        )
        right = holdout_merge.validate_review(
            review_b[sample_id], blind_b[sample_id],
            expected_pass_id=protocol["reviewer_b_pass_id"],
            expected_input_path=blind_b_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=protocol["execution_contract"],
        )
        strict = holdout_merge.is_strict_consensus(left, right)
        labels_a.append(left["discrepancy_label"])
        labels_b.append(right["discrepancy_label"])
        merged.append(
            {
                "artifact_type": "rq2_typing_contract_calibration_v2_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "sample_id": sample_id,
                "cve_id": source_row["cve_id"],
                "field": source_row["field"],
                "calibration_stratum": source_row["calibration_stratum"],
                "expected_label": FIXED_EXPECTED_LABELS.get(
                    source_row["calibration_stratum"]
                ),
                "prior_non_human_consensus_label": source_row[
                    "prior_non_human_consensus_label"
                ],
                "strict_consensus": strict,
                "consensus_label": left["discrepancy_label"] if strict else None,
                "reviewer_a": left,
                "reviewer_b": right,
            }
        )
    sessions_a = {row["execution_session_id"] for row in review_a.values()}
    sessions_b = {row["execution_session_id"] for row in review_b.values()}
    if sessions_a & sessions_b:
        raise ValueError("v2 reviewer A/B sessions must be disjoint")

    strata = {
        stratum: summarize_stratum(
            [row for row in merged if row["calibration_stratum"] == stratum],
            FIXED_EXPECTED_LABELS.get(stratum),
        )
        for stratum in builder.STRATUM_TARGETS
    }
    exact = sum(left == right for left, right in zip(labels_a, labels_b))
    strict_rows = [row for row in merged if row["strict_consensus"]]
    overall = {
        "rows": len(merged),
        "unique_cves": len({row["cve_id"] for row in merged}),
        "exact_label_agreement": exact,
        "exact_label_agreement_rate": exact / len(merged),
        "cohen_kappa": holdout_merge.cohen_kappa(labels_a, labels_b),
        "strict_consensus_rows": len(strict_rows),
        "strict_consensus_coverage": len(strict_rows) / len(merged),
        "prior_consensus_replicated_strict_rows": sum(
            row["strict_consensus"]
            and row["consensus_label"] == row["prior_non_human_consensus_label"]
            for row in merged
        ),
    }
    summary = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_calibration_v2_summary",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_calibration_only": True,
        "disjoint_from_v1": True,
        **overall,
        "strata": strata,
        "gate": build_gate(overall, strata),
        "source_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    cases_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    markdown_path = output_dir / "summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    builder.v1.write_jsonl(cases_path, merged)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_calibration_v2_merge_manifest",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": builder.v1.sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": builder.v1.sha256(reviewer_b_path)},
        },
        "outputs": {
            "cases": {"path": str(cases_path), "sha256": builder.v1.sha256(cases_path)},
            "summary": {"path": str(summary_path), "sha256": builder.v1.sha256(summary_path)},
            "markdown": {"path": str(markdown_path), "sha256": builder.v1.sha256(markdown_path)},
        },
        "gate": summary["gate"],
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {summary_path}")
    print(f"Gate: {summary['gate']['status']}")
    print("Boundary: non-human development calibration; no human-gold claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
