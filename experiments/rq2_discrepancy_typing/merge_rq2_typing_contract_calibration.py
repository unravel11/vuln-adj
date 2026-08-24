#!/usr/bin/env python3
"""Validate and merge the sealed RQ2 construct-calibration reviews."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import build_rq2_typing_contract_calibration as builder
import merge_rq2_typing_holdout_reviews as holdout_merge


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v1"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v1"
)
MIN_OVERALL_EXACT_AGREEMENT = 0.85
MIN_OVERALL_STRICT_COVERAGE = 0.80
MIN_STRATUM_STRICT_EXPECTED_RATE = 0.80
EXPECTED_BOUNDARY_LABELS = {
    "severity_exact_vector_one_missing_score": "incomplete",
    "severity_prefix_vector_one_missing_score": "incomplete",
    "severity_different_vector_one_missing_score": "factual_conflict",
    "severity_missing_vector_one_missing_score": "incomplete",
    "affected_one_sided_unbounded_claim": "incomplete",
}
CORE_GATE_STRATA = {
    "severity_exact_vector_one_missing_score",
    "severity_prefix_vector_one_missing_score",
    "severity_different_vector_one_missing_score",
    "affected_one_sided_unbounded_claim",
    "severity_unchanged_control",
    "affected_versions_unchanged_control",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_unique(path: Path) -> dict[str, dict]:
    result = {}
    for row in builder.iter_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in result:
            raise ValueError(f"{path}: missing or duplicate sample_id={sample_id}")
        result[sample_id] = row
    return result


def expected_label(source: dict) -> str:
    stratum = source["calibration_stratum"]
    if stratum in EXPECTED_BOUNDARY_LABELS:
        return EXPECTED_BOUNDARY_LABELS[stratum]
    if stratum.endswith("_unchanged_control"):
        return source["prior_non_human_consensus_label"]
    raise ValueError(f"unknown calibration stratum: {stratum}")


def validate_manifest(manifest: dict, manifest_path: Path) -> None:
    if manifest.get("schema_version") != builder.SCHEMA_VERSION:
        raise ValueError("unexpected calibration schema_version")
    if manifest.get("artifact_type") != builder.ARTIFACT_TYPE:
        raise ValueError("unexpected calibration artifact_type")
    if manifest.get("label_is_human") is not False:
        raise ValueError("calibration must remain non-human")
    if manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("calibration cannot claim human-gold eligibility")
    if manifest.get("development_calibration_only") is not True:
        raise ValueError("calibration must be marked development-only")
    if manifest.get("selected_rows") != builder.EXPECTED_CALIBRATION_ROWS:
        raise ValueError("unexpected calibration row count")
    if manifest.get("stratum_targets") != builder.STRATUM_TARGETS:
        raise ValueError("calibration stratum targets drifted")
    if manifest_path.stat().st_mtime_ns < manifest["sealed_at_ns"]:
        raise ValueError("calibration manifest timestamp precedes its seal")
    for section in ("inputs", "outputs"):
        for name, item in manifest.get(section, {}).items():
            path = Path(item["path"])
            if not path.is_file() or builder.sha256(path) != item["sha256"]:
                raise ValueError(f"manifest hash mismatch for {section}.{name}")


def summarize_stratum(rows: list[dict]) -> dict:
    exact = sum(
        row["reviewer_a"]["discrepancy_label"]
        == row["reviewer_b"]["discrepancy_label"]
        for row in rows
    )
    strict_rows = [row for row in rows if row["strict_consensus"]]
    strict_expected = sum(
        row["strict_consensus"] and row["consensus_label"] == row["expected_label"]
        for row in rows
    )
    return {
        "rows": len(rows),
        "expected_label_counts": dict(sorted(Counter(
            row["expected_label"] for row in rows
        ).items())),
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
        "strict_expected_rows": strict_expected,
        "strict_expected_rate": strict_expected / len(rows),
        "strict_label_counts": dict(sorted(Counter(
            row["consensus_label"] for row in strict_rows
        ).items())),
    }


def build_gate(overall: dict, strata: dict[str, dict]) -> dict:
    checks = {
        "overall_exact_agreement": (
            overall["exact_label_agreement_rate"] >= MIN_OVERALL_EXACT_AGREEMENT
        ),
        "overall_strict_coverage": (
            overall["strict_consensus_coverage"] >= MIN_OVERALL_STRICT_COVERAGE
        ),
    }
    for stratum in sorted(CORE_GATE_STRATA):
        checks[f"{stratum}.strict_expected_rate"] = (
            strata[stratum]["strict_expected_rate"]
            >= MIN_STRATUM_STRICT_EXPECTED_RATE
        )
    passed = all(checks.values())
    return {
        "status": (
            "ai_contract_candidate_ready_non_human_only"
            if passed
            else "no_go_ai_calibration_unstable"
        ),
        "passed": passed,
        "thresholds": {
            "minimum_overall_exact_agreement": MIN_OVERALL_EXACT_AGREEMENT,
            "minimum_overall_strict_coverage": MIN_OVERALL_STRICT_COVERAGE,
            "minimum_core_stratum_strict_expected_rate": (
                MIN_STRATUM_STRICT_EXPECTED_RATE
            ),
        },
        "checks": checks,
        "scope": "non_human_development_calibration_only",
        "candidate_profile_freeze_allowed": passed,
        "new_non_human_time_cohort_allowed": passed,
        "production_switch_allowed": False,
        "human_gold_claim_allowed": False,
        "confirmatory_performance_claim_allowed": False,
        "human_signed_rows": 0,
        "human_gate_remains": "no_go_until_real_people_sign_the_human_packet",
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ2 Typing Contract Calibration v1",
        "",
        "> Non-human, development-only construct calibration on identical frozen raw inputs.",
        "",
        f"- Rows: `{summary['rows']}`",
        f"- Exact agreement: `{summary['exact_label_agreement']}/{summary['rows']}` (`{summary['exact_label_agreement_rate']:.4f}`)",
        f"- Cohen's kappa: `{summary['cohen_kappa']}`",
        f"- Strict consensus: `{summary['strict_consensus_rows']}/{summary['rows']}` (`{summary['strict_consensus_coverage']:.4f}`)",
        f"- Gate: `{summary['gate']['status']}`",
        "",
        "| Stratum | Rows | Exact | Strict | Strict expected |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, values in sorted(summary["strata"].items()):
        lines.append(
            f"| {name} | {values['rows']} | {values['exact_label_agreement']} "
            f"| {values['strict_consensus_rows']} | {values['strict_expected_rows']} |"
        )
    lines.extend(
        [
            "",
            "Passing this gate may freeze an AI contract candidate for another non-human time-cohort diagnostic. It never creates human gold or permits a production switch.",
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
            raise ValueError(f"reviewer output predates the calibration seal: {path}")
    if reviewer_a_path == reviewer_b_path or builder.sha256(
        reviewer_a_path
    ) == builder.sha256(reviewer_b_path):
        raise ValueError("reviewer outputs must be distinct")

    source = load_unique(source_path)
    blind_a = load_unique(blind_a_path)
    blind_b = load_unique(blind_b_path)
    review_a = load_unique(reviewer_a_path)
    review_b = load_unique(reviewer_b_path)
    sample_ids = list(source)
    if not all(set(rows) == set(sample_ids) for rows in (
        blind_a, blind_b, review_a, review_b
    )):
        raise ValueError("source/blind/reviewer sample ID sets differ")
    if list(blind_a) != sample_ids or list(blind_b) != list(reversed(sample_ids)):
        raise ValueError("calibration worklist order drifted")

    merged = []
    labels_a = []
    labels_b = []
    manifest_hash = builder.sha256(manifest_path)
    for sample_id in sample_ids:
        source_row = source[sample_id]
        if blind_a[sample_id] != blind_b[sample_id]:
            raise ValueError(f"{sample_id}: reviewers did not receive identical raw input")
        left = holdout_merge.validate_review(
            review_a[sample_id],
            blind_a[sample_id],
            expected_pass_id=protocol["reviewer_a_pass_id"],
            expected_input_path=blind_a_path,
            expected_prompt_path=prompt_path,
            expected_manifest_path=manifest_path,
            expected_manifest_sha256=manifest_hash,
            expected_execution=protocol["execution_contract"],
        )
        right = holdout_merge.validate_review(
            review_b[sample_id],
            blind_b[sample_id],
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
                "artifact_type": "rq2_typing_contract_calibration_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "sample_id": sample_id,
                "cve_id": source_row["cve_id"],
                "field": source_row["field"],
                "calibration_stratum": source_row["calibration_stratum"],
                "expected_label": expected_label(source_row),
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
        raise ValueError("reviewer A/B execution sessions must be disjoint")

    strata = {
        stratum: summarize_stratum([
            row for row in merged if row["calibration_stratum"] == stratum
        ])
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
    }
    summary = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_calibration_summary",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_calibration_only": True,
        **overall,
        "strata": strata,
        "gate": build_gate(overall, strata),
        "contract_candidate": {
            "same_canonical_label_and_exact_or_prefix_vector_with_one_missing_score": "incomplete",
            "same_canonical_label_and_materially_different_vectors": "factual_conflict",
            "one_sided_unbounded_affected_claim": "incomplete",
            "missing_vector_case": "exploratory_not_gate_binding",
            "prompt_path": str(prompt_path),
            "prompt_sha256": builder.sha256(prompt_path),
        },
        "source_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
        "reviewer_files": {
            "a": {"path": str(reviewer_a_path), "sha256": builder.sha256(reviewer_a_path)},
            "b": {"path": str(reviewer_b_path), "sha256": builder.sha256(reviewer_b_path)},
        },
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    cases_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    markdown_path = output_dir / "summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    builder.write_jsonl(cases_path, merged)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_calibration_merge_manifest",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": builder.sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": builder.sha256(reviewer_b_path)},
        },
        "outputs": {
            "cases": {"path": str(cases_path), "sha256": builder.sha256(cases_path)},
            "summary": {"path": str(summary_path), "sha256": builder.sha256(summary_path)},
            "markdown": {"path": str(markdown_path), "sha256": builder.sha256(markdown_path)},
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
