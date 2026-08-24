#!/usr/bin/env python3
"""Validate and merge the RQ2 v2 evidence-backed secondary reviews."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import build_rq2_typing_contract_evidence_secondary as builder
import build_rq2_typing_contract_calibration as v1
import merge_rq2_typing_contract_calibration as v1_merge
import merge_rq2_typing_holdout_reviews as holdout_merge


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = builder.DEFAULT_OUTPUT_DIR
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "evidence_secondary_v1"
)
TIMESTAMP_TOLERANCE_NS = 1_000_000_000


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
        raise ValueError("unexpected evidence-secondary schema version")
    if manifest.get("artifact_type") != builder.ARTIFACT_TYPE:
        raise ValueError("unexpected evidence-secondary artifact type")
    if manifest.get("label_is_human") is not False or manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("evidence secondary must remain non-human")
    if manifest.get("selected_rows") != 1 or manifest.get("target_sample_id") != builder.TARGET_SAMPLE_ID:
        raise ValueError("evidence secondary target drifted")
    if manifest.get("evidence_records") != len(builder.EVIDENCE_SOURCES):
        raise ValueError("evidence record count drifted")
    if (
        manifest_path.stat().st_mtime_ns + TIMESTAMP_TOLERANCE_NS
        < manifest["sealed_at_ns"]
    ):
        raise ValueError("manifest timestamp precedes its seal")
    for section in ("inputs", "evidence_cache", "outputs"):
        for name, item in manifest[section].items():
            path = Path(item["path"])
            if not path.is_file() or v1.sha256(path) != item["sha256"]:
                raise ValueError(f"manifest hash mismatch for {section}.{name}")


def build_gate(parent_summary: dict, strict: bool, evidence_backed: bool) -> dict:
    parent_checks = parent_summary["gate"]["checks"]
    remaining_parent_checks = {
        name: passed
        for name, passed in parent_checks.items()
        if name != "affected_prerelease_boundary.strict_consensus_coverage"
    }
    parent_prerelease = parent_summary["strata"]["affected_prerelease_boundary"]
    adjusted_prerelease_strict = parent_prerelease["strict_consensus_rows"] + int(strict)
    adjusted_prerelease_rate = adjusted_prerelease_strict / parent_prerelease["rows"]
    checks = {
        "all_non_prerelease_v2_checks": all(remaining_parent_checks.values()),
        "secondary_strict_consensus": strict,
        "secondary_frozen_evidence_citation": evidence_backed,
        "adjusted_prerelease_strict_coverage": adjusted_prerelease_rate >= 0.80,
    }
    passed = all(checks.values())
    return {
        "status": (
            "ai_contract_v2_evidence_augmented_candidate_ready_non_human_only"
            if passed
            else "no_go_ai_contract_v2_evidence_secondary_unresolved"
        ),
        "passed": passed,
        "checks": checks,
        "parent_v2_strict_consensus_rows": parent_summary["strict_consensus_rows"],
        "evidence_augmented_strict_consensus_rows": (
            parent_summary["strict_consensus_rows"] + int(strict)
        ),
        "evidence_augmented_rows": parent_summary["rows"],
        "adjusted_prerelease_strict_consensus_rows": adjusted_prerelease_strict,
        "adjusted_prerelease_strict_coverage": adjusted_prerelease_rate,
        "scope": "non_human_development_calibration_only",
        "partial_contract_candidate_freeze_allowed": passed,
        "new_non_human_time_cohort_allowed": passed,
        "production_switch_allowed": False,
        "human_gold_claim_allowed": False,
        "confirmatory_performance_claim_allowed": False,
        "human_signed_rows": 0,
    }


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest(manifest, manifest_path)
    protocol = manifest["review_protocol"]
    source_path = Path(manifest["outputs"]["source_rows"]["path"])
    blind_a_path = Path(manifest["outputs"]["blind_worklist_a"]["path"])
    blind_b_path = Path(manifest["outputs"]["blind_worklist_b"]["path"])
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    reviewer_a_path = Path(protocol["reviewer_a_output"])
    reviewer_b_path = Path(protocol["reviewer_b_output"])
    for path in (reviewer_a_path, reviewer_b_path):
        if not path.is_file() or path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"missing or pre-seal reviewer output: {path}")
    if v1.sha256(reviewer_a_path) == v1.sha256(reviewer_b_path):
        raise ValueError("secondary reviewer files must be distinct")

    source = v1_merge.load_unique(source_path)
    blind_a = v1_merge.load_unique(blind_a_path)
    blind_b = v1_merge.load_unique(blind_b_path)
    review_a = v1_merge.load_unique(reviewer_a_path)
    review_b = v1_merge.load_unique(reviewer_b_path)
    if any(set(rows) != {builder.TARGET_SAMPLE_ID} for rows in (source, blind_a, blind_b, review_a, review_b)):
        raise ValueError("secondary review sample IDs drifted")
    if blind_a[builder.TARGET_SAMPLE_ID] != blind_b[builder.TARGET_SAMPLE_ID]:
        raise ValueError("reviewers received different secondary input")
    manifest_hash = v1.sha256(manifest_path)
    left = holdout_merge.validate_review(
        review_a[builder.TARGET_SAMPLE_ID], blind_a[builder.TARGET_SAMPLE_ID],
        expected_pass_id=protocol["reviewer_a_pass_id"],
        expected_input_path=blind_a_path,
        expected_prompt_path=prompt_path,
        expected_manifest_path=manifest_path,
        expected_manifest_sha256=manifest_hash,
        expected_execution=protocol["execution_contract"],
    )
    right = holdout_merge.validate_review(
        review_b[builder.TARGET_SAMPLE_ID], blind_b[builder.TARGET_SAMPLE_ID],
        expected_pass_id=protocol["reviewer_b_pass_id"],
        expected_input_path=blind_b_path,
        expected_prompt_path=prompt_path,
        expected_manifest_path=manifest_path,
        expected_manifest_sha256=manifest_hash,
        expected_execution=protocol["execution_contract"],
    )
    sessions_a = {row["execution_session_id"] for row in review_a.values()}
    sessions_b = {row["execution_session_id"] for row in review_b.values()}
    if sessions_a & sessions_b:
        raise ValueError("secondary reviewer sessions must be disjoint")
    strict = holdout_merge.is_strict_consensus(left, right)
    frozen_urls = {
        record["url"]
        for record in blind_a[builder.TARGET_SAMPLE_ID]["evidence_context"]["records"]
    }
    minimum = protocol["minimum_cited_frozen_evidence_urls"]
    evidence_backed = all(
        len(set(annotation["evidence_urls"]) & frozen_urls) >= minimum
        for annotation in (left, right)
    )
    parent_summary_path = Path(manifest["inputs"]["v2_summary"]["path"])
    parent_summary = json.loads(parent_summary_path.read_text(encoding="utf-8"))
    gate = build_gate(parent_summary, strict, evidence_backed)
    case = {
        "artifact_type": "rq2_typing_contract_evidence_secondary_v1_case",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "sample_id": builder.TARGET_SAMPLE_ID,
        "cve_id": builder.TARGET_CVE_ID,
        "strict_consensus": strict,
        "consensus_label": left["discrepancy_label"] if strict else None,
        "frozen_evidence_citation_passed": evidence_backed,
        "reviewer_a": left,
        "reviewer_b": right,
    }
    summary = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_evidence_secondary_v1_summary",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_calibration_only": True,
        "rows": 1,
        "exact_label_agreement": int(left["discrepancy_label"] == right["discrepancy_label"]),
        "strict_consensus_rows": int(strict),
        "consensus_label": case["consensus_label"],
        "frozen_evidence_citation_passed": evidence_backed,
        "gate": gate,
        "source_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    cases_path = output_dir / "dual_review_consensus.jsonl"
    summary_path = output_dir / "summary.json"
    markdown_path = output_dir / "summary.md"
    merge_manifest_path = output_dir / "merge_manifest.json"
    v1.write_jsonl(cases_path, [case])
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(
        "\n".join([
            "# RQ2 Typing Contract Evidence Secondary v1", "",
            "> One-row, evidence-backed, non-human development calibration.", "",
            f"- Exact agreement: `{summary['exact_label_agreement']}/1`",
            f"- Strict consensus: `{summary['strict_consensus_rows']}/1`",
            f"- Consensus label: `{summary['consensus_label']}`",
            f"- Frozen evidence citation: `{summary['frozen_evidence_citation_passed']}`",
            f"- Gate: `{gate['status']}`", "",
            "This result cannot authorize production or a human-gold claim.", "",
        ]),
        encoding="utf-8",
    )
    merge_manifest = {
        "schema_version": builder.SCHEMA_VERSION,
        "artifact_type": "rq2_typing_contract_evidence_secondary_v1_merge_manifest",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "inputs": {
            "sealed_manifest": {"path": str(manifest_path), "sha256": manifest_hash},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": v1.sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": v1.sha256(reviewer_b_path)},
        },
        "outputs": {
            "cases": {"path": str(cases_path), "sha256": v1.sha256(cases_path)},
            "summary": {"path": str(summary_path), "sha256": v1.sha256(summary_path)},
            "markdown": {"path": str(markdown_path), "sha256": v1.sha256(markdown_path)},
        },
        "gate": gate,
    }
    merge_manifest_path.write_text(json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {summary_path}")
    print(f"Gate: {gate['status']}")
    print("Boundary: non-human evidence secondary; no human-gold claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
