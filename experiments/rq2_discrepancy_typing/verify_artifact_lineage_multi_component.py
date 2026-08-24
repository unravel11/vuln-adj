#!/usr/bin/env python3
"""Independently recompute and verify the multi-component lineage audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_artifact_lineage_cross_case as graph
import analyze_artifact_lineage_multi_component as target
import verify_artifact_lineage_cross_case as cross_verify


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_multi_component_v1/manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verify_fixed_outcome(analysis: dict) -> None:
    if analysis.get("row_count") != 1:
        raise ValueError("fixed multi-component row count must be 1")
    if analysis.get("projection_gate_passed") != 1:
        raise ValueError("fixed multi-component projection must pass 1/1")
    if analysis.get("component_count") != 2:
        raise ValueError("fixed multi-component audit must bind two components")
    if analysis.get("component_heterogeneity_count") != 0:
        raise ValueError("fixed component sets must be homogeneous")
    if analysis.get("candidate_counts") != {"representation_discrepancy": 1}:
        raise ValueError("unexpected fixed development candidate")
    consistency = analysis.get("non_human_consistency_only") or {}
    if consistency.get("rows_matching_both_sealed_ai_reviewers") != 0:
        raise ValueError("fixed candidate must retain disagreement with sealed reviewers")
    case = analysis["cases"][0]
    if case["release_sets"]["relation"] != "equal":
        raise ValueError("fixed product release-set relation must be equal")
    if case["release_sets"]["nvd_product_versions"] != ["1.4.0", "1.5.0"]:
        raise ValueError("unexpected fixed NVD product set")
    if case["release_sets"]["ghsa_component_union_versions"] != [
        "1.4.0",
        "1.5.0",
    ]:
        raise ValueError("unexpected fixed GHSA component union")
    diagnostic = analysis.get("contract_diagnostic") or {}
    if diagnostic.get("status") != (
        "snapshot_extensional_projection_supported_human_resolution_required"
    ):
        raise ValueError("unexpected contract diagnostic")
    if diagnostic.get("production_switch_allowed") is not False:
        raise ValueError("production switch boundary drift")


def validate_manifest(manifest: dict) -> dict:
    if manifest.get("schema_version") != target.SCHEMA_VERSION:
        raise ValueError("unexpected schema version")
    cross_verify.verify_boundary(manifest.get("boundary") or {})
    input_paths = {
        name: cross_verify.verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    analysis_path = cross_verify.verified_record(
        manifest["outputs"]["analysis"], "output:analysis"
    )
    markdown_path = cross_verify.verified_record(
        manifest["outputs"]["markdown"], "output:markdown"
    )
    expected_cache_names = {
        name
        for evidence in target.EVIDENCE_SOURCES
        for name in (f"{evidence.key}.response", f"{evidence.key}.fetch.json")
    }
    if set(manifest["evidence_cache"]) != expected_cache_names:
        raise ValueError("evidence cache inventory differs from fixed sources")
    cache_paths = {
        name: cross_verify.verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    bodies = {}
    for evidence in target.EVIDENCE_SOURCES:
        response_path = cache_paths[f"{evidence.key}.response"]
        metadata_path = cache_paths[f"{evidence.key}.fetch.json"]
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != evidence.url or metadata.get("http_status") != 200:
            raise ValueError(f"cache provenance mismatch for {evidence.key}")
        if metadata.get("response_sha256") != graph.bytes_sha256(body):
            raise ValueError(f"cache body hash mismatch for {evidence.key}")
        bodies[evidence.key] = body

    cohort = graph.load_jsonl(input_paths["cohort"])
    cohort_manifest = json.loads(
        input_paths["cohort_manifest"].read_text(encoding="utf-8")
    )
    if cohort_manifest["output"]["sha256"] != graph.file_sha256(
        input_paths["cohort"]
    ):
        raise ValueError("cohort seal mismatch")
    if any(
        row.get("selection_uses_reviewer_labels") is not False
        or row.get("selection_uses_non_human_consensus") is not False
        or row.get("label_is_human") is not False
        for row in cohort
    ):
        raise ValueError("cohort epistemic boundary drift")
    cases = [target.analyze_case(row, bodies) for row in cohort]
    recomputed = target.build_summary(
        cases,
        graph.reviewer_labels(input_paths["reviewer_a_diagnostic_only"]),
        graph.reviewer_labels(input_paths["reviewer_b_diagnostic_only"]),
    )
    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    if observed != recomputed:
        raise ValueError("analysis does not match deterministic recomputation")
    if markdown_path.read_text(encoding="utf-8") != target.render_markdown(recomputed):
        raise ValueError("Markdown does not match deterministic rendering")
    if manifest.get("contract_diagnostic") != recomputed["contract_diagnostic"]:
        raise ValueError("manifest contract diagnostic mismatch")
    if manifest.get("summary") != {
        "row_count": recomputed["row_count"],
        "projection_gate_passed": recomputed["projection_gate_passed"],
        "component_count": recomputed["component_count"],
    }:
        raise ValueError("manifest summary mismatch")
    verify_fixed_outcome(recomputed)
    return recomputed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified multi-component artifact-lineage audit: "
        f"{analysis['projection_gate_passed']}/{analysis['row_count']} projection; "
        "human semantic resolution remains required"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
