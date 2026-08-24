#!/usr/bin/env python3
"""Independently recompute the unseen-ecosystem artifact-lineage no-go."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_artifact_lineage_cross_case as graph
import analyze_artifact_lineage_unseen_ecosystem as target
import verify_artifact_lineage_cross_case as cross_verify


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_unseen_ecosystem_v1/manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verify_boundary(boundary: dict) -> None:
    for name in (
        "selection_uses_reviewer_labels",
        "upstream_source_conditioned_on_non_human_consensus",
        "label_is_human",
        "eligible_for_human_gold_claim",
        "production_switch_allowed",
        "generalization_claim_allowed",
    ):
        if boundary.get(name) is not False:
            raise ValueError(f"boundary must keep {name}=false")
    for name in ("post_unsealing", "development_diagnostic_only"):
        if boundary.get(name) is not True:
            raise ValueError(f"boundary must keep {name}=true")


def verify_fixed_outcome(analysis: dict) -> None:
    if analysis.get("row_count") != 3:
        raise ValueError("fixed unseen-ecosystem row count must be 3")
    if analysis.get("projection_gate_passed") != 0:
        raise ValueError("fixed unseen-ecosystem projection coverage must be 0/3")
    if analysis.get("component_heterogeneity_count") != 3:
        raise ValueError("all fixed component release sets must remain heterogeneous")
    if analysis.get("candidate_counts") != {"uncertain": 3}:
        raise ValueError("all fixed candidates must abstain as uncertain")
    gate = analysis.get("advancement_gate") or {}
    if gate.get("status") != "no_go_unseen_ecosystem_graph_unstable":
        raise ValueError("unseen-ecosystem advancement gate must remain no-go")
    if gate.get("passed") is not False or gate.get("observed_projection_coverage") != 0:
        raise ValueError("unexpected fixed advancement outcome")
    if gate.get("observed_passing_ecosystems") != []:
        raise ValueError("no fixed ecosystem should pass the product projection")
    if gate.get("failed_checks") != [
        "minimum_projection_coverage",
        "minimum_passing_ecosystems",
    ]:
        raise ValueError("unexpected fixed advancement failure set")
    expected_case_failures = {
        target.NUGET_SAMPLE: {
            "component_boundaries_in_registry_catalogs",
            "nvd_product_release_domain_bound",
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        },
        target.PYPI_SAMPLE: {
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        },
        target.CRATES_SAMPLE: {
            "component_boundaries_in_registry_catalogs",
            "nvd_product_release_domain_bound",
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        },
    }
    for case in analysis["cases"]:
        observed = set(case["gate"]["failed_checks"])
        if observed != expected_case_failures[case["sample_id"]]:
            raise ValueError(
                f"unexpected failure set for {case['sample_id']}: {sorted(observed)}"
            )


def validate_manifest(manifest: dict) -> dict:
    if manifest.get("schema_version") != target.SCHEMA_VERSION:
        raise ValueError("unexpected schema version")
    verify_boundary(manifest.get("boundary") or {})
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
        for source in target.EVIDENCE_SOURCES
        for name in (f"{source.key}.response", f"{source.key}.fetch.json")
    }
    if set(manifest["evidence_cache"]) != expected_cache_names:
        raise ValueError("evidence cache inventory differs from fixed source list")
    cache_paths = {
        name: cross_verify.verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    bodies = {}
    for source in target.EVIDENCE_SOURCES:
        response_path = cache_paths[f"{source.key}.response"]
        metadata_path = cache_paths[f"{source.key}.fetch.json"]
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != source.url or metadata.get("http_status") != 200:
            raise ValueError(f"cache provenance mismatch for {source.key}")
        if metadata.get("response_sha256") != graph.bytes_sha256(body):
            raise ValueError(f"cache body hash mismatch for {source.key}")
        bodies[source.key] = body

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
        or row.get("upstream_source_conditioned_on_non_human_consensus") is not False
        or row.get("label_is_human") is not False
        for row in cohort
    ):
        raise ValueError("cohort epistemic boundary drift")
    cases = [target.analyze_case(row, bodies) for row in cohort]
    recomputed = target.build_summary(cases)
    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    if observed != recomputed:
        raise ValueError("analysis does not match deterministic recomputation")
    if markdown_path.read_text(encoding="utf-8") != target.render_markdown(recomputed):
        raise ValueError("Markdown does not match deterministic rendering")
    if manifest.get("advancement_gate") != recomputed["advancement_gate"]:
        raise ValueError("manifest advancement gate mismatch")
    verify_fixed_outcome(recomputed)
    return recomputed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified unseen-ecosystem artifact-lineage audit: "
        f"{analysis['projection_gate_passed']}/{analysis['row_count']} projections; "
        "advancement gate no-go"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
