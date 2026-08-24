#!/usr/bin/env python3
"""Independently verify the non-equal artifact-lineage no-go result."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_artifact_lineage_cross_case as graph
import analyze_artifact_lineage_non_equal as target
import verify_artifact_lineage_cross_case as cross_verify


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_non_equal_v1/manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verify_fixed_outcome(analysis: dict) -> None:
    if analysis.get("row_count") != 5:
        raise ValueError("fixed non-equal row count must be 5")
    if analysis.get("projection_gate_passed") != 4:
        raise ValueError("fixed non-equal projection coverage must be 4/5")
    consistency = analysis.get("non_human_consistency_only") or {}
    if consistency.get("rows_matching_both_sealed_ai_reviewers") != 2:
        raise ValueError("fixed non-equal AI consistency count must be 2/5")
    gate = analysis.get("advancement_gate") or {}
    if gate.get("status") != "no_go_non_equal_graph_unstable" or gate.get("passed") is not False:
        raise ValueError("non-equal advancement gate must remain no-go")
    if gate.get("observed_projection_coverage") != 0.8:
        raise ValueError("unexpected projection coverage")
    if gate.get("observed_both_reviewer_consistency") != 0.4:
        raise ValueError("unexpected reviewer-consistency diagnostic")
    if gate.get("failed_checks") != ["minimum_both_reviewer_consistency"]:
        raise ValueError("unexpected advancement-gate failure set")


def validate_manifest(manifest: dict) -> dict:
    if manifest.get("schema_version") != target.SCHEMA_VERSION:
        raise ValueError("unexpected schema version")
    cross_verify.verify_boundary(manifest.get("boundary") or {})
    input_paths = {
        name: cross_verify.verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    analysis_path = cross_verify.verified_record(manifest["outputs"]["analysis"], "output:analysis")
    markdown_path = cross_verify.verified_record(manifest["outputs"]["markdown"], "output:markdown")
    expected_cache_names = {
        name
        for evidence in target.EVIDENCE_SOURCES
        for name in (f"{evidence.key}.response", f"{evidence.key}.fetch.json")
    }
    if set(manifest["evidence_cache"]) != expected_cache_names:
        raise ValueError("evidence cache inventory differs from fixed non-equal sources")
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
    cohort_manifest = json.loads(input_paths["cohort_manifest"].read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != graph.file_sha256(input_paths["cohort"]):
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
    if manifest.get("advancement_gate") != recomputed["advancement_gate"]:
        raise ValueError("manifest advancement gate mismatch")
    verify_fixed_outcome(recomputed)
    return recomputed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified non-equal artifact-lineage audit: "
        f"{analysis['projection_gate_passed']}/{analysis['row_count']} projections, "
        f"{analysis['non_human_consistency_only']['rows_matching_both_sealed_ai_reviewers']}/{analysis['row_count']} AI consistency; "
        "advancement gate no-go"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
