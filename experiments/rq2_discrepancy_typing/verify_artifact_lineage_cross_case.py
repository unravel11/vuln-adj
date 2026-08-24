#!/usr/bin/env python3
"""Independently verify the cross-case artifact-lineage audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_artifact_lineage_cross_case as target


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_cross_case_v1/manifest.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file():
        raise ValueError(f"{name} is missing: {path}")
    observed = target.file_sha256(path)
    if observed != record["sha256"]:
        raise ValueError(f"{name} hash mismatch: expected {record['sha256']}, got {observed}")
    return path


def verify_boundary(boundary: dict) -> None:
    required_false = (
        "selection_uses_reviewer_labels",
        "label_is_human",
        "eligible_for_human_gold_claim",
        "production_switch_allowed",
        "generalization_claim_allowed",
    )
    for key in required_false:
        if boundary.get(key) is not False:
            raise ValueError(f"boundary must keep {key}=false")
    required_true = (
        "upstream_source_conditioned_on_non_human_consensus",
        "post_unsealing",
        "development_diagnostic_only",
    )
    for key in required_true:
        if boundary.get(key) is not True:
            raise ValueError(f"boundary must keep {key}=true")


def validate_manifest(manifest: dict, manifest_path: Path) -> dict:
    if manifest.get("schema_version") != target.SCHEMA_VERSION:
        raise ValueError("unexpected schema version")
    verify_boundary(manifest.get("boundary") or {})
    input_paths = {
        name: verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    analysis_path = verified_record(manifest["outputs"]["analysis"], "output:analysis")
    markdown_path = verified_record(manifest["outputs"]["markdown"], "output:markdown")

    expected_cache_names = {
        name
        for source in target.EVIDENCE_SOURCES
        for name in (f"{source.key}.response", f"{source.key}.fetch.json")
    }
    if set(manifest["evidence_cache"]) != expected_cache_names:
        raise ValueError("evidence cache inventory differs from the fixed source specification")
    cache_paths = {
        name: verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    bodies = {}
    for source in target.EVIDENCE_SOURCES:
        response_path = cache_paths[f"{source.key}.response"]
        metadata_path = cache_paths[f"{source.key}.fetch.json"]
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        body = response_path.read_bytes()
        if metadata.get("url") != source.url:
            raise ValueError(f"cached URL drift for {source.key}")
        if metadata.get("http_status") != 200:
            raise ValueError(f"cached response status is not 200 for {source.key}")
        if metadata.get("response_sha256") != target.bytes_sha256(body):
            raise ValueError(f"cached response body hash mismatch for {source.key}")
        bodies[source.key] = body

    cohort = target.load_jsonl(input_paths["cohort"])
    cohort_manifest = json.loads(input_paths["cohort_manifest"].read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != target.file_sha256(input_paths["cohort"]):
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
        target.reviewer_labels(input_paths["reviewer_a_diagnostic_only"]),
        target.reviewer_labels(input_paths["reviewer_b_diagnostic_only"]),
    )
    observed = json.loads(analysis_path.read_text(encoding="utf-8"))
    if observed != recomputed:
        raise ValueError("analysis does not match deterministic recomputation")
    if markdown_path.read_text(encoding="utf-8") != target.render_markdown(recomputed):
        raise ValueError("Markdown does not match deterministic rendering")
    if recomputed["row_count"] != len(target.CASE_SPECS):
        raise ValueError("row count differs from the fixed case specification")
    if recomputed["projection_gate_passed"] != recomputed["row_count"]:
        raise ValueError("not every fixed cross-case projection gate passed")
    if recomputed["non_human_consistency_only"]["rows_matching_both_sealed_ai_reviewers"] != recomputed["row_count"]:
        raise ValueError("development candidates do not match both sealed AI reviewers")
    if manifest["summary"] != {
        "row_count": recomputed["row_count"],
        "projection_gate_passed": recomputed["projection_gate_passed"],
        "projection_coverage": recomputed["projection_coverage"],
    }:
        raise ValueError("manifest summary mismatch")
    return recomputed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    analysis = validate_manifest(manifest, manifest_path)
    print(
        "Verified cross-case artifact-lineage audit: "
        f"{analysis['projection_gate_passed']}/{analysis['row_count']} gates passed; "
        "non-human development boundary preserved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
