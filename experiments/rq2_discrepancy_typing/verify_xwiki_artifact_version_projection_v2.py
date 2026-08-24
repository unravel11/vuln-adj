#!/usr/bin/env python3
"""Independently verify the lineage-aware XWiki projection v2."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_xwiki_artifact_version_projection_v2 as audit
import build_rq2_typing_contract_calibration as calibration


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = audit.DEFAULT_OUTPUT_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def validate_analysis(analysis: dict) -> None:
    if analysis.get("schema_version") != audit.SCHEMA_VERSION:
        raise ValueError("unexpected v2 projection schema version")
    if analysis.get("label_is_human") is not False:
        raise ValueError("v2 projection must remain non-human")
    if analysis.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("v2 projection cannot claim human-gold eligibility")
    if analysis.get("post_unsealing_conditional_analysis") is not True:
        raise ValueError("v2 projection must retain post-unsealing boundary")
    if analysis.get("sample_id") != audit.v1.secondary.TARGET_SAMPLE_ID:
        raise ValueError("v2 projection sample drifted")

    edges = analysis.get("product_to_legacy_edges") or {}
    if set(edges) != set(audit.PRODUCT_RELEASES):
        raise ValueError("product release edge set drifted")
    for product_version, expected_legacy in audit.EXPECTED_PRODUCT_TO_LEGACY.items():
        edge = edges[product_version]
        if edge.get("legacy_coordinate") != audit.v1.LEGACY_COORDINATE:
            raise ValueError(f"{product_version}: legacy coordinate drifted")
        if edge.get("legacy_version") != expected_legacy:
            raise ValueError(f"{product_version}: legacy version edge drifted")
        if edge.get("core_version") != product_version:
            raise ValueError(f"{product_version}: core version edge drifted")
        if edge.get("edge_bound") is not True:
            raise ValueError(f"{product_version}: dependency edge is not bound")

    lineage = analysis.get("source_lineage") or {}
    if lineage.get("relevant_files_checked") != len(audit.RELEVANT_CLASSES):
        raise ValueError("relevant source-file count drifted")
    if lineage.get("transition_common_relevant_files") != len(audit.RELEVANT_CLASSES):
        raise ValueError("legacy/current common source count drifted")
    if lineage.get("transition_identical_relevant_files") != len(audit.RELEVANT_CLASSES):
        raise ValueError("legacy/current identical source count drifted")
    if lineage.get("source_continuity_bound") is not True:
        raise ValueError("legacy/current source continuity is not bound")
    for version, values in (lineage.get("relevant_class_presence") or {}).items():
        if set(values) != set(audit.RELEVANT_CLASSES) or not all(values.values()):
            raise ValueError(f"{version}: relevant class presence drifted")

    projection = analysis.get("release_set_projection") or {}
    if projection.get("relation") != "strict_subset":
        raise ValueError("release-set relation is not strict_subset")
    if projection.get("nvd_only") != []:
        raise ValueError("NVD contains releases absent from GHSA")
    if projection.get("ghsa_only") != ["3.0-milestone-1"]:
        raise ValueError("GHSA-only release set drifted")
    if projection.get("ghsa_release_count") != projection.get("nvd_release_count") + 1:
        raise ValueError("release-set cardinalities do not prove one-element extension")

    checks = analysis.get("checks") or {}
    if set(checks) != set(analysis.get("gate", {}).get("required_checks") or []):
        raise ValueError("v2 projection check set drifted")
    if not all(checks.values()):
        raise ValueError("one or more v2 projection checks failed")
    gate = analysis.get("gate") or {}
    if gate.get("status") != "artifact_version_projection_allowed_development_only":
        raise ValueError("unexpected v2 projection gate status")
    if gate.get("passed") is not True or gate.get("failed_checks") != []:
        raise ValueError("v2 projection gate did not pass cleanly")
    if gate.get("development_typing_candidate") != "incomplete":
        raise ValueError("v2 development typing candidate drifted")
    if gate.get("label_is_human") is not False:
        raise ValueError("v2 gate cannot claim a human label")


def validate_manifest(manifest: dict, manifest_path: Path) -> dict:
    if manifest.get("schema_version") != audit.SCHEMA_VERSION:
        raise ValueError("unexpected v2 projection manifest schema version")
    if manifest.get("artifact_type") != audit.ARTIFACT_TYPE:
        raise ValueError("unexpected v2 projection manifest artifact type")
    if manifest.get("label_is_human") is not False:
        raise ValueError("v2 projection manifest must remain non-human")
    if manifest.get("post_unsealing_conditional_analysis") is not True:
        raise ValueError("v2 projection manifest lost post-unsealing boundary")
    if len(manifest.get("evidence_cache") or {}) != 2 * len(audit.EVIDENCE_SOURCES):
        raise ValueError("unexpected v2 evidence cache file count")
    for section in ("inputs", "evidence_cache", "outputs"):
        for name, item in manifest.get(section, {}).items():
            path = Path(item["path"])
            if not path.is_file() or calibration.sha256(path) != item["sha256"]:
                raise ValueError(f"v2 projection hash mismatch for {section}.{name}")
    analysis_path = Path(manifest["outputs"]["analysis"]["path"])
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    validate_analysis(analysis)
    if manifest.get("gate") != analysis.get("gate"):
        raise ValueError("v2 manifest and analysis gates differ")
    if manifest_path.name != "manifest.json":
        raise ValueError("unexpected v2 projection manifest filename")
    return analysis


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    manifest_path = base_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    analysis = validate_manifest(manifest, manifest_path)
    print(f"Verified {manifest_path}")
    print(f"Gate: {analysis['gate']['status']}")
    print("Boundary: verified post-unsealing non-human candidate; no gold label.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
