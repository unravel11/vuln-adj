#!/usr/bin/env python3
"""Independently verify the XWiki artifact-version projection audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import analyze_xwiki_artifact_version_projection as audit
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
        raise ValueError("unexpected analysis schema version")
    if analysis.get("label_is_human") is not False:
        raise ValueError("projection analysis must remain non-human")
    if analysis.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("projection analysis cannot claim human-gold eligibility")
    if analysis.get("sample_id") != audit.secondary.TARGET_SAMPLE_ID:
        raise ValueError("projection target sample drifted")
    if analysis.get("current_coordinate") != audit.CURRENT_COORDINATE:
        raise ValueError("current coordinate drifted")
    if analysis.get("legacy_coordinate_observed") != audit.LEGACY_COORDINATE:
        raise ValueError("legacy coordinate was not independently observed")
    catalog = analysis.get("current_release_catalog") or {}
    if catalog.get("first_release") != "3.1-milestone-1":
        raise ValueError("unexpected first release in current coordinate catalog")
    if catalog.get("ghsa_start") != "3.0-milestone-1":
        raise ValueError("GHSA lower bound drifted")
    if catalog.get("ghsa_start_present") is not False:
        raise ValueError("GHSA lower bound unexpectedly exists in current catalog")
    expected_nvd = {
        "3.0": False,
        "3.0-milestone-2": False,
        "3.0-milestone-3": False,
        "3.0-rc-1": False,
    }
    if catalog.get("nvd_explicit_present") != expected_nvd:
        raise ValueError("NVD explicit release membership drifted")
    probes = analysis.get("source_path_probe") or {}
    if probes.get("xwiki_web_3_0_milestone_1_http_status") != 404:
        raise ValueError("3.0-milestone-1 module-path probe no longer returns 404")
    if probes.get("xwiki_web_3_0_http_status") != 404:
        raise ValueError("3.0 module-path probe no longer returns 404")
    expected_failed = {
        "ghsa_lower_bound_exists_in_current_lineage",
        "nvd_explicit_versions_exist_in_current_lineage",
        "legacy_to_current_lineage_mapping_bound",
    }
    gate = analysis.get("gate") or {}
    if gate.get("status") != "abstain_artifact_version_projection_unresolved":
        raise ValueError("projection audit must fail closed")
    if gate.get("passed") is not False or gate.get("typing_disposition") != "uncertain":
        raise ValueError("projection audit disposition drifted")
    if set(gate.get("failed_checks") or []) != expected_failed:
        raise ValueError("projection failed-check set drifted")


def validate_manifest(manifest: dict, manifest_path: Path) -> dict:
    if manifest.get("schema_version") != audit.SCHEMA_VERSION:
        raise ValueError("unexpected projection manifest schema version")
    if manifest.get("artifact_type") != audit.ARTIFACT_TYPE:
        raise ValueError("unexpected projection manifest artifact type")
    if manifest.get("label_is_human") is not False:
        raise ValueError("projection manifest must remain non-human")
    for section in ("inputs", "evidence_cache", "outputs"):
        for name, item in manifest.get(section, {}).items():
            path = Path(item["path"])
            if not path.is_file() or calibration.sha256(path) != item["sha256"]:
                raise ValueError(f"projection hash mismatch for {section}.{name}")
    analysis_path = Path(manifest["outputs"]["analysis"]["path"])
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    validate_analysis(analysis)
    if manifest.get("gate") != analysis.get("gate"):
        raise ValueError("manifest and analysis gates differ")
    if manifest_path.name != "manifest.json":
        raise ValueError("unexpected projection manifest filename")
    return analysis


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    manifest_path = base_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    analysis = validate_manifest(manifest, manifest_path)
    print(f"Verified {manifest_path}")
    print(f"Gate: {analysis['gate']['status']}")
    print("Boundary: verified non-human diagnostic; no gold label.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
