#!/usr/bin/env python3
"""Fail-closed validation for V3.1 calibration-1 action distribution bundles."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import build_t1_human_validation_distribution_v3_1 as distribution
import build_t1_human_validation_packet_v3_1 as packet_builder
import validate_t1_human_validation_packet_v3_1 as packet_validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FILES = {
    "GUIDELINE.md",
    "INSTRUCTIONS.md",
    "calibration_1_action_packet.csv",
    "manifest.json",
}
BUNDLE_MANIFEST_KEYS = {
    "schema_version",
    "protocol_id",
    "revision_id",
    "status",
    "distribution_allowed",
    "reviewer",
    "reviewer_id",
    "phase",
    "stage",
    "case_count",
    "human_labels_at_build",
    "human_gold",
    "frozen_preparation",
    "approval_record_sha256",
    "source_files",
    "distributed_files",
    "explicitly_excluded",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=distribution.DEFAULT_PACKET_DIR)
    parser.add_argument(
        "--approval-record", default=distribution.DEFAULT_APPROVAL_RECORD
    )
    parser.add_argument("--bundle-root", default=distribution.DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def validate_reviewer_bundle(
    bundle_root: Path,
    packet_dir: Path,
    approval_path: Path,
    approval: dict[str, Any],
    reviewer: str,
) -> list[str]:
    errors: list[str] = []
    reviewer_dir = bundle_root / reviewer
    if not reviewer_dir.is_dir():
        return [f"{reviewer}: bundle directory is missing"]
    actual_files = {
        str(path.relative_to(reviewer_dir))
        for path in reviewer_dir.rglob("*")
        if path.is_file()
    }
    if actual_files != EXPECTED_FILES:
        errors.append(
            f"{reviewer}: file set is not action-only allowlist; "
            f"observed={sorted(actual_files)}"
        )
        return errors

    manifest_path = reviewer_dir / "manifest.json"
    try:
        manifest = load_json(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"{reviewer}: {exc}"]
    if set(manifest) != BUNDLE_MANIFEST_KEYS:
        errors.append(f"{reviewer}: manifest keys do not equal allowlist")
        return errors
    expected_scalars = {
        "schema_version": distribution.BUNDLE_SCHEMA,
        "protocol_id": packet_builder.PROTOCOL_ID,
        "revision_id": distribution.REVISION_ID,
        "status": "DISTRIBUTION_APPROVED_CALIBRATION_1_ACTION_ONLY",
        "distribution_allowed": True,
        "reviewer": reviewer,
        "reviewer_id": approval["reviewer_governance"][reviewer]["reviewer_id"],
        "phase": distribution.EXPECTED_PHASE,
        "stage": distribution.EXPECTED_STAGE,
        "case_count": distribution.EXPECTED_CASES,
        "human_labels_at_build": 0,
        "human_gold": False,
        "frozen_preparation": approval["frozen_preparation"],
        "approval_record_sha256": distribution.sha256_file(approval_path),
    }
    for key, expected in expected_scalars.items():
        if manifest.get(key) != expected:
            errors.append(f"{reviewer}: manifest {key} mismatch")

    expected_excluded = {
        "all reason packets",
        "calibration-2 reserve",
        "formal evaluation packets",
        "internal frames and mappings",
        "policy and AI outputs",
        "the other reviewer's packet",
    }
    if set(manifest.get("explicitly_excluded", [])) != expected_excluded:
        errors.append(f"{reviewer}: excluded-file declaration drift")

    source_csv = packet_dir / reviewer / "calibration_1_action_packet.csv"
    source_guideline = PROJECT_ROOT / approval["guideline_approval"]["source_path"]
    expected_sources = {
        distribution.relative(source_csv): distribution.sha256_file(source_csv),
        distribution.relative(source_guideline): distribution.sha256_file(
            source_guideline
        ),
    }
    if manifest.get("source_files") != expected_sources:
        errors.append(f"{reviewer}: source file hashes mismatch")
    expected_distributed = {
        name: distribution.sha256_file(reviewer_dir / name)
        for name in EXPECTED_FILES
        if name != "manifest.json"
    }
    if manifest.get("distributed_files") != expected_distributed:
        errors.append(f"{reviewer}: distributed file hashes mismatch")

    distributed_csv = reviewer_dir / "calibration_1_action_packet.csv"
    if distributed_csv.read_bytes() != source_csv.read_bytes():
        errors.append(f"{reviewer}: distributed CSV differs from frozen blank packet")
    fields, rows = read_csv(distributed_csv)
    if fields != packet_validator.expected_csv_fields("action"):
        errors.append(f"{reviewer}: CSV columns do not equal action allowlist")
    if len(rows) != distribution.EXPECTED_CASES:
        errors.append(f"{reviewer}: expected 20 calibration rows")
    for index, row in enumerate(rows, start=1):
        if row.get("phase") != distribution.EXPECTED_PHASE:
            errors.append(f"{reviewer}:{index}: phase drift")
        if row.get("stage") != distribution.EXPECTED_STAGE:
            errors.append(f"{reviewer}:{index}: stage drift")
        for key in packet_builder.ACTION_ANNOTATION:
            if row.get(key) != "":
                errors.append(f"{reviewer}:{index}: source annotation is not blank")

    expected_guideline = distribution.render_distributed_guideline(
        source_guideline.read_text(encoding="utf-8")
    )
    if (
        (reviewer_dir / "GUIDELINE.md").read_text(encoding="utf-8")
        != expected_guideline
    ):
        errors.append(f"{reviewer}: distributed guideline content drift")
    expected_instructions = distribution.render_instructions(
        approval["reviewer_governance"][reviewer]["reviewer_id"]
    )
    if (reviewer_dir / "INSTRUCTIONS.md").read_text(
        encoding="utf-8"
    ) != expected_instructions:
        errors.append(f"{reviewer}: instructions drift")

    banned_terms = (
        "baseline_status",
        "baseline_note",
        "ai_candidate",
        "deterministic_type",
        "discrepancy_type",
        "policy_actions",
        "selection_cell",
        "evaluation_weight",
    )
    for path in reviewer_dir.iterdir():
        if path.is_file() and path.suffix in {".md", ".json", ".csv"}:
            text = path.read_text(encoding="utf-8")
            for term in banned_terms:
                if term in text:
                    errors.append(f"{reviewer}: banned term {term} in {path.name}")
    return errors


def validate_bundle_root(
    packet_dir: Path, approval_path: Path, bundle_root: Path
) -> list[str]:
    try:
        errors = packet_validator.validate_packet_dir(packet_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors = [f"frozen packet validation could not run: {exc}"]
    try:
        approval = load_json(approval_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return errors + [str(exc)]
    errors.extend(distribution.validate_approval_record(approval, packet_dir))
    if not bundle_root.is_dir():
        return errors + [f"bundle root is missing: {bundle_root}"]
    actual_reviewers = {
        path.name for path in bundle_root.iterdir() if path.is_dir()
    }
    if actual_reviewers != set(distribution.REVIEWERS):
        errors.append("bundle root must contain exactly reviewer_a and reviewer_b")
    actual_root_files = [path.name for path in bundle_root.iterdir() if path.is_file()]
    if actual_root_files:
        errors.append(f"bundle root contains unexpected files: {actual_root_files}")
    for reviewer in distribution.REVIEWERS:
        errors.extend(
            validate_reviewer_bundle(
                bundle_root, packet_dir, approval_path, approval, reviewer
            )
        )
    return errors


def main() -> int:
    args = parse_args()
    errors = validate_bundle_root(
        resolve(args.packet_dir),
        resolve(args.approval_record),
        resolve(args.bundle_root),
    )
    if errors:
        print(f"FAIL: {len(errors)} distribution-bundle error(s)")
        for error in errors:
            print(f"- {error}")
        return 1
    print(
        "PASS: two reviewer-scoped calibration-1 action CSV bundles validate; "
        "all future stages and internal evidence are excluded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
