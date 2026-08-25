#!/usr/bin/env python3
"""Build minimal, reviewer-scoped V3.1 calibration-1 action bundles."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import build_t1_human_validation_packet_v3_1 as packet_builder
import validate_t1_human_validation_packet_v3_1 as packet_validator


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACKET_DIR = "data/annotations/rq2/t1_human_validation_v3_1"
DEFAULT_DISTRIBUTION_DIR = (
    "data/annotations/rq2/t1_human_validation_v3_1_distribution_r2"
)
DEFAULT_APPROVAL_RECORD = f"{DEFAULT_DISTRIBUTION_DIR}/approval_record.json"
DEFAULT_OUTPUT_DIR = f"{DEFAULT_DISTRIBUTION_DIR}/generated"
DEFAULT_REPORT = f"{DEFAULT_DISTRIBUTION_DIR}/readiness_report.json"
GUIDELINE_PATH = "docs/annotation_guidelines/t1_action_reason_v3_1.md"
FROZEN_TAG = "jss-t1-human-validation-v3.1-preparation-freeze-20260825"
FROZEN_COMMIT = "e98dff344473fcc906b80d59b64cb0d6324558e0"
FROZEN_MANIFEST_SHA256 = (
    "5833698444c9bf835cd82a6706326a91988804a14e24af4d6ee3ba29b433e893"
)
FROZEN_GUIDELINE_SHA256 = (
    "a5dcf70d52f8e7124af1e2328fade4b5024696dc5911a74401988fb6d4efbb6c"
)
REVISION_ID = "t1-v3.1-calibration-1-action-r2"
APPROVAL_SCHEMA = "t1_v31_distribution_approval_v2"
READINESS_SCHEMA = "t1_v31_distribution_readiness_v2"
BUNDLE_SCHEMA = "t1_v31_distribution_bundle_v2"
ATTESTATION_LEVEL = "AUTHOR_ATTESTED_NOT_INDEPENDENTLY_VERIFIED"
REVIEWERS = ("reviewer_a", "reviewer_b")
EXPECTED_ROLE = "doctoral_student_trained_analyst"
EXPECTED_PHASE = "calibration_1"
EXPECTED_STAGE = "action"
EXPECTED_CASES = 20

TOP_LEVEL_APPROVAL_KEYS = {
    "schema_version",
    "protocol_id",
    "revision_id",
    "frozen_preparation",
    "scope",
    "reviewers",
    "author_attestation",
    "distribution_allowed",
    "human_labels",
    "human_gold",
}
FROZEN_KEYS = {"tag", "commit", "manifest_path", "manifest_sha256"}
SCOPE_KEYS = {
    "phase",
    "stage",
    "reviewers",
    "file_format",
    "case_count_per_reviewer",
}
REVIEWER_KEYS = {"reviewer_id", "role_category"}
AUTHOR_ATTESTATION_KEYS = {
    "evidence_level",
    "attestation_basis",
    "attested_by",
    "attested_at",
    "two_distinct_real_doctoral_reviewers",
    "trained_analyst_not_practitioner",
    "independent_no_discussion_no_ai",
    "voluntary_conflict_compensation_handled",
    "institutional_ethics_requirements_handled",
    "guideline_and_action_only_scope_approved",
    "guideline_sha256",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-dir", default=DEFAULT_PACKET_DIR)
    parser.add_argument("--approval-record", default=DEFAULT_APPROVAL_RECORD)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Write readiness only; never create reviewer bundles.",
    )
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exact_keys(value: Any, expected: set[str], label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected object")
        return False
    if set(value) != expected:
        errors.append(f"{label}: keys do not equal the allowlist")
        return False
    return True


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def validate_approval_record(
    approval: dict[str, Any], packet_dir: Path
) -> list[str]:
    errors: list[str] = []
    if not exact_keys(approval, TOP_LEVEL_APPROVAL_KEYS, "approval", errors):
        return errors
    if approval["schema_version"] != APPROVAL_SCHEMA:
        errors.append("approval: schema version mismatch")
    if approval["protocol_id"] != packet_builder.PROTOCOL_ID:
        errors.append("approval: protocol ID mismatch")
    if approval["revision_id"] != REVISION_ID:
        errors.append("approval: revision ID mismatch")

    frozen = approval["frozen_preparation"]
    if exact_keys(frozen, FROZEN_KEYS, "frozen_preparation", errors):
        expected_frozen = {
            "tag": FROZEN_TAG,
            "commit": FROZEN_COMMIT,
            "manifest_path": f"{DEFAULT_PACKET_DIR}/manifest.json",
            "manifest_sha256": FROZEN_MANIFEST_SHA256,
        }
        if frozen != expected_frozen:
            errors.append("frozen_preparation: authority or hash mismatch")

    scope = approval["scope"]
    if exact_keys(scope, SCOPE_KEYS, "scope", errors):
        expected_scope = {
            "phase": EXPECTED_PHASE,
            "stage": EXPECTED_STAGE,
            "reviewers": list(REVIEWERS),
            "file_format": "csv",
            "case_count_per_reviewer": EXPECTED_CASES,
        }
        if scope != expected_scope:
            errors.append(
                "scope: only reviewer A/B calibration-1 action CSV is allowed"
            )

    reviewers = approval["reviewers"]
    if not isinstance(reviewers, dict) or set(reviewers) != set(REVIEWERS):
        errors.append("reviewers: exact reviewer A/B records are required")
    else:
        reviewer_ids: list[str] = []
        for reviewer in REVIEWERS:
            record = reviewers[reviewer]
            label = f"reviewers.{reviewer}"
            if not exact_keys(record, REVIEWER_KEYS, label, errors):
                continue
            reviewer_id = str(record.get("reviewer_id", "")).strip()
            reviewer_ids.append(reviewer_id)
            if not reviewer_id:
                errors.append(f"{label}: reviewer_id is required")
            if record.get("role_category") != EXPECTED_ROLE:
                errors.append(f"{label}: role must be doctoral trained analyst")
        if len(reviewer_ids) == 2 and (
            not all(reviewer_ids) or reviewer_ids[0] == reviewer_ids[1]
        ):
            errors.append("reviewers: reviewer IDs must be distinct")

    attestation = approval["author_attestation"]
    if exact_keys(
        attestation, AUTHOR_ATTESTATION_KEYS, "author_attestation", errors
    ):
        if attestation.get("evidence_level") != ATTESTATION_LEVEL:
            errors.append("author_attestation: evidence level mismatch")
        for key in ("attestation_basis", "attested_by", "attested_at"):
            if not str(attestation.get(key, "")).strip():
                errors.append(f"author_attestation: {key} is required")
        for key in (
            "two_distinct_real_doctoral_reviewers",
            "trained_analyst_not_practitioner",
            "independent_no_discussion_no_ai",
            "voluntary_conflict_compensation_handled",
            "institutional_ethics_requirements_handled",
            "guideline_and_action_only_scope_approved",
        ):
            if attestation.get(key) is not True:
                errors.append(f"author_attestation: {key} must be true")
        if attestation.get("guideline_sha256") != FROZEN_GUIDELINE_SHA256:
            errors.append("author_attestation: guideline hash mismatch")

    if approval["distribution_allowed"] is not True:
        errors.append("approval: distribution_allowed must be explicitly true")
    if approval["human_labels"] != 0 or approval["human_gold"] is not False:
        errors.append("approval: pre-distribution human-label boundary is invalid")

    manifest_path = packet_dir / "manifest.json"
    if not manifest_path.is_file():
        errors.append(f"missing frozen preparation manifest: {manifest_path}")
    else:
        if sha256_file(manifest_path) != FROZEN_MANIFEST_SHA256:
            errors.append("frozen preparation manifest bytes changed")
        try:
            manifest = load_json(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(str(exc))
        else:
            if manifest.get("distribution_allowed") is not False:
                errors.append("frozen preparation manifest must remain blocked")
            if (
                manifest.get("human_labels") != 0
                or manifest.get("human_gold") is not False
            ):
                errors.append("frozen preparation manifest overstates human evidence")

    guideline_path = PROJECT_ROOT / GUIDELINE_PATH
    if (
        not guideline_path.is_file()
        or sha256_file(guideline_path) != FROZEN_GUIDELINE_SHA256
    ):
        errors.append("frozen guideline bytes changed")
    return errors


def render_distributed_guideline(source: str) -> str:
    old = "Status: `DRAFT_NOT_APPROVED_FOR_DISTRIBUTION`"
    new = "Status: `APPROVED_FOR_CALIBRATION_1_ACTION_ONLY`"
    if source.count(old) != 1:
        raise ValueError("frozen guideline status marker drift")
    return source.replace(old, new, 1)


def render_instructions(reviewer_id: str) -> str:
    return f"""# Calibration-1 Action Instructions

Reviewer ID: `{reviewer_id}`

For each of the 20 rows, choose one action using only the supplied context:
`no_action`, `enrich_record`, `wait_for_sync`, `conflict_escalation`, or
`abstain`.

Fill only `action_label`, `action_rationale`, `action_uncertainty`, and
`reviewer_notes`. Do not change any other cell or row order. Work independently:
do not browse live sources, use AI/model assistance, consult the other reviewer,
or open a reason packet. `abstain` is a valid completed answer.
"""


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    if len(rows) != EXPECTED_CASES:
        raise ValueError(f"expected {EXPECTED_CASES} rows: {path}")
    for row in rows:
        if row.get("phase") != EXPECTED_PHASE or row.get("stage") != EXPECTED_STAGE:
            raise ValueError(f"phase/stage drift: {path}")
        for key in packet_builder.ACTION_ANNOTATION:
            if row.get(key) != "":
                raise ValueError(f"nonblank annotation in source packet: {path}")
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_bundles(
    approval: dict[str, Any], packet_dir: Path, output_dir: Path, approval_path: Path
) -> None:
    if output_dir.exists():
        raise FileExistsError(
            f"refusing to overwrite distribution output: {output_dir}"
        )
    guideline_source_path = PROJECT_ROOT / GUIDELINE_PATH
    guideline_text = render_distributed_guideline(
        guideline_source_path.read_text(encoding="utf-8")
    )
    output_dir.mkdir(parents=True)
    for reviewer in REVIEWERS:
        reviewer_id = approval["reviewers"][reviewer]["reviewer_id"]
        source_csv = packet_dir / reviewer / "calibration_1_action_packet.csv"
        load_csv_rows(source_csv)
        reviewer_dir = output_dir / reviewer
        reviewer_dir.mkdir()
        destination_csv = reviewer_dir / "calibration_1_action_packet.csv"
        guideline_path = reviewer_dir / "GUIDELINE.md"
        instructions_path = reviewer_dir / "INSTRUCTIONS.md"
        shutil.copyfile(source_csv, destination_csv)
        guideline_path.write_text(guideline_text, encoding="utf-8")
        instructions_path.write_text(render_instructions(reviewer_id), encoding="utf-8")
        manifest = {
            "schema_version": BUNDLE_SCHEMA,
            "protocol_id": packet_builder.PROTOCOL_ID,
            "revision_id": REVISION_ID,
            "status": "DISTRIBUTION_APPROVED_CALIBRATION_1_ACTION_ONLY",
            "distribution_allowed": True,
            "reviewer": reviewer,
            "reviewer_id": reviewer_id,
            "phase": EXPECTED_PHASE,
            "stage": EXPECTED_STAGE,
            "case_count": EXPECTED_CASES,
            "human_labels_at_build": 0,
            "human_gold": False,
            "frozen_preparation": approval["frozen_preparation"],
            "approval_record_sha256": sha256_file(approval_path),
            "source_files": {
                relative(source_csv): sha256_file(source_csv),
                relative(guideline_source_path): sha256_file(guideline_source_path),
            },
            "distributed_files": {
                "calibration_1_action_packet.csv": sha256_file(destination_csv),
                "GUIDELINE.md": sha256_file(guideline_path),
                "INSTRUCTIONS.md": sha256_file(instructions_path),
            },
            "explicitly_excluded": [
                "all reason packets",
                "calibration-2 reserve",
                "formal evaluation packets",
                "internal frames and mappings",
                "policy and AI outputs",
                "the other reviewer's packet",
            ],
        }
        write_json(reviewer_dir / "manifest.json", manifest)


def readiness_report(
    approval: dict[str, Any], errors: list[str], bundle_created: bool
) -> dict[str, Any]:
    return {
        "schema_version": READINESS_SCHEMA,
        "protocol_id": packet_builder.PROTOCOL_ID,
        "revision_id": REVISION_ID,
        "status": "READY" if not errors else "BLOCKED",
        "distribution_allowed": not errors,
        "bundle_created": bundle_created,
        "governance_evidence_level": ATTESTATION_LEVEL,
        "known_role_design": {
            "reviewer_count": 2,
            "role_category": EXPECTED_ROLE,
            "practitioner_expertise_claimed": False,
        },
        "scope": {
            "phase": EXPECTED_PHASE,
            "stage": EXPECTED_STAGE,
            "case_count_per_reviewer": EXPECTED_CASES,
        },
        "blockers": errors,
        "human_labels": approval.get("human_labels"),
        "human_gold": approval.get("human_gold"),
    }


def main() -> int:
    args = parse_args()
    packet_dir = resolve(args.packet_dir)
    approval_path = resolve(args.approval_record)
    output_dir = resolve(args.output_dir)
    report_path = resolve(args.report)
    try:
        approval = load_json(approval_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 1
    try:
        errors = packet_validator.validate_packet_dir(packet_dir)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors = [f"frozen packet validation could not run: {exc}"]
    errors.extend(validate_approval_record(approval, packet_dir))
    report = readiness_report(approval, errors, output_dir.is_dir())
    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(report_path, report)
    if errors:
        print(f"BLOCKED: {len(errors)} distribution-readiness requirement(s) remain")
        for error in errors:
            print(f"- {error}")
        return 2
    if args.check_only:
        print("READY: minimal author attestation and frozen inputs permit distribution")
        return 0
    try:
        build_bundles(approval, packet_dir, output_dir, approval_path)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1
    report["bundle_created"] = True
    write_json(report_path, report)
    print(
        "PASS: built reviewer A/B calibration-1 action-only bundles; "
        "reason, calibration-2, formal, internal, policy, and AI files excluded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
