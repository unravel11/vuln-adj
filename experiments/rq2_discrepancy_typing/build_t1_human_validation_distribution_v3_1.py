#!/usr/bin/env python3
"""Build reviewer-scoped V3.1 calibration-1 action bundles after governance clears."""

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
DEFAULT_APPROVAL_RECORD = (
    "data/annotations/rq2/"
    "t1_human_validation_v3_1_distribution_r1/approval_record.json"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/rq2/"
    "t1_human_validation_v3_1_distribution_r1/generated"
)
DEFAULT_REPORT = (
    "data/annotations/rq2/"
    "t1_human_validation_v3_1_distribution_r1/readiness_report.json"
)
FROZEN_TAG = "jss-t1-human-validation-v3.1-preparation-freeze-20260825"
FROZEN_COMMIT = "e98dff344473fcc906b80d59b64cb0d6324558e0"
FROZEN_MANIFEST_SHA256 = (
    "5833698444c9bf835cd82a6706326a91988804a14e24af4d6ee3ba29b433e893"
)
FROZEN_GUIDELINE_SHA256 = (
    "a5dcf70d52f8e7124af1e2328fade4b5024696dc5911a74401988fb6d4efbb6c"
)
REVISION_ID = "t1-v3.1-calibration-1-action-r1"
APPROVAL_SCHEMA = "t1_v31_distribution_approval_v1"
READINESS_SCHEMA = "t1_v31_distribution_readiness_v1"
BUNDLE_SCHEMA = "t1_v31_distribution_bundle_v1"
REVIEWERS = ("reviewer_a", "reviewer_b")
EXPECTED_ROLE = "doctoral_student_trained_analyst"
EXPECTED_PHASE = "calibration_1"
EXPECTED_STAGE = "action"
EXPECTED_CASES = 20
PRIVATE_HASH_RE = set("0123456789abcdef")

TOP_LEVEL_APPROVAL_KEYS = {
    "schema_version",
    "protocol_id",
    "revision_id",
    "frozen_preparation",
    "scope",
    "role_design",
    "guideline_approval",
    "reviewer_governance",
    "ethics_recruitment",
    "author_distribution_approval",
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
ROLE_DESIGN_KEYS = {
    "reviewer_count",
    "role_category",
    "practitioner_expertise_claimed",
    "source_statement",
}
GUIDELINE_KEYS = {
    "source_path",
    "sha256",
    "approved",
    "approval_basis",
    "approved_by",
    "approved_at",
    "signature_recorded",
}
REVIEWER_KEYS = {
    "reviewer_id",
    "role_category",
    "practitioner_expertise_claimed",
    "real_person_identity_verified",
    "doctoral_status_verified",
    "relevant_experience_summary",
    "independence_signed",
    "conflict_disclosed",
    "compensation_disclosed",
    "consent_signed",
    "private_record_sha256",
}
ETHICS_KEYS = {
    "determination_recorded",
    "determination",
    "identifier_or_written_rationale",
    "recruitment_method",
    "information_sheet_sha256",
}
AUTHOR_KEYS = {
    "approved",
    "approved_by",
    "approved_at",
    "two_distinct_reviewers_verified",
    "scope_and_hashes_verified",
    "policy_output_blinding_commitment_signed",
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


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(PRIVATE_HASH_RE)
    )


def is_completed_text(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text) and "pending" not in text.lower()


def exact_keys(value: Any, expected: set[str], label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected object")
        return False
    if set(value) != expected:
        errors.append(f"{label}: keys do not equal the frozen allowlist")
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
        expected = {
            "tag": FROZEN_TAG,
            "commit": FROZEN_COMMIT,
            "manifest_path": f"{DEFAULT_PACKET_DIR}/manifest.json",
            "manifest_sha256": FROZEN_MANIFEST_SHA256,
        }
        if frozen != expected:
            errors.append("frozen_preparation: authority or manifest hash mismatch")

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
                "scope: only both reviewers' calibration-1 action CSV is allowed"
            )

    role_design = approval["role_design"]
    if exact_keys(role_design, ROLE_DESIGN_KEYS, "role_design", errors):
        if role_design.get("reviewer_count") != 2:
            errors.append("role_design: exactly two reviewers are required")
        if role_design.get("role_category") != EXPECTED_ROLE:
            errors.append("role_design: reviewers must be doctoral trained analysts")
        if role_design.get("practitioner_expertise_claimed") is not False:
            errors.append("role_design: practitioner expertise may not be claimed")
        if not str(role_design.get("source_statement", "")).strip():
            errors.append("role_design: source statement is required")

    guideline = approval["guideline_approval"]
    if exact_keys(guideline, GUIDELINE_KEYS, "guideline_approval", errors):
        if guideline.get("source_path") != (
            "docs/annotation_guidelines/t1_action_reason_v3_1.md"
        ):
            errors.append("guideline_approval: source path mismatch")
        if guideline.get("sha256") != FROZEN_GUIDELINE_SHA256:
            errors.append("guideline_approval: hash mismatch")
        if guideline.get("approved") is not True:
            errors.append("guideline_approval: author approval is missing")
        for key in ("approval_basis", "approved_by", "approved_at"):
            if not is_completed_text(guideline.get(key)):
                errors.append(f"guideline_approval: {key} is required")
        if guideline.get("signature_recorded") is not True:
            errors.append("guideline_approval: named-author signature is not recorded")

    governance = approval["reviewer_governance"]
    if not isinstance(governance, dict) or set(governance) != set(REVIEWERS):
        errors.append("reviewer_governance: exact reviewer A/B records are required")
    else:
        reviewer_ids: list[str] = []
        for reviewer in REVIEWERS:
            record = governance[reviewer]
            label = f"reviewer_governance.{reviewer}"
            if not exact_keys(record, REVIEWER_KEYS, label, errors):
                continue
            reviewer_id = str(record.get("reviewer_id", "")).strip()
            reviewer_ids.append(reviewer_id)
            if not reviewer_id:
                errors.append(f"{label}: reviewer_id is required")
            if record.get("role_category") != EXPECTED_ROLE:
                errors.append(f"{label}: role category mismatch")
            if record.get("practitioner_expertise_claimed") is not False:
                errors.append(f"{label}: practitioner expertise may not be claimed")
            for key in (
                "real_person_identity_verified",
                "doctoral_status_verified",
                "independence_signed",
                "conflict_disclosed",
                "compensation_disclosed",
                "consent_signed",
            ):
                if record.get(key) is not True:
                    errors.append(f"{label}: {key} is not complete")
            experience = record.get("relevant_experience_summary")
            if not is_completed_text(experience):
                errors.append(f"{label}: relevant experience is not recorded")
            if not is_sha256(record.get("private_record_sha256")):
                errors.append(f"{label}: private signed-record hash is missing")
        if len(reviewer_ids) == 2 and (
            not all(reviewer_ids) or reviewer_ids[0] == reviewer_ids[1]
        ):
            errors.append("reviewer_governance: reviewer IDs must be distinct")

    ethics = approval["ethics_recruitment"]
    if exact_keys(ethics, ETHICS_KEYS, "ethics_recruitment", errors):
        if ethics.get("determination_recorded") is not True:
            errors.append("ethics_recruitment: determination is not recorded")
        if ethics.get("determination") not in {
            "approved",
            "exempt",
            "not_required_with_recorded_rationale",
            "other_institutional_determination",
        }:
            errors.append("ethics_recruitment: determination value is unresolved")
        for key in ("identifier_or_written_rationale", "recruitment_method"):
            if not is_completed_text(ethics.get(key)):
                errors.append(f"ethics_recruitment: {key} is required")
        if not is_sha256(ethics.get("information_sheet_sha256")):
            errors.append("ethics_recruitment: information-sheet hash is missing")

    author = approval["author_distribution_approval"]
    if exact_keys(author, AUTHOR_KEYS, "author_distribution_approval", errors):
        if author.get("approved") is not True:
            errors.append("author_distribution_approval: approval is missing")
        for key in ("approved_by", "approved_at"):
            if not is_completed_text(author.get(key)):
                errors.append(f"author_distribution_approval: {key} is required")
        for key in (
            "two_distinct_reviewers_verified",
            "scope_and_hashes_verified",
            "policy_output_blinding_commitment_signed",
        ):
            if author.get(key) is not True:
                errors.append(f"author_distribution_approval: {key} is not complete")

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
                errors.append(
                    "frozen preparation manifest must remain distribution-blocked"
                )
            if (
                manifest.get("human_labels") != 0
                or manifest.get("human_gold") is not False
            ):
                errors.append("frozen preparation manifest overstates human evidence")

    guideline_path = (
        PROJECT_ROOT / "docs/annotation_guidelines/t1_action_reason_v3_1.md"
    )
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

Scope: 20 calibration cases, maintenance action only.

1. Read `GUIDELINE.md` before opening the CSV.
2. Work independently, using only the supplied cells and context.
3. Do not browse live sources, use AI/model assistance, or consult another reviewer.
4. Fill only `action_label`, `action_rationale`, `action_uncertainty`, and
   `reviewer_notes`. Do not change row order or any other cell.
5. Use exactly one allowed action label per row. `abstain` is a completed answer.
6. Return the completed CSV to the author. Do not request or open a reason packet.

This is calibration, not a correctness test and not formal endpoint data.
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
    guideline_source_path = PROJECT_ROOT / approval["guideline_approval"]["source_path"]
    guideline_text = render_distributed_guideline(
        guideline_source_path.read_text(encoding="utf-8")
    )
    output_dir.mkdir(parents=True)
    for reviewer in REVIEWERS:
        reviewer_id = approval["reviewer_governance"][reviewer]["reviewer_id"]
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


def readiness_report(approval: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    return {
        "schema_version": READINESS_SCHEMA,
        "protocol_id": packet_builder.PROTOCOL_ID,
        "revision_id": REVISION_ID,
        "status": "READY" if not errors else "BLOCKED",
        "distribution_allowed": not errors,
        "bundle_created": False,
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
    report = readiness_report(approval, errors)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(report_path, report)
    if errors:
        print(f"BLOCKED: {len(errors)} distribution-readiness requirement(s) remain")
        for error in errors:
            print(f"- {error}")
        return 2
    if args.check_only:
        print("READY: governance and frozen inputs permit bundle construction")
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
