#!/usr/bin/env python3
"""Fail-closed validation for the reference-normalization human review packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = (
    "data/annotations/rq2/reference_normalization_impact_human_review"
)
DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_human_review"
)
SCHEMA_VERSION = "rq2_reference_normalization_human_review_v1"
EXPECTED_ROWS = 56
IDENTITY_DEFINITIONS = {
    "underlying_content_resource",
    "frozen_http_resource",
    "other_explicit_definition",
}
IDENTITY_DEFINITION_TEXT = {
    "underlying_content_resource": (
        "Treat URLs as the same resource when repository/revision/path or "
        "equivalent identifiers establish the same underlying content, even "
        "if one literal URL is malformed or does not resolve."
    ),
    "frozen_http_resource": (
        "Treat URLs as the same resource only when the supplied frozen HTTP "
        "probes establish the same final resource or matching content."
    ),
    "other_explicit_definition": (
        "Use another definition only when it is written explicitly in "
        "custom_identity_definition."
    ),
}
IDENTITY_VERDICTS = {
    "all_aliases_same_resource",
    "one_or_more_not_same",
    "insufficient",
}
FINAL_STATUSES = {
    "incomplete",
    "representation_discrepancy",
    "uncertain",
}
CONFIDENCE = {"high", "medium", "low"}
STATUS_MAPPING = {
    "all_aliases_same_resource": "incomplete",
    "one_or_more_not_same": "representation_discrepancy",
    "insufficient": "uncertain",
}
SOURCE_BOUND_KEYS = (
    "review_id",
    "cve_id",
    "field",
    "identity_groups",
    "review_contract",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--require-signed", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def parse_time(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def empty_decision() -> dict:
    return {
        "human_id": "",
        "identity_definition": "",
        "custom_identity_definition": "",
        "identity_verdict": "",
        "final_status": "",
        "confidence": "",
        "rationale": "",
        "group_decisions": [],
        "reviewed_at": "",
    }


def empty_human_review() -> dict:
    return {
        "review_status": "pending",
        "annotator": empty_decision(),
        "independent_reviewer": empty_decision(),
        "resolution": {
            "final_identity_definition": "",
            "custom_identity_definition": "",
            "final_identity_verdict": "",
            "final_status": "",
            "group_decisions": [],
            "resolution_rationale": "",
            "author_id": "",
            "author_signoff": "pending",
            "signed_at": "",
        },
        "exclusion_reason": "",
    }


def expected_priority(source: dict) -> tuple[str, str]:
    definition_sensitive = any(
        "%23l" in str(member.get("url") or "").lower()
        for group in source.get("identity_groups", [])
        for member in group.get("members", [])
    )
    if definition_sensitive:
        return (
            "definition_sensitive",
            "encoded_line_resource_definition_sensitive",
        )
    return "full_impact_confirmation", "complete_impact_set_confirmation"


def validate_identity_definition(
    sample_id: str,
    role: str,
    identity_definition: object,
    custom_definition: object,
) -> list[str]:
    errors = []
    if identity_definition not in IDENTITY_DEFINITIONS:
        errors.append(f"{sample_id}: invalid {role}.identity_definition")
    custom = str(custom_definition or "").strip()
    if identity_definition == "other_explicit_definition" and len(custom) < 40:
        errors.append(
            f"{sample_id}: {role}.custom_identity_definition must contain at least 40 characters"
        )
    elif identity_definition != "other_explicit_definition" and custom:
        errors.append(
            f"{sample_id}: {role}.custom_identity_definition must be blank for a predefined definition"
        )
    return errors


def validate_group_decisions(
    sample_id: str,
    role: str,
    decisions: object,
    source_groups: list[dict],
    verdict: object,
) -> list[str]:
    errors = []
    if not isinstance(decisions, list):
        return [f"{sample_id}: {role}.group_decisions must be a list"]
    expected_ids = [group["group_id"] for group in source_groups]
    actual_ids = [item.get("group_id") for item in decisions if isinstance(item, dict)]
    if len(actual_ids) != len(decisions) or actual_ids != expected_ids:
        errors.append(
            f"{sample_id}: {role}.group_decisions must match source group IDs and order"
        )
        return errors
    values = []
    for item in decisions:
        value = item.get("same_resource")
        values.append(value)
        if value is not True and value is not False and value is not None:
            errors.append(f"{sample_id}: invalid {role}.same_resource value")
        if len(str(item.get("reason") or "").strip()) < 20:
            errors.append(
                f"{sample_id}: every {role} group reason must contain at least 20 characters"
            )
    if verdict == "all_aliases_same_resource" and not all(value is True for value in values):
        errors.append(f"{sample_id}: {role} all-aliases verdict requires all groups true")
    elif verdict == "one_or_more_not_same" and False not in values:
        errors.append(f"{sample_id}: {role} not-same verdict requires a false group")
    elif verdict == "insufficient" and None not in values:
        errors.append(f"{sample_id}: {role} insufficient verdict requires a null group")
    return errors


def validate_decision(
    sample_id: str,
    role: str,
    decision: dict,
    source_groups: list[dict],
) -> list[str]:
    errors = []
    if not str(decision.get("human_id") or "").strip():
        errors.append(f"{sample_id}: {role}.human_id is required")
    errors.extend(
        validate_identity_definition(
            sample_id,
            role,
            decision.get("identity_definition"),
            decision.get("custom_identity_definition"),
        )
    )
    verdict = decision.get("identity_verdict")
    status = decision.get("final_status")
    if verdict not in IDENTITY_VERDICTS:
        errors.append(f"{sample_id}: invalid {role}.identity_verdict")
    if status not in FINAL_STATUSES:
        errors.append(f"{sample_id}: invalid {role}.final_status")
    elif verdict in STATUS_MAPPING and status != STATUS_MAPPING[verdict]:
        errors.append(f"{sample_id}: {role} verdict-to-status mapping is inconsistent")
    if decision.get("confidence") not in CONFIDENCE:
        errors.append(f"{sample_id}: invalid {role}.confidence")
    if len(str(decision.get("rationale") or "").strip()) < 80:
        errors.append(f"{sample_id}: {role}.rationale must contain at least 80 characters")
    errors.extend(
        validate_group_decisions(
            sample_id,
            role,
            decision.get("group_decisions"),
            source_groups,
            verdict,
        )
    )
    if not parse_time(decision.get("reviewed_at")):
        errors.append(f"{sample_id}: {role}.reviewed_at must be ISO date/time")
    return errors


def validate_resolution(
    sample_id: str,
    resolution: dict,
    source_groups: list[dict],
) -> list[str]:
    errors = validate_identity_definition(
        sample_id,
        "resolution",
        resolution.get("final_identity_definition"),
        resolution.get("custom_identity_definition"),
    )
    verdict = resolution.get("final_identity_verdict")
    status = resolution.get("final_status")
    if verdict not in IDENTITY_VERDICTS:
        errors.append(f"{sample_id}: invalid resolution.final_identity_verdict")
    if status not in FINAL_STATUSES:
        errors.append(f"{sample_id}: invalid resolution.final_status")
    elif verdict in STATUS_MAPPING and status != STATUS_MAPPING[verdict]:
        errors.append(f"{sample_id}: resolution verdict-to-status mapping is inconsistent")
    errors.extend(
        validate_group_decisions(
            sample_id,
            "resolution",
            resolution.get("group_decisions"),
            source_groups,
            verdict,
        )
    )
    if len(str(resolution.get("resolution_rationale") or "").strip()) < 40:
        errors.append(f"{sample_id}: resolution_rationale must contain at least 40 characters")
    if not str(resolution.get("author_id") or "").strip():
        errors.append(f"{sample_id}: resolution.author_id is required")
    if resolution.get("author_signoff") != "signed":
        errors.append(f"{sample_id}: author_signoff must be signed")
    if not parse_time(resolution.get("signed_at")):
        errors.append(f"{sample_id}: resolution.signed_at must be ISO date/time")
    return errors


def validate_row(row: dict, source: dict) -> list[str]:
    sample_id = str(row.get("review_id") or "<missing>")
    errors = []
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{sample_id}: invalid schema_version")
    if row.get("artifact_type") != "rq2_reference_normalization_human_review_packet":
        errors.append(f"{sample_id}: invalid artifact_type")
    if row.get("label_is_human") is not False:
        errors.append(f"{sample_id}: packet label_is_human must remain false")
    if row.get("eligible_for_human_gold_claim") is not False:
        errors.append(
            f"{sample_id}: packet eligible_for_human_gold_claim must remain false"
        )
    for key in SOURCE_BOUND_KEYS:
        if row.get(key) != source.get(key):
            errors.append(f"{sample_id}: source identity/value drift for {key}")
    priority_tier, priority_reason = expected_priority(source)
    if row.get("priority_tier") != priority_tier:
        errors.append(f"{sample_id}: priority_tier drift")
    if row.get("priority_reason") != priority_reason:
        errors.append(f"{sample_id}: priority_reason drift")
    review = row.get("human_review")
    if not isinstance(review, dict):
        return [*errors, f"{sample_id}: missing human_review"]
    status = review.get("review_status")
    if status not in {"pending", "final", "excluded"}:
        errors.append(f"{sample_id}: invalid review_status")
        return errors
    if status == "pending":
        if review != empty_human_review():
            errors.append(f"{sample_id}: pending row must not contain review content")
        return errors
    resolution = review.get("resolution") or {}
    if status == "excluded":
        if len(str(review.get("exclusion_reason") or "").strip()) < 40:
            errors.append(f"{sample_id}: exclusion_reason must contain at least 40 characters")
        if review.get("annotator") != empty_decision():
            errors.append(f"{sample_id}: excluded row annotator content must remain blank")
        if review.get("independent_reviewer") != empty_decision():
            errors.append(f"{sample_id}: excluded row reviewer content must remain blank")
        permitted_resolution = {
            **empty_human_review()["resolution"],
            "author_id": resolution.get("author_id"),
            "author_signoff": resolution.get("author_signoff"),
            "signed_at": resolution.get("signed_at"),
        }
        if resolution != permitted_resolution:
            errors.append(f"{sample_id}: excluded row must not contain final decisions")
        if resolution.get("author_signoff") != "signed":
            errors.append(f"{sample_id}: excluded row requires signed author resolution")
        if not str(resolution.get("author_id") or "").strip():
            errors.append(f"{sample_id}: excluded row requires author_id")
        if not parse_time(resolution.get("signed_at")):
            errors.append(f"{sample_id}: excluded row requires signed_at")
        return errors

    source_groups = source.get("identity_groups") or []
    annotator = review.get("annotator") or {}
    reviewer = review.get("independent_reviewer") or {}
    errors.extend(validate_decision(sample_id, "annotator", annotator, source_groups))
    errors.extend(
        validate_decision(
            sample_id,
            "independent_reviewer",
            reviewer,
            source_groups,
        )
    )
    annotator_id = str(annotator.get("human_id") or "").strip()
    reviewer_id = str(reviewer.get("human_id") or "").strip()
    if annotator_id and reviewer_id and annotator_id == reviewer_id:
        errors.append(f"{sample_id}: independent reviewer must differ from annotator")
    errors.extend(validate_resolution(sample_id, resolution, source_groups))
    if str(review.get("exclusion_reason") or "").strip():
        errors.append(f"{sample_id}: final row exclusion_reason must be blank")
    return errors


def validate_manifest(manifest: dict, input_dir: Path) -> tuple[Path, Path]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid human packet manifest schema_version")
    if manifest.get("row_count") != EXPECTED_ROWS:
        raise ValueError("human packet manifest row count is not 56")
    if manifest.get("label_is_human") is not False:
        raise ValueError("human packet manifest label_is_human must remain false")
    if manifest.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("human packet manifest cannot claim human-gold eligibility")
    if manifest.get("source_review_protocol_revision") != 2:
        raise ValueError("human packet must bind reference review protocol revision 2")
    if manifest.get("identity_definitions") != IDENTITY_DEFINITION_TEXT:
        raise ValueError("human packet identity-definition contract drift")
    if manifest.get("status_mapping") != STATUS_MAPPING:
        raise ValueError("human packet verdict-to-status contract drift")
    source_seal = Path(manifest["source_seal"])
    source_worklist = Path(manifest["source_worklist"])
    packet_path = Path(manifest["jsonl_path"])
    if sha256(source_seal) != manifest.get("source_seal_sha256"):
        raise ValueError("source seal hash mismatch")
    if sha256(source_worklist) != manifest.get("source_worklist_sha256"):
        raise ValueError("source worklist hash mismatch")
    seal = json.loads(source_seal.read_text(encoding="utf-8"))
    sealed_worklist = seal["outputs"]["secondary_worklist"]
    if seal.get("review_protocol_revision") != 2:
        raise ValueError("source seal protocol revision drift")
    if Path(sealed_worklist["path"]) != source_worklist:
        raise ValueError("manifest worklist path differs from source seal")
    if sealed_worklist["sha256"] != manifest["source_worklist_sha256"]:
        raise ValueError("manifest worklist hash differs from source seal")
    if packet_path.parent != input_dir:
        raise ValueError("packet JSONL is outside the declared input directory")
    if packet_path.name != "reference_normalization_impact_human_review.jsonl":
        raise ValueError("unexpected human packet JSONL filename")
    return source_worklist, packet_path


def render_markdown(metrics: dict) -> str:
    return "\n".join(
        [
            "# Reference Normalization Human Review Readiness",
            "",
            f"- Rows: `{metrics['rows']}`",
            f"- Definition-sensitive rows: `{metrics['definition_sensitive_rows']}`",
            f"- Signed final rows: `{metrics['signed_final_rows']}`",
            f"- Excluded rows: `{metrics['excluded_rows']}`",
            f"- Pending rows: `{metrics['pending_rows']}`",
            f"- Validation errors: `{metrics['validation_error_count']}`",
            f"- Complete: `{str(metrics['complete']).lower()}`",
            "",
            "No packet row is canonical human gold until the three-stage gate passes.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    input_dir = resolve(args.input_dir)
    output_dir = resolve(args.output_dir)
    manifest = json.loads((input_dir / "manifest.json").read_text(encoding="utf-8"))
    source_path, packet_path = validate_manifest(manifest, input_dir)
    source_rows = list(iter_jsonl(source_path))
    packet_rows = list(iter_jsonl(packet_path))
    if len(source_rows) != EXPECTED_ROWS or len(packet_rows) != EXPECTED_ROWS:
        raise ValueError("expected 56 source and packet rows")
    source_ids = [row.get("review_id") for row in source_rows]
    packet_ids = [row.get("review_id") for row in packet_rows]
    if source_ids != packet_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source and packet review IDs must be unique and ordered identically")

    errors = []
    signed = excluded = pending = 0
    for row, source in zip(packet_rows, source_rows):
        row_errors = validate_row(row, source)
        errors.extend(row_errors)
        status = (row.get("human_review") or {}).get("review_status")
        if status == "final" and not row_errors:
            signed += 1
        elif status == "excluded" and not row_errors:
            excluded += 1
        else:
            pending += 1
    complete = signed + excluded == EXPECTED_ROWS and not errors
    status_counts = Counter(
        (row.get("human_review") or {}).get("review_status") for row in packet_rows
    )
    metrics = {
        "artifact_type": "rq2_reference_normalization_human_review_readiness",
        "packet_label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "rows": len(packet_rows),
        "definition_sensitive_rows": sum(
            row.get("priority_tier") == "definition_sensitive" for row in packet_rows
        ),
        "signed_final_rows": signed,
        "excluded_rows": excluded,
        "pending_rows": pending,
        "validation_error_count": len(errors),
        "complete": complete,
        "status_counts": dict(sorted(status_counts.items())),
        "errors": errors[:100],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "reference_normalization_human_review_readiness.json"
    md_path = output_dir / "reference_normalization_human_review_readiness.md"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    if errors or (args.require_signed and signed == 0) or (
        args.require_complete and not complete
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
