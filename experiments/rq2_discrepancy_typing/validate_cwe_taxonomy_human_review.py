#!/usr/bin/env python3
"""Fail-closed validation for the three-stage CWE taxonomy human review packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_DIR = "data/annotations/rq2/cwe_taxonomy_impact_human_review"
DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_human_review"
)
SCHEMA_VERSION = "rq2_cwe_taxonomy_human_review_v1"
LABELS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
SOURCE_BOUND_KEYS = (
    "review_id",
    "cve_id",
    "field",
    "nvd_value",
    "ghsa_value",
    "vulnerability_context",
    "official_cwe_entries",
    "official_cross_source_ancestor_descendant_paths",
    "taxonomy_source",
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


def allowed_paths(row: dict) -> set[str]:
    paths = set()
    for relation in row["official_cross_source_ancestor_descendant_paths"]:
        path = relation["path"]
        paths.add(">".join(item["cwe_id"] for item in path))
        paths.add(">".join(item["cwe_id"] for item in reversed(path)))
    return paths


def validate_decision(
    sample_id: str,
    role: str,
    decision: dict,
    permitted_paths: set[str],
) -> list[str]:
    errors = []
    if not str(decision.get("human_id") or "").strip():
        errors.append(f"{sample_id}: {role}.human_id is required")
    if decision.get("label") not in LABELS:
        errors.append(f"{sample_id}: invalid {role}.label")
    if len(str(decision.get("rationale") or "").strip()) < 80:
        errors.append(f"{sample_id}: {role}.rationale must contain at least 80 characters")
    paths = decision.get("supporting_cwe_paths")
    if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
        errors.append(f"{sample_id}: {role}.supporting_cwe_paths must be a string list")
    elif set(paths) - permitted_paths:
        errors.append(f"{sample_id}: {role} cites an unknown CWE path")
    elif decision.get("label") == "representation_discrepancy" and not paths:
        errors.append(f"{sample_id}: representation discrepancy requires a CWE path")
    if not parse_time(decision.get("reviewed_at")):
        errors.append(f"{sample_id}: {role}.reviewed_at must be ISO date/time")
    return errors


def validate_row(row: dict, source: dict) -> list[str]:
    sample_id = str(row.get("review_id") or "<missing>")
    errors = []
    if row.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{sample_id}: invalid schema_version")
    if row.get("label_is_human") is not False:
        errors.append(f"{sample_id}: packet label_is_human must remain false")
    for key in SOURCE_BOUND_KEYS:
        if row.get(key) != source.get(key):
            errors.append(f"{sample_id}: source identity/value drift for {key}")
    review = row.get("human_review")
    if not isinstance(review, dict):
        return [*errors, f"{sample_id}: missing human_review"]
    status = review.get("review_status")
    if status not in {"pending", "final", "excluded"}:
        errors.append(f"{sample_id}: invalid review_status")
        return errors
    if status == "pending":
        if review != {
            "review_status": "pending",
            "annotator": {
                "human_id": "",
                "label": "",
                "rationale": "",
                "supporting_cwe_paths": [],
                "reviewed_at": "",
            },
            "independent_reviewer": {
                "human_id": "",
                "label": "",
                "rationale": "",
                "supporting_cwe_paths": [],
                "reviewed_at": "",
            },
            "resolution": {
                "final_label": "",
                "resolution_rationale": "",
                "author_id": "",
                "author_signoff": "pending",
                "signed_at": "",
            },
            "exclusion_reason": "",
        }:
            errors.append(f"{sample_id}: pending row must not contain review content")
        return errors
    resolution = review.get("resolution") or {}
    if status == "excluded":
        if len(str(review.get("exclusion_reason") or "").strip()) < 40:
            errors.append(f"{sample_id}: exclusion_reason must contain at least 40 characters")
        if resolution.get("author_signoff") != "signed":
            errors.append(f"{sample_id}: excluded row requires signed author resolution")
        if not str(resolution.get("author_id") or "").strip():
            errors.append(f"{sample_id}: excluded row requires author_id")
        if not parse_time(resolution.get("signed_at")):
            errors.append(f"{sample_id}: excluded row requires signed_at")
        return errors

    permitted_paths = allowed_paths(row)
    annotator = review.get("annotator") or {}
    reviewer = review.get("independent_reviewer") or {}
    errors.extend(
        validate_decision(sample_id, "annotator", annotator, permitted_paths)
    )
    errors.extend(
        validate_decision(
            sample_id, "independent_reviewer", reviewer, permitted_paths
        )
    )
    annotator_id = str(annotator.get("human_id") or "").strip()
    reviewer_id = str(reviewer.get("human_id") or "").strip()
    if annotator_id and reviewer_id and annotator_id == reviewer_id:
        errors.append(f"{sample_id}: independent reviewer must differ from annotator")
    if resolution.get("final_label") not in LABELS:
        errors.append(f"{sample_id}: invalid resolution.final_label")
    if len(str(resolution.get("resolution_rationale") or "").strip()) < 40:
        errors.append(f"{sample_id}: resolution_rationale must contain at least 40 characters")
    if not str(resolution.get("author_id") or "").strip():
        errors.append(f"{sample_id}: resolution.author_id is required")
    if resolution.get("author_signoff") != "signed":
        errors.append(f"{sample_id}: author_signoff must be signed")
    if not parse_time(resolution.get("signed_at")):
        errors.append(f"{sample_id}: resolution.signed_at must be ISO date/time")
    return errors


def render_markdown(metrics: dict) -> str:
    return "\n".join(
        [
            "# CWE Taxonomy Human Review Readiness",
            "",
            f"- Rows: `{metrics['rows']}`",
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
    source_path = Path(manifest["source_worklist"])
    if sha256(source_path) != manifest["source_worklist_sha256"]:
        raise ValueError("source worklist hash mismatch")
    packet_path = Path(manifest["jsonl_path"])
    source_rows = list(iter_jsonl(source_path))
    packet_rows = list(iter_jsonl(packet_path))
    if len(source_rows) != 17 or len(packet_rows) != 17:
        raise ValueError("expected 17 source and packet rows")
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
    complete = signed + excluded == 17 and not errors
    metrics = {
        "artifact_type": "rq2_cwe_taxonomy_human_review_readiness",
        "packet_label_is_human": False,
        "rows": len(packet_rows),
        "signed_final_rows": signed,
        "excluded_rows": excluded,
        "pending_rows": pending,
        "validation_error_count": len(errors),
        "complete": complete,
        "status_counts": dict(
            sorted(
                Counter(
                    (row.get("human_review") or {}).get("review_status")
                    for row in packet_rows
                ).items()
            )
        ),
        "errors": errors[:100],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "cwe_taxonomy_human_review_readiness.json"
    md_path = output_dir / "cwe_taxonomy_human_review_readiness.md"
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
