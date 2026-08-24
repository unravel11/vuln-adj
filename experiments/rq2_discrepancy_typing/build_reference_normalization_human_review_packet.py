#!/usr/bin/env python3
"""Build a blank three-stage human review packet for 56 reference-impact rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VALIDATION_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/rq2/reference_normalization_impact_human_review"
)
SCHEMA_VERSION = "rq2_reference_normalization_human_review_v1"
EXPECTED_ROWS = 56
EXPECTED_PRIORITY_ROWS = 24
ENCODED_LINE_RE = re.compile(r"%23L\d+", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validation-dir", default=DEFAULT_VALIDATION_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def is_definition_sensitive(row: dict) -> bool:
    return any(
        ENCODED_LINE_RE.search(str(member.get("url") or ""))
        for group in row.get("identity_groups", [])
        for member in group.get("members", [])
    )


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


def packet_row(source: dict) -> dict:
    priority = is_definition_sensitive(source)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_reference_normalization_human_review_packet",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "review_id": source["review_id"],
        "cve_id": source["cve_id"],
        "field": source["field"],
        "priority_tier": (
            "definition_sensitive" if priority else "full_impact_confirmation"
        ),
        "priority_reason": (
            "encoded_line_resource_definition_sensitive"
            if priority
            else "complete_impact_set_confirmation"
        ),
        "identity_groups": source["identity_groups"],
        "review_contract": source["review_contract"],
        "human_review": empty_human_review(),
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = [
        "review_id",
        "cve_id",
        "priority_tier",
        "priority_reason",
        "identity_groups_json",
        "review_status",
        "annotator_human_id",
        "annotator_identity_definition",
        "annotator_identity_verdict",
        "annotator_final_status",
        "annotator_confidence",
        "annotator_rationale",
        "annotator_group_decisions_json",
        "annotator_reviewed_at",
        "reviewer_human_id",
        "reviewer_identity_definition",
        "reviewer_identity_verdict",
        "reviewer_final_status",
        "reviewer_confidence",
        "reviewer_rationale",
        "reviewer_group_decisions_json",
        "reviewer_reviewed_at",
        "final_identity_definition",
        "final_identity_verdict",
        "final_status",
        "resolution_group_decisions_json",
        "resolution_rationale",
        "author_id",
        "author_signoff",
        "signed_at",
        "exclusion_reason",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            review = row["human_review"]
            annotator = review["annotator"]
            reviewer = review["independent_reviewer"]
            resolution = review["resolution"]
            writer.writerow(
                {
                    "review_id": row["review_id"],
                    "cve_id": row["cve_id"],
                    "priority_tier": row["priority_tier"],
                    "priority_reason": row["priority_reason"],
                    "identity_groups_json": json.dumps(
                        row["identity_groups"], ensure_ascii=False
                    ),
                    "review_status": review["review_status"],
                    "annotator_human_id": annotator["human_id"],
                    "annotator_identity_definition": annotator[
                        "identity_definition"
                    ],
                    "annotator_identity_verdict": annotator["identity_verdict"],
                    "annotator_final_status": annotator["final_status"],
                    "annotator_confidence": annotator["confidence"],
                    "annotator_rationale": annotator["rationale"],
                    "annotator_group_decisions_json": json.dumps(
                        annotator["group_decisions"]
                    ),
                    "annotator_reviewed_at": annotator["reviewed_at"],
                    "reviewer_human_id": reviewer["human_id"],
                    "reviewer_identity_definition": reviewer[
                        "identity_definition"
                    ],
                    "reviewer_identity_verdict": reviewer["identity_verdict"],
                    "reviewer_final_status": reviewer["final_status"],
                    "reviewer_confidence": reviewer["confidence"],
                    "reviewer_rationale": reviewer["rationale"],
                    "reviewer_group_decisions_json": json.dumps(
                        reviewer["group_decisions"]
                    ),
                    "reviewer_reviewed_at": reviewer["reviewed_at"],
                    "final_identity_definition": resolution[
                        "final_identity_definition"
                    ],
                    "final_identity_verdict": resolution["final_identity_verdict"],
                    "final_status": resolution["final_status"],
                    "resolution_group_decisions_json": json.dumps(
                        resolution["group_decisions"]
                    ),
                    "resolution_rationale": resolution["resolution_rationale"],
                    "author_id": resolution["author_id"],
                    "author_signoff": resolution["author_signoff"],
                    "signed_at": resolution["signed_at"],
                    "exclusion_reason": review["exclusion_reason"],
                }
            )


def validate_sealed_source(seal: dict, worklist_path: Path) -> None:
    if seal.get("artifact_type") != "reference_normalization_impact_manifest":
        raise ValueError("unexpected reference impact seal artifact_type")
    if seal.get("review_protocol_revision") != 2:
        raise ValueError("human packet requires reference review protocol revision 2")
    if seal.get("reviewer_outputs_absent_at_seal") is not True:
        raise ValueError("reference worklist was not sealed before reviewer outputs")
    sealed_worklist = (seal.get("outputs") or {}).get("secondary_worklist") or {}
    if Path(sealed_worklist.get("path", "")) != worklist_path:
        raise ValueError("secondary worklist path does not match sealed manifest")
    if sha256(worklist_path) != sealed_worklist.get("sha256"):
        raise ValueError("secondary worklist does not match sealed manifest")


def main() -> int:
    args = parse_args()
    validation_dir = resolve(args.validation_dir)
    output_dir = resolve(args.output_dir)
    seal_path = validation_dir / "reference_normalization_impact_manifest.sealed.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    worklist_path = Path(seal["outputs"]["secondary_worklist"]["path"])
    validate_sealed_source(seal, worklist_path)
    source_rows = list(iter_jsonl(worklist_path))
    review_ids = [row.get("review_id") for row in source_rows]
    if len(source_rows) != EXPECTED_ROWS or len(review_ids) != len(set(review_ids)):
        raise ValueError("expected 56 unique reference impact rows")
    if any(row.get("field") != "references" for row in source_rows):
        raise ValueError("reference human packet contains a non-reference field")
    rows = [packet_row(row) for row in source_rows]
    priority_rows = sum(
        row["priority_tier"] == "definition_sensitive" for row in rows
    )
    if priority_rows != EXPECTED_PRIORITY_ROWS:
        raise ValueError("expected 24 encoded-line definition-sensitive rows")

    jsonl_path = output_dir / "reference_normalization_impact_human_review.jsonl"
    csv_path = output_dir / "reference_normalization_impact_human_review.csv"
    manifest_path = output_dir / "manifest.json"
    readme_path = output_dir / "README.md"
    existing = [
        path
        for path in (jsonl_path, csv_path, manifest_path, readme_path)
        if path.exists()
    ]
    if existing:
        raise FileExistsError(f"refusing to overwrite human review files: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    write_csv(csv_path, rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(rows),
        "priority_rows": priority_rows,
        "secondary_rows": len(rows) - priority_rows,
        "signed_human_rows": 0,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "source_review_protocol_revision": seal["review_protocol_revision"],
        "source_seal": str(seal_path),
        "source_seal_sha256": sha256(seal_path),
        "source_worklist": str(worklist_path),
        "source_worklist_sha256": sha256(worklist_path),
        "jsonl_path": str(jsonl_path),
        "csv_path": str(csv_path),
        "identity_definitions": {
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
        },
        "status_mapping": {
            "all_aliases_same_resource": "incomplete",
            "one_or_more_not_same": "representation_discrepancy",
            "insufficient": "uncertain",
        },
        "instructions": [
            "The annotator and independent reviewer must work from this sealed evidence packet; Codex decisions are not prefilled.",
            "Each human must choose and record a resource-identity definition before deciding every identity group.",
            "The independent reviewer must use a different human_id from the annotator.",
            "No row becomes canonical human gold until author_signoff=signed passes the validator; promotion is a separate step.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    readme_path.write_text(
        "# Reference Normalization Human Review Packet\n\n"
        "This is a blank three-stage packet for all 56 sealed reference-normalization impact rows. "
        "The 24 encoded-line rows are `definition_sensitive`; the other 32 rows remain in the packet for full-impact confirmation.\n\n"
        "## Required process\n\n"
        "1. A real human annotator chooses an identity definition and labels every identity group.\n"
        "2. A different real human repeats the review independently.\n"
        "3. An author resolves any difference, records the final identity definition and group decisions, and signs the row.\n\n"
        "The permitted definitions and verdict-to-status mapping are recorded in `manifest.json`; they are validator-enforced rather than hidden. "
        "Codex outputs are not copied into any human field. The packet remains `label_is_human=false`; canonical promotion is a separate guarded step.\n\n"
        "Edit the JSONL file as the authoritative review record. The CSV is a read-only convenience view and is not imported by the validator.\n",
        encoding="utf-8",
    )
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {csv_path}")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
