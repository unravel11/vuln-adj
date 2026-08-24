#!/usr/bin/env python3
"""Import reviewed RQ2 typing decisions into an isolated candidate JSONL."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from run_expert_candidate_annotation import (
    LABELS,
    PROJECT_ROOT,
    SCHEMA_VERSION,
    VERSION_REASONING,
    allowed_evidence_urls,
    build_model_input,
    iter_jsonl,
    source_sample_id,
    validate_batch,
)


CONFIDENCE = {"high", "medium", "low"}
FIELDS = {"severity", "published", "references", "affected_versions", "cwe_ids"}
AFFECTED_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
}
REQUIRED_KEYS = {
    "sample_id",
    "cve_id",
    "field",
    "discrepancy_label",
    "adjudicated_source",
    "adjudicated_value",
    "evidence_urls",
    "rationale",
    "evidence_notes",
    "uncertainty_notes",
    "version_reasoning_type",
    "confidence",
    "needs_human_review",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--pass-id", required=True)
    parser.add_argument(
        "--annotator-id",
        default="codex_security_expert:multi_agent_rq2_main_review_v1",
    )
    parser.add_argument("--schedule", default="field_partitioned_review")
    parser.add_argument(
        "--prompt-path", default="docs/prompts/expert_candidate_annotation_prompt.md"
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_jsonl(path: Path) -> list[dict]:
    rows = list(iter_jsonl(path))
    if not rows:
        raise ValueError(f"No rows in {path}")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{path}: every row must be an object")
    return rows


def index_unique(rows: list[dict], key_fn, path: Path) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for row in rows:
        key = key_fn(row)
        if key in indexed:
            raise ValueError(f"{path}: duplicate sample_id={key}")
        indexed[key] = row
    return indexed


def validate_decision_shape(decision: dict, model_input: dict) -> None:
    sample_id = decision.get("sample_id")
    missing = sorted(REQUIRED_KEYS - set(decision))
    extra = sorted(set(decision) - REQUIRED_KEYS)
    if missing or extra:
        raise ValueError(f"{sample_id}: missing={missing}, extra={extra}")
    if decision.get("cve_id") != model_input.get("cve_id"):
        raise ValueError(f"{sample_id}: cve_id does not match source")
    if decision.get("field") != model_input.get("field"):
        raise ValueError(f"{sample_id}: field does not match source")
    if decision["field"] not in FIELDS:
        raise ValueError(f"{sample_id}: invalid field={decision['field']!r}")
    if decision["discrepancy_label"] not in LABELS:
        raise ValueError(
            f"{sample_id}: invalid discrepancy_label={decision['discrepancy_label']!r}"
        )
    if decision["adjudicated_source"] != "abstain":
        raise ValueError(f"{sample_id}: RQ2 decisions must use source=abstain")
    if decision["adjudicated_value"] != "":
        raise ValueError(f"{sample_id}: RQ2 decisions must use an empty value")
    if decision["version_reasoning_type"] not in VERSION_REASONING:
        raise ValueError(
            f"{sample_id}: invalid version_reasoning_type="
            f"{decision['version_reasoning_type']!r}"
        )
    if decision["field"] == "affected_versions":
        if decision["version_reasoning_type"] not in AFFECTED_REASONING:
            raise ValueError(
                f"{sample_id}: affected_versions requires an affected reasoning type"
            )
    elif decision["version_reasoning_type"] != "not_applicable":
        raise ValueError(f"{sample_id}: non-version fields require not_applicable")
    if decision["confidence"] not in CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid confidence={decision['confidence']!r}")
    if not isinstance(decision["needs_human_review"], bool):
        raise ValueError(f"{sample_id}: needs_human_review must be boolean")
    if (
        decision["discrepancy_label"] == "uncertain"
        or decision["confidence"] == "low"
    ) and not decision["needs_human_review"]:
        raise ValueError(f"{sample_id}: uncertain/low decisions require review")
    if not isinstance(decision["rationale"], str) or not decision["rationale"].strip():
        raise ValueError(f"{sample_id}: rationale must be a non-empty string")
    for key in ("evidence_notes", "uncertainty_notes"):
        if not isinstance(decision[key], str):
            raise ValueError(f"{sample_id}: {key} must be a string")
    urls = decision["evidence_urls"]
    if not isinstance(urls, list):
        raise ValueError(f"{sample_id}: evidence_urls must be a list")
    if any(not isinstance(url, str) or not url for url in urls):
        raise ValueError(f"{sample_id}: evidence URLs must be non-empty strings")
    if len(urls) != len(set(urls)):
        raise ValueError(f"{sample_id}: evidence URLs must be unique")
    unknown = sorted(set(urls) - allowed_evidence_urls(model_input))
    if unknown:
        raise ValueError(f"{sample_id}: untraceable evidence URLs: {unknown}")


def main() -> int:
    args = parse_args()
    decisions_path = resolve(args.decisions)
    source_path = resolve(args.source)
    output_path = resolve(args.output)

    decisions = load_jsonl(decisions_path)
    source_rows = load_jsonl(source_path)
    source_by_id = index_unique(source_rows, source_sample_id, source_path)
    decision_by_id = index_unique(
        decisions, lambda row: str(row.get("sample_id") or ""), decisions_path
    )
    if "" in decision_by_id:
        raise ValueError(f"{decisions_path}: decision missing sample_id")

    existing_rows = load_jsonl(output_path) if output_path.exists() else []
    existing_ids = {str(row.get("sample_id")) for row in existing_rows}
    duplicates = sorted(set(decision_by_id) & existing_ids)
    if duplicates:
        raise ValueError(f"Already present in {output_path}: {duplicates[:5]}")

    selected_sources: list[dict] = []
    model_inputs: list[dict] = []
    for sample_id, decision in decision_by_id.items():
        source_row = source_by_id.get(sample_id)
        if source_row is None:
            raise ValueError(f"{sample_id}: missing source row")
        model_input = build_model_input(
            source_row,
            task_kind="rq2",
            max_evidence_records=0,
            max_evidence_chars=0,
        )
        validate_decision_shape(decision, model_input)
        selected_sources.append(source_row)
        model_inputs.append(model_input)

    normalized = validate_batch(
        model_inputs,
        {"annotations": list(decision_by_id.values())},
    )
    selected_by_id = {source_sample_id(row): row for row in selected_sources}
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    wrappers = []
    for annotation in normalized:
        sample_id = annotation["sample_id"]
        source_row = selected_by_id[sample_id]
        contract_normalizations = annotation.pop("_contract_normalizations", [])
        wrappers.append(
            {
                "schema_version": SCHEMA_VERSION,
                "candidate_status": "unreviewed",
                "label_is_human": False,
                "annotator_type": "ai_security_expert",
                "annotator_id": args.annotator_id,
                "model": "codex_current_session",
                "api_route": "interactive_codex",
                "schedule": args.schedule,
                "pass_id": args.pass_id,
                "generated_at": generated_at,
                "prompt_path": args.prompt_path,
                "input_path": str(source_path.relative_to(PROJECT_ROOT)),
                "sample_id": sample_id,
                "original_sample_id": source_row.get("original_sample_id"),
                "baseline_status": source_row.get("baseline_status"),
                "contract_normalizations": contract_normalizations,
                "review_provenance": {
                    "review_type": "multi_codex_agent_field_partitioned_review",
                    "independent_human_review": False,
                    "author_signoff": False,
                },
                "annotation": annotation,
            }
        )

    print(
        json.dumps(
            {
                "decision_rows": len(decisions),
                "existing_rows": len(existing_rows),
                "result_rows": len(existing_rows) + len(wrappers),
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )
    if args.dry_run:
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for wrapper in wrappers:
            handle.write(json.dumps(wrapper, ensure_ascii=True, separators=(",", ":")))
            handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
