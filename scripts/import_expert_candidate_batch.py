#!/usr/bin/env python3
"""Import reviewed AI candidate decisions into the isolated candidate JSONL."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LABELS = {
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
}
SOURCES = {"nvd", "ghsa", "both", "neither", "abstain"}
VERSION_REASONING = {
    "token_support",
    "range_semantic",
    "package_identity",
    "insufficient_evidence",
    "not_applicable",
}
CONFIDENCE = {"high", "medium", "low"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--pass-id", required=True)
    parser.add_argument(
        "--annotator-id",
        default="codex_security_expert:dual_agent_review_with_main_contract_check_v2",
    )
    parser.add_argument("--schedule", default="targeted_evidence_review")
    parser.add_argument(
        "--prompt-path", default="docs/prompts/expert_candidate_annotation_prompt.md"
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            rows.append(row)
    if not rows:
        raise ValueError(f"No rows in {path}")
    return rows


def index_unique(rows: list[dict], key: str, path: Path) -> dict[str, dict]:
    indexed = {}
    for row in rows:
        value = row.get(key)
        if not value:
            raise ValueError(f"{path}: row missing {key}")
        if value in indexed:
            raise ValueError(f"{path}: duplicate {key}={value}")
        indexed[value] = row
    return indexed


def validate_decision(decision: dict, evidence: dict) -> None:
    sample_id = decision["sample_id"]
    if decision.get("cve_id") != evidence.get("cve_id"):
        raise ValueError(f"{sample_id}: cve_id does not match evidence")
    if decision.get("field") != evidence.get("field"):
        raise ValueError(f"{sample_id}: field does not match evidence")
    required_text = (
        "discrepancy_label",
        "adjudicated_source",
        "rationale",
        "evidence_notes",
        "version_reasoning_type",
        "confidence",
    )
    for key in required_text:
        if not decision.get(key):
            raise ValueError(f"{sample_id}: missing {key}")
    if not isinstance(decision.get("needs_human_review"), bool):
        raise ValueError(f"{sample_id}: needs_human_review must be boolean")
    enum_checks = (
        ("discrepancy_label", LABELS),
        ("adjudicated_source", SOURCES),
        ("version_reasoning_type", VERSION_REASONING),
        ("confidence", CONFIDENCE),
    )
    for key, allowed in enum_checks:
        if decision[key] not in allowed:
            raise ValueError(f"{sample_id}: invalid {key}={decision[key]!r}")
    adjudicated_value = decision.get("adjudicated_value")
    if not isinstance(adjudicated_value, str):
        raise ValueError(f"{sample_id}: adjudicated_value must be a string")
    if not isinstance(decision.get("uncertainty_notes"), str):
        raise ValueError(f"{sample_id}: uncertainty_notes must be a string")
    if decision["adjudicated_source"] == "abstain" and adjudicated_value:
        raise ValueError(f"{sample_id}: abstain requires an empty adjudicated_value")
    if decision["adjudicated_source"] != "abstain" and not adjudicated_value:
        raise ValueError(
            f"{sample_id}: non-abstain source requires adjudicated_value"
        )
    if (
        decision["discrepancy_label"] == "uncertain"
        or decision["confidence"] == "low"
    ) and not decision["needs_human_review"]:
        raise ValueError(
            f"{sample_id}: uncertain/low-confidence decisions require human review"
        )
    urls = decision.get("evidence_urls")
    if not isinstance(urls, list) or not urls:
        raise ValueError(f"{sample_id}: evidence_urls must be non-empty")
    if any(not isinstance(url, str) or not url for url in urls):
        raise ValueError(f"{sample_id}: evidence_urls must contain non-empty strings")
    if len(urls) != len(set(urls)):
        raise ValueError(f"{sample_id}: evidence_urls must not contain duplicates")
    evidence_records = {
        record.get("url"): record
        for record in evidence["evidence_context"]["records"]
    }
    unknown = sorted(set(urls) - set(evidence_records))
    if unknown:
        raise ValueError(f"{sample_id}: untraceable evidence URLs: {unknown}")
    unavailable = sorted(
        url for url in urls if evidence_records[url].get("fetch_status") != "ok"
    )
    if unavailable:
        raise ValueError(f"{sample_id}: evidence URLs were not fetched: {unavailable}")
    empty_body = sorted(
        url
        for url in urls
        if not str(evidence_records[url].get("text_snippet") or "").strip()
    )
    if empty_body:
        raise ValueError(f"{sample_id}: evidence URLs have empty bodies: {empty_body}")


def main() -> int:
    args = parse_args()
    decisions_path = resolve(args.decisions)
    evidence_path = resolve(args.evidence)
    output_path = resolve(args.output)

    decisions = load_jsonl(decisions_path)
    evidence_rows = index_unique(load_jsonl(evidence_path), "sample_id", evidence_path)
    existing_rows = load_jsonl(output_path) if output_path.exists() else []
    existing_ids = {row["sample_id"] for row in existing_rows}

    wrappers = []
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for decision in decisions:
        sample_id = decision.get("sample_id")
        if not sample_id:
            raise ValueError(f"{decisions_path}: decision missing sample_id")
        if sample_id in existing_ids:
            raise ValueError(f"{sample_id}: already present in {output_path}")
        evidence = evidence_rows.get(sample_id)
        if evidence is None:
            raise ValueError(f"{sample_id}: missing source evidence")
        validate_decision(decision, evidence)
        wrappers.append(
            {
                "schema_version": "expert_candidate_v1",
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
                "input_path": str(evidence_path.relative_to(PROJECT_ROOT)),
                "sample_id": sample_id,
                "original_sample_id": None,
                "baseline_status": evidence["baseline_status"],
                "contract_normalizations": [],
                "review_provenance": {
                    "review_type": "dual_codex_agent_evidence_review",
                    "independent_human_review": False,
                    "author_signoff": False,
                },
                "annotation": decision,
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
