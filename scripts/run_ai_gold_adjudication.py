#!/usr/bin/env python3
"""Run a resumable second-pass adjudication over risky AI candidate rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from run_expert_candidate_annotation import BATCH_SCHEMA
from run_expert_candidate_annotation import build_model_input
from run_expert_candidate_annotation import call_with_retries
from run_expert_candidate_annotation import chunks
from run_expert_candidate_annotation import load_dotenv
from run_expert_candidate_annotation import validate_batch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "ai_gold_adjudication_v1"
DEFAULT_PROMPT = "docs/prompts/ai_gold_adjudication_prompt.md"
DEFAULT_MODEL = "gpt-5.5"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-input", required=True)
    parser.add_argument("--candidate-input", required=True)
    parser.add_argument("--comparison-input", action="append", default=[])
    parser.add_argument("--task-kind", choices=("rq2", "rq3"), required=True)
    parser.add_argument("--pass-id", required=True)
    parser.add_argument("--output-path", required=True)
    parser.add_argument("--request-log-path")
    parser.add_argument("--prompt-path", default=DEFAULT_PROMPT)
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
    parser.add_argument("--api", choices=("chat", "responses"), default="chat")
    parser.add_argument(
        "--use-fallback",
        action="store_true",
        help="Use OPENAI_FALLBACK_API_KEY/OPENAI_FALLBACK_BASE_URL from .env.",
    )
    parser.add_argument("--batch-size", type=int, default=3)
    parser.add_argument("--max-retries", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--max-evidence-records", type=int, default=12)
    parser.add_argument("--max-evidence-chars", type=int, default=5000)
    parser.add_argument("--max-output-tokens", type=int, default=3000)
    parser.add_argument("--max-new-rows", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--all", action="store_true", help="Adjudicate every candidate row.")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument(
        "--worklist-output",
        help="Write selected model inputs as JSONL without changing their content.",
    )
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
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
            yield row


def load_unique(path: Path, key_fn) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        key = key_fn(row)
        if not key:
            raise ValueError(f"{path}: row has no identity key")
        if key in rows:
            raise ValueError(f"{path}: duplicate identity {key}")
        rows[key] = row
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_id(row: dict) -> str:
    return str(row.get("sample_id") or row.get("review_sample_id") or "")


def candidate_id(row: dict) -> str:
    return str(row.get("sample_id") or "")


def comparison_id(row: dict) -> str:
    return str(row.get("original_sample_id") or row.get("sample_id") or "")


def annotation_from(row: dict) -> dict | None:
    for key in ("annotation", "llm_annotation", "silver_v2_annotation"):
        value = row.get(key)
        if isinstance(value, dict):
            return value
    if (
        row.get("sample_id")
        and row.get("discrepancy_label")
        and row.get("adjudicated_source")
    ):
        return row
    return None


def normalized(value: object) -> str:
    return str(value or "").strip().lower()


def risk_reasons(candidate: dict, comparisons: list[dict], *, all_rows: bool) -> list[str]:
    if all_rows:
        return ["full_second_pass"]
    reasons = []
    annotation = annotation_from(candidate) or {}
    if annotation.get("needs_human_review") is True:
        reasons.append("candidate_requests_review")
    if normalized(annotation.get("discrepancy_label")) == "uncertain":
        reasons.append("candidate_label_uncertain")
    if normalized(annotation.get("confidence")) == "low":
        reasons.append("candidate_confidence_low")
    if (
        normalized(candidate.get("baseline_status"))
        and normalized(candidate.get("baseline_status"))
        != normalized(annotation.get("discrepancy_label"))
    ):
        reasons.append("candidate_baseline_disagreement")
    for comparison in comparisons:
        other = annotation_from(comparison)
        if not other:
            continue
        if (
            normalized(other.get("discrepancy_label") or other.get("llm_label"))
            and normalized(other.get("discrepancy_label") or other.get("llm_label"))
            != normalized(annotation.get("discrepancy_label"))
        ):
            reasons.append("comparison_label_disagreement")
        if (
            normalized(other.get("adjudicated_source"))
            and normalized(other.get("adjudicated_source"))
            != normalized(annotation.get("adjudicated_source"))
        ):
            reasons.append("comparison_source_disagreement")
    return sorted(set(reasons))


def compact_prior(row: dict) -> dict:
    annotation = annotation_from(row)
    return {
        "schema_version": row.get("schema_version"),
        "annotator_type": row.get("annotator_type"),
        "annotator_id": row.get("annotator_id"),
        "model": row.get("model"),
        "pass_id": row.get("pass_id"),
        "label_is_human": row.get("label_is_human", False),
        "annotation": annotation,
    }


def read_completed(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        str(row["sample_id"])
        for row in iter_jsonl(path)
        if row.get("schema_version") == SCHEMA_VERSION and row.get("sample_id")
    }


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    args = parse_args()
    if args.batch_size < 1 or args.max_retries < 1 or args.max_output_tokens < 1:
        raise ValueError("batch-size, max-retries, and max-output-tokens must be positive")
    if args.max_new_rows is not None and args.max_new_rows < 0:
        raise ValueError("max-new-rows must be non-negative")
    if args.use_fallback:
        fallback_key = os.environ.get("OPENAI_FALLBACK_API_KEY")
        fallback_base_url = os.environ.get("OPENAI_FALLBACK_BASE_URL")
        if not fallback_key or not fallback_base_url:
            raise RuntimeError("Fallback API key or base URL is not set")
        os.environ["OPENAI_API_KEY"] = fallback_key
        os.environ["OPENAI_BASE_URL"] = fallback_base_url
        args.model = os.environ.get("OPENAI_FALLBACK_MODEL", args.model)

    source_path = resolve(args.source_input)
    candidate_path = resolve(args.candidate_input)
    comparison_paths = [resolve(value) for value in args.comparison_input]
    output_path = resolve(args.output_path)
    prompt_path = resolve(args.prompt_path)
    request_path = resolve(
        args.request_log_path or str(output_path.with_suffix(".requests.jsonl"))
    )

    sources = load_unique(source_path, source_id)
    candidates = load_unique(candidate_path, candidate_id)
    if set(sources) != set(candidates):
        missing = sorted(set(sources) - set(candidates))
        extra = sorted(set(candidates) - set(sources))
        raise ValueError(f"source/candidate identity mismatch: missing={missing[:5]} extra={extra[:5]}")

    comparisons_by_id: dict[str, list[dict]] = {key: [] for key in sources}
    comparison_hashes = {}
    for path in comparison_paths:
        comparison_hashes[str(path)] = sha256(path)
        for row in iter_jsonl(path):
            key = comparison_id(row)
            if key in comparisons_by_id:
                comparisons_by_id[key].append(row)

    selected = []
    reason_counts = Counter()
    for sample_id in sorted(sources):
        reasons = risk_reasons(
            candidates[sample_id], comparisons_by_id[sample_id], all_rows=args.all
        )
        if reasons:
            selected.append((sample_id, reasons))
            reason_counts.update(reasons)

    completed = read_completed(output_path) if args.resume else set()
    selected = [(sample_id, reasons) for sample_id, reasons in selected if sample_id not in completed]
    if args.max_new_rows is not None:
        selected = selected[: args.max_new_rows]

    plan = {
        "schema_version": SCHEMA_VERSION,
        "source_rows": len(sources),
        "selected_rows_total_before_resume": sum(
            1
            for sample_id in sources
            if risk_reasons(candidates[sample_id], comparisons_by_id[sample_id], all_rows=args.all)
        ),
        "completed_rows": len(completed),
        "scheduled_rows": len(selected),
        "risk_reason_counts": dict(sorted(reason_counts.items())),
        "preview": [
            {"sample_id": sample_id, "reasons": reasons}
            for sample_id, reasons in selected[:20]
        ],
    }
    if args.worklist_output:
        worklist_path = resolve(args.worklist_output)
        worklist_path.parent.mkdir(parents=True, exist_ok=True)
        with worklist_path.open("w", encoding="utf-8") as handle:
            for sample_id, reasons in selected:
                item = build_model_input(
                    sources[sample_id],
                    task_kind=args.task_kind,
                    max_evidence_records=args.max_evidence_records,
                    max_evidence_chars=args.max_evidence_chars,
                )
                item["candidate_to_review"] = compact_prior(candidates[sample_id])
                item["comparison_passes"] = [
                    compact_prior(row) for row in comparisons_by_id[sample_id]
                ]
                item["selection_reasons"] = reasons
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
        plan["worklist_output"] = str(worklist_path)
        plan["worklist_sha256"] = sha256(worklist_path)
    if args.plan_only:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("OPENAI_BASE_URL"):
        raise RuntimeError("OPENAI_API_KEY and OPENAI_BASE_URL are required")

    from openai import OpenAI

    prompt = prompt_path.read_text(encoding="utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    request_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if args.resume else "w"
    client = OpenAI(timeout=args.timeout_seconds, max_retries=0)
    candidate_hash = sha256(candidate_path)
    source_hash = sha256(source_path)
    processed = 0

    with output_path.open(mode, encoding="utf-8") as output_handle, request_path.open(
        mode, encoding="utf-8"
    ) as request_handle:
        for selected_batch in chunks(selected, args.batch_size):
            model_batch = []
            reasons_by_id = {}
            for sample_id, reasons in selected_batch:
                item = build_model_input(
                    sources[sample_id],
                    task_kind=args.task_kind,
                    max_evidence_records=args.max_evidence_records,
                    max_evidence_chars=args.max_evidence_chars,
                )
                item["candidate_to_review"] = compact_prior(candidates[sample_id])
                item["comparison_passes"] = [
                    compact_prior(row) for row in comparisons_by_id[sample_id]
                ]
                item["selection_reasons"] = reasons
                model_batch.append(item)
                reasons_by_id[sample_id] = reasons

            request_handle.write(
                json.dumps(
                    {
                        "event_type": "request",
                        "schema_version": SCHEMA_VERSION,
                        "pass_id": args.pass_id,
                        "model": args.model,
                        "api_route": "fallback" if args.use_fallback else "primary",
                        "prompt_path": str(prompt_path),
                        "items": model_batch,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            request_handle.flush()
            raw = call_with_retries(client, args, prompt, model_batch)
            parsed = json.loads(raw)
            annotations = validate_batch(model_batch, parsed)
            completed_at = datetime.now(timezone.utc).isoformat()
            request_handle.write(
                json.dumps(
                    {
                        "event_type": "response_success",
                        "schema_version": SCHEMA_VERSION,
                        "pass_id": args.pass_id,
                        "sample_ids": [row["sample_id"] for row in annotations],
                        "completed_at": completed_at,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            request_handle.flush()
            for annotation in annotations:
                sample_id = annotation["sample_id"]
                contract_normalizations = annotation.pop("_contract_normalizations", [])
                record = {
                    "schema_version": SCHEMA_VERSION,
                    "adjudication_status": (
                        "final_abstain"
                        if annotation["discrepancy_label"] == "uncertain"
                        or annotation["adjudicated_source"] == "abstain"
                        and args.task_kind == "rq3"
                        else "final_determinate"
                    ),
                    "label_is_human": False,
                    "eligible_for_human_gold_claim": False,
                    "adjudicator_type": "ai_security_expert",
                    "adjudicator_id": f"codex_ai_gold_adjudicator:{args.model}:{args.pass_id}",
                    "model": args.model,
                    "api_route": "fallback" if args.use_fallback else "primary",
                    "pass_id": args.pass_id,
                    "generated_at": completed_at,
                    "prompt_path": str(prompt_path),
                    "source_input_path": str(source_path),
                    "source_input_sha256": source_hash,
                    "candidate_input_path": str(candidate_path),
                    "candidate_input_sha256": candidate_hash,
                    "comparison_input_sha256": comparison_hashes,
                    "same_model_family_review": True,
                    "independent_human_review": False,
                    "sample_id": sample_id,
                    "cve_id": annotation["cve_id"],
                    "field": annotation["field"],
                    "selection_reasons": reasons_by_id[sample_id],
                    "contract_normalizations": contract_normalizations,
                    "prior_candidate": compact_prior(candidates[sample_id]),
                    "annotation": annotation,
                }
                output_handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            output_handle.flush()
            processed += len(selected_batch)
            print(f"Progress [{args.pass_id}]: {processed}/{len(selected)}", flush=True)
            if args.sleep_seconds:
                time.sleep(args.sleep_seconds)

    print(json.dumps(plan, ensure_ascii=False, indent=2))
    print(f"Adjudication output: {output_path}")
    print("Boundary: label_is_human=false; this is AI-adjudicated gold only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
