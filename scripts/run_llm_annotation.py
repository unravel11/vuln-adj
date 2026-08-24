#!/usr/bin/env python3
"""Run LLM-assisted draft annotation for Phase D samples."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROMPT = "docs/prompts/phase_d_llm_annotation_prompt.md"
DEFAULT_OUTPUT_DIR = "data/annotations/phase_d/llm_drafts"
DEFAULT_MODEL = "gpt-5.4-mini"

ANNOTATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "sample_id": {"type": "string"},
        "cve_id": {"type": "string"},
        "field": {
            "type": "string",
            "enum": ["severity", "affected_versions", "published", "references", "cwe_ids"],
        },
        "llm_label": {
            "type": "string",
            "enum": [
                "equivalent",
                "representation_discrepancy",
                "incomplete",
                "temporal_discrepancy",
                "factual_conflict",
                "uncertain",
            ],
        },
        "is_baseline_false_positive": {
            "type": "string",
            "enum": ["yes", "no", "uncertain"],
        },
        "adjudicated_source": {
            "type": "string",
            "enum": ["nvd", "ghsa", "both", "neither", "abstain"],
        },
        "adjudicated_value": {"type": "string"},
        "evidence_urls": {
            "type": "array",
            "items": {"type": "string"},
        },
        "evidence_notes": {"type": "string"},
        "uncertainty_notes": {"type": "string"},
        "confidence": {
            "type": "string",
            "enum": ["low", "medium", "high"],
        },
    },
    "required": [
        "sample_id",
        "cve_id",
        "field",
        "llm_label",
        "is_baseline_false_positive",
        "adjudicated_source",
        "adjudicated_value",
        "evidence_urls",
        "evidence_notes",
        "uncertainty_notes",
        "confidence",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Call OpenAI Responses API to draft Phase D annotations."
    )
    parser.add_argument("input_path", help="Sample JSONL file to annotate.")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for LLM draft JSONL outputs.",
    )
    parser.add_argument(
        "--prompt-path",
        default=DEFAULT_PROMPT,
        help="Prompt markdown file.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", DEFAULT_MODEL),
        help="OpenAI model ID.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of rows to annotate.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.0,
        help="Delay between API calls.",
    )
    parser.add_argument(
        "--use-fallback",
        action="store_true",
        help="Use OPENAI_FALLBACK_API_KEY and OPENAI_FALLBACK_BASE_URL from .env.",
    )
    parser.add_argument(
        "--api",
        choices=["responses", "chat"],
        default="responses",
        help="API surface to use. Use chat for OpenAI-compatible gateways without Responses API support.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip sample_ids already present in the output JSONL.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum attempts per sample.",
    )
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def iter_jsonl(path: Path, limit: int | None = None) -> Iterable[dict]:
    count = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            yield json.loads(line)
            count += 1
            if limit is not None and count >= limit:
                break


def build_model_input(row: dict) -> dict:
    model_input = {
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "baseline_status": row["baseline_status"],
        "baseline_note": row["baseline_note"],
        "nvd_value": row["nvd_value"],
        "ghsa_value": row["ghsa_value"],
        "nvd_context": row["nvd_context"],
        "ghsa_context": row["ghsa_context"],
    }
    if "evidence_context" in row:
        model_input["evidence_context"] = row["evidence_context"]
    return model_input


def is_valid_annotation(record: dict) -> bool:
    annotation = record.get("llm_annotation")
    if not isinstance(annotation, dict):
        return False
    return all(key in annotation for key in ANNOTATION_SCHEMA["required"])


def read_completed_sample_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    sample_ids = set()
    valid_records: list[dict] = []
    invalid_count = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if is_valid_annotation(record):
                sample_ids.add(record["sample_id"])
                valid_records.append(record)
            else:
                invalid_count += 1
    if invalid_count:
        backup_path = path.with_suffix(path.suffix + ".invalid_backup")
        path.replace(backup_path)
        with path.open("w", encoding="utf-8") as handle:
            for record in valid_records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(
            f"Filtered {invalid_count} invalid existing annotation rows to {backup_path}; "
            f"kept {len(valid_records)} valid rows."
        )
    return sample_ids


def extract_output_text(response) -> str:
    if isinstance(response, str):
        return response
    output_text = getattr(response, "output_text", None)
    if output_text:
        return output_text
    if hasattr(response, "output") and isinstance(response.output, str):
        return response.output
    data = response.model_dump()
    texts = []
    for item in data.get("output", []):
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                texts.append(content.get("text", ""))
    if texts:
        return "".join(texts)
    raise ValueError("Could not extract output text from response")


def extract_sse_output_text(raw_output: str) -> str:
    if not raw_output.lstrip().startswith("event:"):
        return raw_output

    deltas: list[str] = []
    failed = False
    error_messages: list[str] = []
    for line in raw_output.splitlines():
        if not line.startswith("data: "):
            continue
        payload = line.removeprefix("data: ").strip()
        if not payload:
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        event_type = event.get("type")
        if event_type == "response.output_text.delta":
            deltas.append(event.get("delta", ""))
        elif event_type in {"error", "response.failed"}:
            failed = True
            error = event.get("error") or (event.get("response") or {}).get("error") or {}
            message = error.get("message") if isinstance(error, dict) else None
            if message:
                error_messages.append(message)

    if deltas:
        return "".join(deltas)
    if failed:
        detail = "; ".join(error_messages) if error_messages else "remote SSE response failed"
        raise RuntimeError(detail)
    raise RuntimeError("Remote model API returned SSE without output text")


def create_annotation(client, args: argparse.Namespace, prompt: str, model_input: dict):
    serialized_input = json.dumps(model_input, ensure_ascii=False)
    if args.api == "chat":
        response = client.chat.completions.create(
            model=args.model,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": serialized_input},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "phase_d_llm_annotation",
                    "strict": True,
                    "schema": ANNOTATION_SCHEMA,
                },
            },
        )
        if isinstance(response, str):
            return response
        return response.choices[0].message.content or ""

    response = client.responses.create(
        model=args.model,
        instructions=prompt,
        input=serialized_input,
        text={
            "format": {
                "type": "json_schema",
                "name": "phase_d_llm_annotation",
                "strict": True,
                "schema": ANNOTATION_SCHEMA,
            }
        },
    )
    return extract_output_text(response)


def create_annotation_with_retries(client, args: argparse.Namespace, prompt: str, model_input: dict) -> str:
    last_error: Exception | None = None
    for attempt in range(1, args.max_retries + 1):
        try:
            raw_output = extract_sse_output_text(create_annotation(client, args, prompt, model_input))
            if raw_output.lstrip().startswith("<!doctype html") or raw_output.lstrip().startswith("<html"):
                raise RuntimeError("Remote model API returned HTML instead of JSON")
            return raw_output
        except Exception as exc:  # API gateways can fail transiently.
            last_error = exc
            if attempt >= args.max_retries:
                break
            time.sleep(min(2 ** attempt, 20))
    assert last_error is not None
    raise last_error


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    args = parse_args()
    if args.use_fallback:
        fallback_key = os.environ.get("OPENAI_FALLBACK_API_KEY")
        fallback_base_url = os.environ.get("OPENAI_FALLBACK_BASE_URL")
        if not fallback_key or not fallback_base_url:
            raise RuntimeError("Fallback API key or base URL is not set")
        os.environ["OPENAI_API_KEY"] = fallback_key
        os.environ["OPENAI_BASE_URL"] = fallback_base_url
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set")

    from openai import OpenAI

    input_path = resolve_path(args.input_path)
    output_dir = resolve_path(args.output_dir)
    prompt_path = resolve_path(args.prompt_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not prompt_path.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_path}")

    prompt = prompt_path.read_text(encoding="utf-8")
    output_path = output_dir / f"{input_path.stem}.llm_draft.jsonl"
    request_log_path = output_dir / f"{input_path.stem}.requests.jsonl"
    client = OpenAI()

    completed_sample_ids = read_completed_sample_ids(output_path) if args.resume else set()
    output_mode = "a" if args.resume else "w"

    with output_path.open(output_mode, encoding="utf-8") as output_handle, request_log_path.open(
        output_mode, encoding="utf-8"
    ) as request_handle:
        for row in iter_jsonl(input_path, args.limit):
            if row["sample_id"] in completed_sample_ids:
                continue
            model_input = build_model_input(row)
            request_record = {
                "sample_id": row["sample_id"],
                "model": args.model,
                "prompt_path": str(prompt_path),
                "input": model_input,
            }
            request_handle.write(json.dumps(request_record, ensure_ascii=False) + "\n")

            raw_output = create_annotation_with_retries(client, args, prompt, model_input)
            try:
                parsed = json.loads(raw_output)
            except json.JSONDecodeError as exc:
                debug_path = output_dir / f"{input_path.stem}.last_bad_output.txt"
                debug_path.write_text(raw_output, encoding="utf-8")
                raise ValueError(f"Model output was not valid JSON. Saved to {debug_path}") from exc
            candidate_record = {"llm_annotation": parsed}
            if not is_valid_annotation(candidate_record):
                debug_path = output_dir / f"{input_path.stem}.last_bad_output.txt"
                debug_path.write_text(raw_output, encoding="utf-8")
                missing = sorted(set(ANNOTATION_SCHEMA["required"]) - set(parsed))
                raise ValueError(
                    "Model output did not match required annotation schema "
                    f"(missing={missing}). Saved to {debug_path}"
                )
            output_record = {
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "field": row["field"],
                "model": args.model,
                "prompt_path": str(prompt_path),
                "llm_annotation": parsed,
            }
            output_handle.write(json.dumps(output_record, ensure_ascii=False) + "\n")
            output_handle.flush()

            if args.sleep_seconds:
                time.sleep(args.sleep_seconds)

    print(f"LLM draft annotations: {output_path}")
    print(f"Request log:           {request_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
