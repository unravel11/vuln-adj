#!/usr/bin/env python3
"""Build compact evidence views for canonical token prediction disagreements."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from affected_versions_semantic_baseline import parse_version
from evaluate_affected_versions_silver_v2 import (
    VERSION_CANDIDATE_RE,
    extract_version_tokens,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_SILVER = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_EFFECT = "results/rq3_adjudication/canonical_version_token_effect.json"
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"
RAW_METHOD = "version_token_support_baseline"
CANONICAL_METHOD = "canonical_version_token_support_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--silver", default=DEFAULT_SILVER)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--effect", default=DEFAULT_EFFECT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_by_sample(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate sample_id in {path}: {sample_id}")
        rows[sample_id] = row
    return rows


def load_predictions(path: Path) -> dict[tuple[str, str], dict]:
    rows = {}
    for row in iter_jsonl(path):
        if row.get("method") not in {RAW_METHOD, CANONICAL_METHOD}:
            continue
        key = (row["sample_id"], row["method"])
        if key in rows:
            raise ValueError(f"Duplicate prediction in {path}: {key}")
        rows[key] = row
    return rows


def token_versions(row: dict) -> set:
    tokens = extract_version_tokens(row.get("nvd_value") or [])
    tokens |= extract_version_tokens(row.get("ghsa_value") or [])
    return {version for token in tokens if (version := parse_version(token)) is not None}


def compact_contexts(row: dict) -> list[dict]:
    versions = token_versions(row)
    contexts = []
    seen = set()
    for record in (row.get("evidence_context") or {}).get("records", []):
        if record.get("fetch_status") != "ok":
            continue
        text = " ".join(
            part for part in (record.get("title"), record.get("text_snippet")) if part
        )
        for match in VERSION_CANDIDATE_RE.finditer(text):
            candidate = match.group(0)
            if parse_version(candidate.rstrip(".,;:")) not in versions:
                continue
            start = max(0, match.start() - 180)
            end = min(len(text), match.end() + 280)
            context = " ".join(text[start:end].split())
            key = (record.get("url"), context)
            if key in seen:
                continue
            seen.add(key)
            contexts.append(
                {
                    "url": record.get("url"),
                    "matched_text": candidate,
                    "context": context,
                }
            )
            if len(contexts) >= 12:
                return contexts
    return contexts


def render_markdown(rows: list[dict]) -> str:
    lines = [
        "# Canonical Version-Token Disagreement Review",
        "",
        "These rows are selected because raw and canonical token predictions differ. They are not a representative sample and silver labels are not human gold.",
        "",
        "| Sample | CVE | Silver | Raw | Canonical | Package names |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        packages = "; ".join(
            [
                "NVD=" + ",".join(row["nvd_package_names"]),
                "GHSA=" + ",".join(row["ghsa_package_names"]),
            ]
        )
        lines.append(
            f"| {row['sample_id']} | {row['cve_id']} | {row['target_source']} | "
            f"{row['raw_prediction']} | {row['canonical_prediction']} | {packages} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    evidence_path = resolve_path(args.evidence)
    silver_path = resolve_path(args.silver)
    predictions_path = resolve_path(args.predictions)
    effect_path = resolve_path(args.effect)
    output_dir = resolve_path(args.output_dir)

    evidence = load_by_sample(evidence_path)
    silver = load_by_sample(silver_path)
    predictions = load_predictions(predictions_path)
    effect = json.loads(effect_path.read_text(encoding="utf-8"))
    changed = effect["datasets"]["silver_v2"]["token"]["changed_cases"]
    rows = []
    for change in changed:
        sample_id = change["sample_id"]
        source = evidence[sample_id]
        raw = predictions[(sample_id, RAW_METHOD)]
        canonical = predictions[(sample_id, CANONICAL_METHOD)]
        rows.append(
            {
                **change,
                "field": "affected_versions",
                "nvd_value": source.get("nvd_value"),
                "ghsa_value": source.get("ghsa_value"),
                "nvd_package_names": source.get("nvd_context", {}).get(
                    "package_names", []
                ),
                "ghsa_package_names": source.get("ghsa_context", {}).get(
                    "package_names", []
                ),
                "raw_support": raw.get("prediction_detail", {}).get("support"),
                "canonical_support": canonical.get("prediction_detail", {}).get(
                    "support"
                ),
                "silver_annotation": silver[sample_id].get("llm_annotation"),
                "evidence_contexts": compact_contexts(source),
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "canonical_version_token_disagreement_review.jsonl"
    md_path = output_dir / "canonical_version_token_disagreement_review.md"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    md_path.write_text(render_markdown(rows), encoding="utf-8")
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {md_path}")
    print(f"Rows: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
