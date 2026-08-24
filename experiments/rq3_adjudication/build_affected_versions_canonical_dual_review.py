#!/usr/bin/env python3
"""Build a blinded worklist for dual review of canonical token matches."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/affected_versions_canonical_dual_review"
RAW_METHOD = "version_token_support_baseline"
CANONICAL_METHOD = "canonical_version_token_support_baseline"
FORBIDDEN_OUTPUT_KEYS = {
    "annotation",
    "baseline_note",
    "baseline_status",
    "candidate_source",
    "gold_adjudicated_source",
    "gold_label",
    "is_correct",
    "llm_annotation",
    "manual_label",
    "predicted_source",
    "silver_label",
    "silver_source",
    "target_source",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_unique(path: Path, key_name: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        key = row[key_name]
        if key in rows:
            raise ValueError(f"Duplicate {key_name} in {path}: {key}")
        rows[key] = row
    return rows


def load_method_predictions(path: Path) -> dict[tuple[str, str], dict]:
    rows = {}
    for row in iter_jsonl(path):
        method = row.get("method")
        if method not in {RAW_METHOD, CANONICAL_METHOD}:
            continue
        key = (row["sample_id"], method)
        if key in rows:
            raise ValueError(f"Duplicate prediction in {path}: {key}")
        rows[key] = row
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def support_matches(prediction: dict, source: str) -> set[tuple[str, str]]:
    support = prediction.get("prediction_detail", {}).get("support", {}).get(source, {})
    urls = support.get("matched_urls", [])
    tokens = support.get("matched_tokens", [])
    if len(urls) != len(tokens):
        raise ValueError(
            f"Support URL/token length mismatch for {prediction['sample_id']} {source}"
        )
    return {(str(url), str(token)) for url, token in zip(urls, tokens)}


def canonical_only_matches(raw: dict, canonical: dict) -> dict[str, list[dict]]:
    result = {}
    for source in ("nvd", "ghsa"):
        added = support_matches(canonical, source) - support_matches(raw, source)
        result[source] = [
            {"url": url, "version_token": token}
            for url, token in sorted(added)
        ]
    return result


def relevant_context(source: dict) -> dict:
    return {
        "package_names": source.get("package_names", []),
        "references": source.get("references", []),
        "published": source.get("published"),
    }


def assert_blinded(value: object, path: str = "row") -> None:
    if isinstance(value, dict):
        forbidden = FORBIDDEN_OUTPUT_KEYS & set(value)
        if forbidden:
            raise ValueError(f"Blinding violation at {path}: {sorted(forbidden)}")
        for key, child in value.items():
            assert_blinded(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_blinded(child, f"{path}[{index}]")


def build_rows(evidence: dict[str, dict], predictions: dict[tuple[str, str], dict]) -> list[dict]:
    raw_ids = {sample_id for sample_id, method in predictions if method == RAW_METHOD}
    canonical_ids = {
        sample_id for sample_id, method in predictions if method == CANONICAL_METHOD
    }
    if raw_ids != canonical_ids:
        raise ValueError("Raw and canonical prediction sample sets differ")

    changed_ids = []
    for sample_id in sorted(raw_ids):
        raw = predictions[(sample_id, RAW_METHOD)]
        canonical = predictions[(sample_id, CANONICAL_METHOD)]
        if raw["predicted_source"] != canonical["predicted_source"]:
            changed_ids.append(sample_id)

    if len(changed_ids) != 10:
        raise ValueError(f"Expected 10 changed token decisions, found {len(changed_ids)}")

    rows = []
    for review_index, sample_id in enumerate(changed_ids, start=1):
        if sample_id not in evidence:
            raise ValueError(f"Missing evidence row: {sample_id}")
        source = evidence[sample_id]
        raw = predictions[(sample_id, RAW_METHOD)]
        canonical = predictions[(sample_id, CANONICAL_METHOD)]
        row = {
            "review_id": f"affected_versions_canonical_dual_review:{review_index:03d}",
            "sample_id": sample_id,
            "cve_id": source["cve_id"],
            "field": "affected_versions",
            "selection_reason": "raw_and_canonical_token_support_decisions_differ",
            "nvd_source_id": source.get("nvd_source_id"),
            "ghsa_source_id": source.get("ghsa_source_id"),
            "nvd_value": source.get("nvd_value"),
            "ghsa_value": source.get("ghsa_value"),
            "nvd_context": relevant_context(source.get("nvd_context", {})),
            "ghsa_context": relevant_context(source.get("ghsa_context", {})),
            "canonical_only_evidence_matches": canonical_only_matches(raw, canonical),
            "evidence_context": source.get("evidence_context", {}),
            "review_contract": {
                "discrepancy_label": [
                    "equivalent",
                    "representation_discrepancy",
                    "incomplete",
                    "temporal_discrepancy",
                    "factual_conflict",
                    "uncertain",
                ],
                "adjudicated_source": ["nvd", "ghsa", "both", "neither", "abstain"],
                "canonical_match_verdict": [
                    "valid_contextual_support",
                    "incidental_or_wrong_context",
                    "mixed",
                    "insufficient_evidence",
                ],
                "recommended_match_policy": [
                    "allow_canonical",
                    "require_raw",
                    "abstain",
                ],
                "confidence": ["high", "medium", "low"],
            },
        }
        assert_blinded(row)
        rows.append(row)
    return rows


def main() -> int:
    args = parse_args()
    evidence_path = resolve_path(args.evidence)
    predictions_path = resolve_path(args.predictions)
    output_dir = resolve_path(args.output_dir)
    evidence = load_unique(evidence_path, "sample_id")
    predictions = load_method_predictions(predictions_path)
    rows = build_rows(evidence, predictions)

    output_dir.mkdir(parents=True, exist_ok=True)
    worklist_path = output_dir / "worklist.blind.jsonl"
    with worklist_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    manifest = {
        "artifact_type": "affected_versions_canonical_dual_review_worklist",
        "row_count": len(rows),
        "selection_only_uses_method_disagreement": True,
        "blinded_from_silver_labels": True,
        "blinded_from_expert_candidate_labels": True,
        "blinded_from_method_predictions": True,
        "live_web_lookup_permitted": False,
        "inputs": {
            "evidence": str(evidence_path),
            "predictions": str(predictions_path),
        },
        "input_sha256": {
            "evidence": sha256(evidence_path),
            "predictions": sha256(predictions_path),
        },
        "output": str(worklist_path),
        "output_sha256": sha256(worklist_path),
    }
    manifest_path = output_dir / "worklist_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {worklist_path}")
    print(f"Wrote {manifest_path}")
    print(f"Rows: {len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
