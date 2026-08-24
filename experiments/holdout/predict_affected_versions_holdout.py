#!/usr/bin/env python3
"""Seal label-free affected_versions method predictions before holdout review."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
RQ3_DIR = ROOT / "experiments/rq3_adjudication"
sys.path.insert(0, str(RQ3_DIR))

import evaluate_affected_versions_silver_v2 as baseline  # noqa: E402
from affected_versions_artifact_graph import extract_artifact_graph_features  # noqa: E402
from affected_versions_branch_graph import extract_branch_graph_features  # noqa: E402


DEFAULT_INPUT = (
    "data/annotations/holdout/affected_versions_v1/evidence/"
    "source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v1/sealed_predictions"
FALLBACK = "repository_crosswalk_package_gated_canonical_token_baseline"
METHOD_FILES = (
    "experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py",
    "experiments/rq3_adjudication/affected_versions_semantic_baseline.py",
    "experiments/rq3_adjudication/affected_versions_release_boundary.py",
    "experiments/rq3_adjudication/affected_versions_branch_graph.py",
    "experiments/rq3_adjudication/affected_versions_artifact_graph.py",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-rows", type=int, default=100)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def predictors() -> dict[str, Callable[[dict], dict]]:
    return {
        "prefer_nvd": baseline.predict_prefer("nvd"),
        "prefer_ghsa": baseline.predict_prefer("ghsa"),
        "latest_published": baseline.predict_latest_published,
        "version_token_support_baseline": baseline.predict_version_token_support,
        "canonical_version_token_support_baseline": baseline.predict_canonical_version_token_support,
        "contextual_version_claim_baseline": baseline.predict_contextual_version_claim_support,
        "contextual_canonical_version_claim_baseline": baseline.predict_contextual_canonical_version_claim_support,
        "package_gated_contextual_version_claim_baseline": baseline.predict_package_gated_contextual_version_claim_support,
        "package_gated_contextual_canonical_version_claim_baseline": baseline.predict_package_gated_contextual_canonical_version_claim_support,
        "package_gated_token_baseline": baseline.predict_package_gated_token_support,
        "package_gated_canonical_token_baseline": baseline.predict_package_gated_canonical_token_support,
        "repository_crosswalk_package_gated_token_baseline": baseline.predict_repository_crosswalk_package_gated_token_support,
        FALLBACK: baseline.predict_repository_crosswalk_package_gated_canonical_token_support,
        "package_range_evidence_baseline": baseline.predict_package_range_evidence,
    }


def load_rows(path: Path, expected_rows: int) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    sample_ids = [row.get("sample_id") for row in rows]
    if len(rows) != expected_rows or len(set(sample_ids)) != expected_rows or None in sample_ids:
        raise ValueError("holdout input must contain the expected unique sample IDs")
    return sorted(rows, key=lambda row: row["sample_id"])


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    output_dir = resolve(args.output_dir)
    rows = load_rows(input_path, args.expected_rows)
    base_predictors = predictors()
    predictions = []
    feature_rows = []
    method_names = set(base_predictors)
    method_names.update(
        {
            "branch_release_graph",
            "artifact_bound_branch_graph",
            "branch_graph_then_crosswalk_canonical",
            "artifact_graph_then_crosswalk_canonical",
        }
    )
    for row in rows:
        sample_predictions = {
            name: predictor(row) for name, predictor in base_predictors.items()
        }
        branch = extract_branch_graph_features(row)
        artifact = extract_artifact_graph_features(row)
        branch_source = branch["predicted_source"]
        artifact_source = artifact["predicted_source"]
        fallback_source = sample_predictions[FALLBACK]["predicted_source"]
        sample_predictions["branch_release_graph"] = {
            "predicted_source": branch_source,
            "rule": "sealed_branch_release_graph",
        }
        sample_predictions["artifact_bound_branch_graph"] = {
            "predicted_source": artifact_source,
            "rule": "sealed_artifact_bound_branch_graph",
        }
        sample_predictions["branch_graph_then_crosswalk_canonical"] = {
            "predicted_source": fallback_source if branch_source == "abstain" else branch_source,
            "rule": "sealed_branch_then_fixed_fallback",
        }
        sample_predictions["artifact_graph_then_crosswalk_canonical"] = {
            "predicted_source": fallback_source if artifact_source == "abstain" else artifact_source,
            "rule": "sealed_artifact_then_fixed_fallback",
        }
        for method in sorted(sample_predictions):
            prediction = sample_predictions[method]
            predictions.append(
                {
                    "sample_id": row["sample_id"],
                    "cve_id": row["cve_id"],
                    "method": method,
                    "predicted_source": prediction["predicted_source"],
                    "rule": prediction["rule"],
                    "prediction_detail": {
                        key: value
                        for key, value in prediction.items()
                        if key not in {"predicted_source", "rule"}
                    },
                }
            )
        feature_rows.append(
            {
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "branch": branch,
                "artifact": artifact,
            }
        )
    if len(predictions) != args.expected_rows * len(method_names):
        raise AssertionError("prediction matrix is incomplete")

    output_dir.mkdir(parents=True, exist_ok=True)
    prediction_path = output_dir / "affected_versions_holdout_predictions.jsonl"
    feature_path = output_dir / "affected_versions_holdout_graph_features.jsonl"
    with prediction_path.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    with feature_path.open("w", encoding="utf-8") as handle:
        for row in feature_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "artifact_type": "affected_versions_holdout_sealed_predictions_v1",
        "contains_gold_labels": False,
        "contains_ai_labels": False,
        "prediction_generation_uses_labels": False,
        "sealed_before_agent_review": True,
        "primary_method": "version_token_support_baseline",
        "primary_metric": "full_accuracy_on_strict_dual_codex_determinate_rows",
        "secondary_metrics": ["macro_f1", "prediction_coverage", "selective_accuracy"],
        "rows": args.expected_rows,
        "methods": sorted(method_names),
        "prediction_rows": len(predictions),
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "method_code": {
            name: sha256(resolve(name)) for name in METHOD_FILES
        },
        "outputs": {
            "predictions": {"path": str(prediction_path), "sha256": sha256(prediction_path)},
            "graph_features": {"path": str(feature_path), "sha256": sha256(feature_path)},
        },
        "cautions": [
            "The cohort is independent of method development by CVE, not human-gold.",
            "No method may be changed after unsealing reviewer decisions for this cohort.",
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {prediction_path}")
    print(f"Wrote {feature_path}")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
