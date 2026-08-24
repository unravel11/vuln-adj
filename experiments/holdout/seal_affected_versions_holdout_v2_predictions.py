#!/usr/bin/env python3
"""Seal label-free type and FC-source predictions for affected_versions v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RQ3_DIR = ROOT / "experiments/rq3_adjudication"
sys.path.insert(0, str(RQ3_DIR))

import evaluate_affected_versions_silver_v2 as baseline  # noqa: E402
from affected_versions_artifact_graph import extract_artifact_graph_features  # noqa: E402
from affected_versions_branch_graph import extract_branch_graph_features  # noqa: E402
from affected_versions_semantic_baseline import (  # noqa: E402
    range_relation,
    repository_crosswalk_package_profile,
)
from affected_versions_task_separated import predict_tasks  # noqa: E402


DEFAULT_INPUT = (
    "data/annotations/holdout/affected_versions_v2/evidence/"
    "source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v2/sealed_predictions"
DEFAULT_AGENT_A = "data/annotations/holdout/affected_versions_v2/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = "data/annotations/holdout/affected_versions_v2/agent_b_decisions.jsonl"
FALLBACK = "repository_crosswalk_package_gated_canonical_token_baseline"
TYPE_PRIMARY = "task_separated_type_v1"
SOURCE_PRIMARY = "branch_release_graph"
METHOD_FILES = (
    "experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py",
    "experiments/rq3_adjudication/affected_versions_semantic_baseline.py",
    "experiments/rq3_adjudication/affected_versions_release_boundary.py",
    "experiments/rq3_adjudication/affected_versions_branch_graph.py",
    "experiments/rq3_adjudication/affected_versions_artifact_graph.py",
    "experiments/rq3_adjudication/affected_versions_task_separated.py",
)
LEGACY_NON_CONFLICT = {
    "normalized_interval_equivalent",
    "successor_boundary_candidate",
    "nvd_points_within_ghsa_ranges",
    "ghsa_points_within_nvd_ranges",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
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


def load_rows(path: Path, expected_rows: int) -> list[dict]:
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    sample_ids = [row.get("sample_id") for row in rows]
    if len(rows) != expected_rows or len(set(sample_ids)) != expected_rows or None in sample_ids:
        raise ValueError("v2 input must contain the expected unique sample IDs")
    if any(not sample_id.startswith("affected_versions_holdout_v2:") for sample_id in sample_ids):
        raise ValueError("v2 input contains a non-v2 sample ID")
    return sorted(rows, key=lambda row: row["sample_id"])


def assert_unsealed(agent_paths: list[Path], output_paths: list[Path]) -> None:
    existing_agents = [str(path) for path in agent_paths if path.exists()]
    if existing_agents:
        raise RuntimeError(f"review decisions already exist; refusing to reseal: {existing_agents}")
    existing_outputs = [str(path) for path in output_paths if path.exists()]
    if existing_outputs:
        raise RuntimeError(f"sealed outputs already exist; refusing overwrite: {existing_outputs}")


def base_source_predictors() -> dict:
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


def type_predictions(row: dict, task: dict) -> dict[str, dict]:
    legacy = range_relation(row)
    package = repository_crosswalk_package_profile(row)
    legacy_non_conflict = package["comparable"] and legacy["relation"] in LEGACY_NON_CONFLICT
    return {
        "all_fc_candidate_miner": {
            "predicted_discrepancy_label": "factual_conflict",
            "prediction_status": "determinate",
            "rule": "retain the deterministic candidate-miner label",
        },
        "legacy_structural_type": {
            "predicted_discrepancy_label": (
                "representation_discrepancy" if legacy_non_conflict else "factual_conflict"
            ),
            "prediction_status": "determinate",
            "rule": "legacy structural compatibility else factual conflict",
            "package_comparable": package["comparable"],
            "legacy_range_relation": legacy["relation"],
        },
        TYPE_PRIMARY: {
            "predicted_discrepancy_label": task["type"]["predicted_discrepancy_label"],
            "prediction_status": task["type"]["type_prediction_status"],
            "rule": task["type"]["rule"],
            "prediction_detail": task["type"],
        },
    }


def source_predictions(row: dict, task: dict) -> dict[str, dict]:
    predictions = {name: predictor(row) for name, predictor in base_source_predictors().items()}
    branch = extract_branch_graph_features(row)
    artifact = extract_artifact_graph_features(row)
    branch_source = branch["predicted_source"]
    artifact_source = artifact["predicted_source"]
    fallback_source = predictions[FALLBACK]["predicted_source"]
    predictions.update(
        {
            SOURCE_PRIMARY: task["source_head"],
            "artifact_bound_branch_graph": {
                "predicted_source": artifact_source,
                "rule": "sealed_artifact_bound_branch_graph",
            },
            "branch_graph_then_crosswalk_canonical": {
                "predicted_source": fallback_source if branch_source == "abstain" else branch_source,
                "rule": "sealed_branch_then_fixed_fallback",
            },
            "artifact_graph_then_crosswalk_canonical": {
                "predicted_source": fallback_source if artifact_source == "abstain" else artifact_source,
                "rule": "sealed_artifact_then_fixed_fallback",
            },
            "task_separated_pipeline_source_v1": task["source"],
        }
    )
    return predictions


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    output_dir = resolve(args.output_dir)
    agent_paths = [resolve(args.agent_a), resolve(args.agent_b)]
    type_path = output_dir / "affected_versions_holdout_v2_type_predictions.jsonl"
    source_path = output_dir / "affected_versions_holdout_v2_source_predictions.jsonl"
    manifest_path = output_dir / "manifest.json"
    assert_unsealed(agent_paths, [type_path, source_path, manifest_path])
    rows = load_rows(input_path, args.expected_rows)

    type_rows = []
    source_rows = []
    type_methods: set[str] = set()
    source_methods: set[str] = set()
    for row in rows:
        task = predict_tasks(row)
        typed = type_predictions(row, task)
        sourced = source_predictions(row, task)
        type_methods.update(typed)
        source_methods.update(sourced)
        for method, prediction in sorted(typed.items()):
            type_rows.append(
                {
                    "sample_id": row["sample_id"],
                    "cve_id": row["cve_id"],
                    "method": method,
                    **prediction,
                }
            )
        for method, prediction in sorted(sourced.items()):
            source_rows.append(
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
    if len(type_rows) != args.expected_rows * len(type_methods):
        raise AssertionError("type prediction matrix is incomplete")
    if len(source_rows) != args.expected_rows * len(source_methods):
        raise AssertionError("source prediction matrix is incomplete")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(type_path, type_rows)
    write_jsonl(source_path, source_rows)
    manifest = {
        "artifact_type": "affected_versions_holdout_v2_sealed_predictions",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "contains_gold_labels": False,
        "contains_ai_labels": False,
        "prediction_generation_uses_labels": False,
        "review_decision_paths_absent_at_seal": [str(path) for path in agent_paths],
        "sealed_before_agent_review": True,
        "rows": args.expected_rows,
        "type_methods": sorted(type_methods),
        "source_methods": sorted(source_methods),
        "type_prediction_rows": len(type_rows),
        "source_prediction_rows": len(source_rows),
        "preregistered_endpoints": {
            "discrepancy_typing": {
                "primary_method": TYPE_PRIMARY,
                "primary_metric": "full_accuracy_with_abstain_incorrect_on_strict_type_consensus",
                "secondary_metrics": ["prediction_coverage", "selective_accuracy", "macro_f1"],
                "comparators": ["all_fc_candidate_miner", "legacy_structural_type"],
            },
            "fc_source_adjudication": {
                "primary_method": SOURCE_PRIMARY,
                "population": "rows_with_strict_factual_conflict_type_and_strict_source_consensus",
                "primary_metric": "full_source_accuracy_with_abstain_incorrect",
                "secondary_metrics": ["prediction_coverage", "selective_accuracy", "macro_f1"],
                "comparators": [
                    "prefer_nvd",
                    "prefer_ghsa",
                    "latest_published",
                    "artifact_bound_branch_graph",
                ],
            },
        },
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "method_code": {name: sha256(resolve(name)) for name in METHOD_FILES},
        "protocol_code": {
            name: sha256(resolve(name))
            for name in (
                "docs/prompts/affected_versions_holdout_v2_adjudication.md",
                "experiments/holdout/build_affected_versions_blind_worklist_v2.py",
                "experiments/holdout/seal_affected_versions_holdout_v2_predictions.py",
                "experiments/holdout/merge_affected_versions_holdout_v2_adjudication.py",
                "experiments/holdout/evaluate_affected_versions_holdout_v2.py",
            )
        },
        "outputs": {
            "type_predictions": {"path": str(type_path), "sha256": sha256(type_path)},
            "source_predictions": {"path": str(source_path), "sha256": sha256(source_path)},
        },
        "cautions": [
            "The primary method was selected on the old development and unsealed v1 cohorts only.",
            "Type and FC-source endpoints are evaluated separately.",
            "No method or endpoint may change after reviewer decisions are unsealed.",
            "All future reviewer labels remain non-human until real human signoff.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {type_path}")
    print(f"Wrote {source_path}")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
