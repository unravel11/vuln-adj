#!/usr/bin/env python3
"""Evaluate post-v2 type and authority candidates on all unsealed cohorts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import evaluate_affected_versions_silver_v2 as baseline
from affected_versions_authority_graph import predict_authority_filtered_source
from affected_versions_branch_graph import extract_branch_graph_features
from affected_versions_semantic_baseline import (
    range_relation,
    repository_crosswalk_package_profile,
)
from affected_versions_task_separated import predict_discrepancy_type
from affected_versions_task_separated_v2 import predict_discrepancy_type_v2


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PHASE_D = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_PHASE_D_GOLD = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
DEFAULT_V1 = (
    "data/annotations/holdout/affected_versions_v1/evidence/source_rows.evidence.jsonl"
)
DEFAULT_V1_GOLD = (
    "results/holdout/affected_versions_v1/affected_versions_holdout_consensus.jsonl"
)
DEFAULT_V2 = (
    "data/annotations/holdout/affected_versions_v2/evidence/source_rows.evidence.jsonl"
)
DEFAULT_V2_GOLD = (
    "results/holdout/affected_versions_v2/affected_versions_holdout_v2_consensus.jsonl"
)
DEFAULT_OUTPUT_DIR = (
    "results/rq3_adjudication/affected_versions_task_separated_v2"
)
TYPE_ABSTAIN = {"uncertain", "abstain"}
SOURCE_ABSTAIN = {"abstain", "not_applicable", "both"}
LEGACY_NON_CONFLICT = {
    "normalized_interval_equivalent",
    "successor_boundary_candidate",
    "nvd_points_within_ghsa_ranges",
    "ghsa_points_within_nvd_ranges",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase-d", default=DEFAULT_PHASE_D)
    parser.add_argument("--phase-d-gold", default=DEFAULT_PHASE_D_GOLD)
    parser.add_argument("--v1", default=DEFAULT_V1)
    parser.add_argument("--v1-gold", default=DEFAULT_V1_GOLD)
    parser.add_argument("--v2", default=DEFAULT_V2)
    parser.add_argument("--v2-gold", default=DEFAULT_V2_GOLD)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def metrics(gold: list[str], predicted: list[str], abstain_values: set[str]) -> dict:
    if len(gold) != len(predicted):
        raise ValueError("gold/prediction length mismatch")
    determinate = [prediction not in abstain_values for prediction in predicted]
    correct = [
        prediction not in abstain_values and prediction == target
        for target, prediction in zip(gold, predicted)
    ]
    covered = sum(determinate)
    return {
        "rows": len(gold),
        "correct": sum(correct),
        "full_accuracy": sum(correct) / len(gold) if gold else None,
        "determinate": covered,
        "prediction_coverage": covered / len(gold) if gold else None,
        "selective_accuracy": sum(correct) / covered if covered else None,
        "gold_counts": dict(sorted(Counter(gold).items())),
        "prediction_counts": dict(sorted(Counter(predicted).items())),
    }


def legacy_type(row: dict) -> str:
    package = repository_crosswalk_package_profile(row)
    relation = range_relation(row)["relation"]
    return (
        "representation_discrepancy"
        if package["comparable"] and relation in LEGACY_NON_CONFLICT
        else "factual_conflict"
    )


def source_predictions(row: dict) -> dict[str, str]:
    return {
        "authority_filtered_branch_graph": predict_authority_filtered_source(row)[
            "predicted_source"
        ],
        "branch_release_graph": extract_branch_graph_features(row)["predicted_source"],
        "contextual_canonical_version_claim_baseline": baseline.predict_contextual_canonical_version_claim_support(
            row
        )["predicted_source"],
        "prefer_nvd": "nvd",
        "prefer_ghsa": "ghsa",
        "latest_published": baseline.predict_latest_published(row)["predicted_source"],
    }


def evaluate_cohort(name: str, inputs: list[dict], targets: dict[str, dict]) -> dict:
    type_gold = []
    type_predictions: dict[str, list[str]] = {
        "task_separated_type_v1": [],
        "task_separated_type_v2_candidate": [],
        "all_fc_candidate_miner": [],
        "legacy_structural_type": [],
    }
    source_gold = []
    source_method_predictions: dict[str, list[str]] = {}
    for row in inputs:
        target = targets.get(row["sample_id"])
        if target is None:
            continue
        gold_type = target["discrepancy_label"]
        if gold_type != "uncertain":
            type_gold.append(gold_type)
            type_predictions["task_separated_type_v1"].append(
                predict_discrepancy_type(row)["predicted_discrepancy_label"]
            )
            type_predictions["task_separated_type_v2_candidate"].append(
                predict_discrepancy_type_v2(row)["predicted_discrepancy_label"]
            )
            type_predictions["all_fc_candidate_miner"].append("factual_conflict")
            type_predictions["legacy_structural_type"].append(legacy_type(row))

        gold_source = target.get("adjudicated_source")
        if gold_type == "factual_conflict" and gold_source in {"nvd", "ghsa", "neither"}:
            source_gold.append(gold_source)
            predicted = source_predictions(row)
            for method, value in predicted.items():
                source_method_predictions.setdefault(method, []).append(value)

    return {
        "name": name,
        "type_endpoint": {
            method: metrics(type_gold, predicted, TYPE_ABSTAIN)
            for method, predicted in type_predictions.items()
        },
        "source_endpoint": {
            method: metrics(source_gold, predicted, SOURCE_ABSTAIN)
            for method, predicted in source_method_predictions.items()
        },
    }


def phase_d_targets(path: Path) -> dict[str, dict]:
    return {
        row["annotation"]["sample_id"]: row["annotation"]
        for row in load_jsonl(path)
    }


def v1_targets(path: Path) -> dict[str, dict]:
    return {
        row["sample_id"]: row
        for row in load_jsonl(path)
        if row["consensus_status"] == "strict_determinate"
    }


def v2_targets(path: Path) -> dict[str, dict]:
    return {
        row["sample_id"]: row
        for row in load_jsonl(path)
        if row["type_consensus_status"] == "strict_determinate"
    }


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Versions Post-V2 Development Diagnostic",
        "",
        "All cohorts were unsealed before this candidate was defined. Targets are non-human labels; the diagnostic is post-hoc and not confirmatory.",
        "",
        "## Type endpoint",
        "",
        "| Cohort | Method | Correct/rows | Coverage | Selective accuracy |",
        "|---|---|---:|---:|---:|",
    ]
    for cohort in artifact["cohorts"]:
        for method, result in cohort["type_endpoint"].items():
            selective = result["selective_accuracy"]
            lines.append(
                f"| {cohort['name']} | {method} | {result['correct']}/{result['rows']} | "
                f"{result['prediction_coverage']:.4f} | "
                f"{selective:.4f} |"
                if selective is not None
                else f"| {cohort['name']} | {method} | {result['correct']}/{result['rows']} | {result['prediction_coverage']:.4f} | - |"
            )
    lines.extend(
        [
            "",
            "## FC-source endpoint",
            "",
            "| Cohort | Method | Correct/rows | Coverage | Selective accuracy |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for cohort in artifact["cohorts"]:
        for method, result in cohort["source_endpoint"].items():
            selective = result["selective_accuracy"]
            lines.append(
                f"| {cohort['name']} | {method} | {result['correct']}/{result['rows']} | "
                f"{result['prediction_coverage']:.4f} | "
                f"{selective:.4f} |"
                if selective is not None
                else f"| {cohort['name']} | {method} | {result['correct']}/{result['rows']} | {result['prediction_coverage']:.4f} | - |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    paths = {
        "phase_d": resolve(args.phase_d),
        "phase_d_gold": resolve(args.phase_d_gold),
        "v1": resolve(args.v1),
        "v1_gold": resolve(args.v1_gold),
        "v2": resolve(args.v2),
        "v2_gold": resolve(args.v2_gold),
    }
    cohorts = [
        evaluate_cohort(
            "phase_d_ai_candidate",
            load_jsonl(paths["phase_d"]),
            phase_d_targets(paths["phase_d_gold"]),
        ),
        evaluate_cohort(
            "v1_strict_dual_codex",
            load_jsonl(paths["v1"]),
            v1_targets(paths["v1_gold"]),
        ),
        evaluate_cohort(
            "v2_strict_dual_codex",
            load_jsonl(paths["v2"]),
            v2_targets(paths["v2_gold"]),
        ),
    ]
    artifact = {
        "artifact_type": "affected_versions_post_v2_development_diagnostic",
        "analysis_is_posthoc": True,
        "method_selected_after_inspecting_v2": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "cohorts": cohorts,
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
        },
        "method_code": {
            name: {
                "path": str(Path(__file__).with_name(name)),
                "sha256": sha256(Path(__file__).with_name(name)),
            }
            for name in (
                "affected_versions_task_separated_v2.py",
                "affected_versions_authority_graph.py",
            )
        },
        "cautions": [
            "The type rules were designed after inspecting v2 feature/label cross-tabs.",
            "Authority classes are deterministic provenance filters, not validated reliability weights.",
            "All targets are AI/Codex candidates rather than human gold.",
            "Only a future disjoint cohort can test generalization.",
        ],
    }
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "development_diagnostic.json"
    md_path = output_dir / "development_diagnostic.md"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
