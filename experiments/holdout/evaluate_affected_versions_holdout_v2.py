#!/usr/bin/env python3
"""Evaluate preregistered v2 discrepancy-type and FC-source endpoints."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONSENSUS = (
    "results/holdout/affected_versions_v2/affected_versions_holdout_v2_consensus.jsonl"
)
DEFAULT_SUMMARY = (
    "results/holdout/affected_versions_v2/affected_versions_holdout_v2_consensus_summary.json"
)
DEFAULT_TYPE_PREDICTIONS = (
    "results/holdout/affected_versions_v2/sealed_predictions/"
    "affected_versions_holdout_v2_type_predictions.jsonl"
)
DEFAULT_SOURCE_PREDICTIONS = (
    "results/holdout/affected_versions_v2/sealed_predictions/"
    "affected_versions_holdout_v2_source_predictions.jsonl"
)
DEFAULT_PREDICTION_MANIFEST = (
    "results/holdout/affected_versions_v2/sealed_predictions/manifest.json"
)
DEFAULT_AGENT_A = "data/annotations/holdout/affected_versions_v2/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = "data/annotations/holdout/affected_versions_v2/agent_b_decisions.jsonl"
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v2/evaluation"
FORBIDDEN_KEYS = {"gold_label", "gold_source", "silver_label", "silver_source", "is_correct"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--consensus-summary", default=DEFAULT_SUMMARY)
    parser.add_argument("--type-predictions", default=DEFAULT_TYPE_PREDICTIONS)
    parser.add_argument("--source-predictions", default=DEFAULT_SOURCE_PREDICTIONS)
    parser.add_argument("--prediction-manifest", default=DEFAULT_PREDICTION_MANIFEST)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260715)
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


def validate_sealed_code_hashes(mapping: object, kind: str) -> None:
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError(f"prediction manifest lacks sealed {kind} hashes")
    for relative_path, expected_hash in mapping.items():
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            raise ValueError(f"prediction manifest has invalid {kind} hash entry")
        if sha256(resolve(relative_path)) != expected_hash:
            raise ValueError(f"{kind} file changed after prediction seal: {relative_path}")


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_matrix(path: Path, value_key: str, status_key: str | None = None) -> dict:
    matrix: dict[str, dict[str, dict]] = {}
    for line_number, row in enumerate(load_jsonl(path), 1):
        forbidden = FORBIDDEN_KEYS & set(row)
        if forbidden:
            raise ValueError(f"{path}:{line_number}: contains labels {sorted(forbidden)}")
        sample_id = row.get("sample_id")
        method = row.get("method")
        if not sample_id or not method or value_key not in row:
            raise ValueError(f"{path}:{line_number}: incomplete prediction identity")
        methods = matrix.setdefault(sample_id, {})
        if method in methods:
            raise ValueError(f"{path}:{line_number}: duplicate sample/method")
        methods[method] = {
            "value": row[value_key],
            "status": row.get(status_key) if status_key else None,
        }
    return matrix


def macro_f1(gold: list[str], predicted: list[str]) -> float:
    labels = sorted(set(gold))
    scores = []
    for label in labels:
        tp = sum(g == label and p == label for g, p in zip(gold, predicted))
        fp = sum(g != label and p == label for g, p in zip(gold, predicted))
        fn = sum(g == label and p != label for g, p in zip(gold, predicted))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return sum(scores) / len(scores) if scores else 0.0


def endpoint_metrics(rows: list[dict], method: str, abstain_values: set[str]) -> dict:
    gold = [row["gold"] for row in rows]
    predicted = [row["predictions"][method]["value"] for row in rows]
    determinate = [value not in abstain_values for value in predicted]
    correct = [p not in abstain_values and g == p for g, p in zip(gold, predicted)]
    covered_correct = sum(ok and covered for ok, covered in zip(correct, determinate))
    coverage = sum(determinate) / len(rows) if rows else 0.0
    return {
        "rows": len(rows),
        "correct": sum(correct),
        "accuracy": sum(correct) / len(rows) if rows else 0.0,
        "macro_f1_over_supported_labels": macro_f1(gold, predicted),
        "non_abstain": sum(determinate),
        "prediction_coverage": coverage,
        "selective_accuracy": (
            covered_correct / sum(determinate) if any(determinate) else None
        ),
        "prediction_counts": dict(sorted(Counter(predicted).items())),
        "gold_counts": dict(sorted(Counter(gold).items())),
    }


def paired_comparison(
    rows: list[dict], primary: str, comparator: str, abstain_values: set[str], replicates: int, seed: int
) -> dict:
    primary_correct = [
        row["predictions"][primary]["value"] not in abstain_values
        and row["predictions"][primary]["value"] == row["gold"]
        for row in rows
    ]
    comparator_correct = [
        row["predictions"][comparator]["value"] not in abstain_values
        and row["predictions"][comparator]["value"] == row["gold"]
        for row in rows
    ]
    deltas = [int(p) - int(c) for p, c in zip(primary_correct, comparator_correct)]
    observed = sum(deltas) / len(deltas) if deltas else 0.0
    rng = random.Random(seed)
    boot = []
    if deltas:
        for _ in range(replicates):
            boot.append(sum(deltas[rng.randrange(len(deltas))] for _ in deltas) / len(deltas))
        boot.sort()
        lower = boot[int(0.025 * (len(boot) - 1))]
        upper = boot[int(0.975 * (len(boot) - 1))]
    else:
        lower = upper = 0.0
    return {
        "primary": primary,
        "comparator": comparator,
        "rows": len(rows),
        "accuracy_delta": observed,
        "bootstrap_95_interval": [lower, upper],
        "primary_only_correct": sum(p and not c for p, c in zip(primary_correct, comparator_correct)),
        "comparator_only_correct": sum(c and not p for p, c in zip(primary_correct, comparator_correct)),
        "both_correct": sum(p and c for p, c in zip(primary_correct, comparator_correct)),
        "both_wrong": sum(not p and not c for p, c in zip(primary_correct, comparator_correct)),
        "primary_abstain_values": sorted(abstain_values),
    }


def validate_matrix(matrix: dict, expected_ids: set[str], methods: set[str], name: str) -> None:
    if set(matrix) != expected_ids:
        raise ValueError(f"{name} sample identity mismatch")
    for sample_id, predictions in matrix.items():
        if set(predictions) != methods:
            raise ValueError(f"{name} incomplete method matrix for {sample_id}")


def eligible_source_consensus(row: dict) -> bool:
    return (
        row["type_consensus_status"] == "strict_determinate"
        and row["discrepancy_label"] == "factual_conflict"
        and row["source_consensus_status"] == "strict_determinate"
    )


def main() -> int:
    args = parse_args()
    consensus_path = resolve(args.consensus)
    summary_path = resolve(args.consensus_summary)
    type_path = resolve(args.type_predictions)
    source_path = resolve(args.source_predictions)
    manifest_path = resolve(args.prediction_manifest)
    agent_paths = [resolve(args.agent_a), resolve(args.agent_b)]
    output_dir = resolve(args.output_dir)

    consensus = load_jsonl(consensus_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    type_matrix = load_matrix(type_path, "predicted_discrepancy_label", "prediction_status")
    source_matrix = load_matrix(source_path, "predicted_source")
    for sample_predictions in type_matrix.values():
        for method, prediction in sample_predictions.items():
            expected_status = (
                "abstain" if prediction["value"] in {"uncertain", "abstain"} else "determinate"
            )
            if prediction["status"] != expected_status:
                raise ValueError(f"type prediction value/status mismatch for {method}")
    if len(consensus) != manifest.get("rows"):
        raise ValueError("consensus row count differs from sealed cohort size")
    if summary.get("rows") != len(consensus):
        raise ValueError("consensus summary row count differs from consensus")
    if summary.get("label_is_human") is not False:
        raise ValueError("consensus summary must remain explicitly non-human")
    sample_ids = [row.get("sample_id") for row in consensus]
    cve_ids = [row.get("cve_id") for row in consensus]
    if None in sample_ids or len(sample_ids) != len(set(sample_ids)):
        raise ValueError("consensus sample IDs must be present and unique")
    if None in cve_ids or len(cve_ids) != len(set(cve_ids)):
        raise ValueError("consensus CVE IDs must be present and unique for row bootstrap")
    if manifest.get("contains_gold_labels") is not False or manifest.get("sealed_before_agent_review") is not True:
        raise ValueError("prediction manifest does not prove a label-free pre-review seal")
    if manifest["outputs"]["type_predictions"]["sha256"] != sha256(type_path):
        raise ValueError("type prediction hash mismatch")
    if manifest["outputs"]["source_predictions"]["sha256"] != sha256(source_path):
        raise ValueError("source prediction hash mismatch")
    if manifest["input"]["sha256"] != summary["inputs"]["evidence"]["sha256"]:
        raise ValueError("predictions and consensus use different evidence snapshots")
    if summary["inputs"]["agent_a"]["sha256"] != sha256(agent_paths[0]):
        raise ValueError("consensus summary is not bound to the current agent A file")
    if summary["inputs"]["agent_b"]["sha256"] != sha256(agent_paths[1]):
        raise ValueError("consensus summary is not bound to the current agent B file")
    if summary["output"]["sha256"] != sha256(consensus_path):
        raise ValueError("consensus hash differs from its summary")
    validate_sealed_code_hashes(manifest.get("method_code"), "method")
    validate_sealed_code_hashes(manifest.get("protocol_code"), "protocol")
    seal_mtime = max(type_path.stat().st_mtime_ns, source_path.stat().st_mtime_ns, manifest_path.stat().st_mtime_ns)
    if any(path.stat().st_mtime_ns <= seal_mtime for path in agent_paths):
        raise ValueError("review decision mtime does not postdate the complete prediction seal")

    expected_ids = set(sample_ids)
    type_methods = set(manifest["type_methods"])
    source_methods = set(manifest["source_methods"])
    validate_matrix(type_matrix, expected_ids, type_methods, "type")
    validate_matrix(source_matrix, expected_ids, source_methods, "source")

    strict_type_rows = []
    strict_source_rows = []
    for gold in consensus:
        sample_id = gold["sample_id"]
        if gold["type_consensus_status"] == "strict_determinate":
            strict_type_rows.append(
                {
                    "sample_id": sample_id,
                    "gold": gold["discrepancy_label"],
                    "predictions": type_matrix[sample_id],
                }
            )
        if eligible_source_consensus(gold):
            strict_source_rows.append(
                {
                    "sample_id": sample_id,
                    "gold": gold["adjudicated_source"],
                    "predictions": source_matrix[sample_id],
                }
            )

    endpoints = manifest["preregistered_endpoints"]
    type_primary = endpoints["discrepancy_typing"]["primary_method"]
    source_primary = endpoints["fc_source_adjudication"]["primary_method"]
    type_metrics = {
        method: endpoint_metrics(strict_type_rows, method, {"uncertain", "abstain"})
        for method in sorted(type_methods)
    }
    source_metrics = {
        method: endpoint_metrics(strict_source_rows, method, {"abstain", "not_applicable"})
        for method in sorted(source_methods)
    }
    type_confirmatory_methods = {
        type_primary,
        *endpoints["discrepancy_typing"]["comparators"],
    }
    source_confirmatory_methods = {
        source_primary,
        *endpoints["fc_source_adjudication"]["comparators"],
    }
    type_ranking = [
        {"method": method, **type_metrics[method]}
        for method in sorted(type_confirmatory_methods)
    ]
    type_ranking.sort(key=lambda row: (row["accuracy"], row["prediction_coverage"], row["method"]), reverse=True)
    source_ranking = [
        {"method": method, **source_metrics[method]}
        for method in sorted(source_confirmatory_methods)
    ]
    source_ranking.sort(key=lambda row: (row["accuracy"], row["prediction_coverage"], row["method"]), reverse=True)
    type_exploratory = [
        {"method": method, **type_metrics[method]}
        for method in sorted(type_methods - type_confirmatory_methods)
    ]
    source_exploratory = [
        {"method": method, **source_metrics[method]}
        for method in sorted(source_methods - source_confirmatory_methods)
    ]
    type_paired = {
        comparator: paired_comparison(
            strict_type_rows,
            type_primary,
            comparator,
            {"uncertain", "abstain"},
            args.bootstrap_replicates,
            args.bootstrap_seed,
        )
        for comparator in endpoints["discrepancy_typing"]["comparators"]
    }
    source_paired = {
        comparator: paired_comparison(
            strict_source_rows,
            source_primary,
            comparator,
            {"abstain", "not_applicable"},
            args.bootstrap_replicates,
            args.bootstrap_seed,
        )
        for comparator in endpoints["fc_source_adjudication"]["comparators"]
    }
    artifact = {
        "artifact_type": "affected_versions_holdout_v2_task_separated_evaluation",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "production_default_changed": False,
        "cohort_rows": len(consensus),
        "strict_type_rows": len(strict_type_rows),
        "strict_type_coverage": len(strict_type_rows) / len(consensus),
        "strict_source_rows": len(strict_source_rows),
        "strict_source_coverage": len(strict_source_rows) / len(consensus),
        "preregistered_endpoints": endpoints,
        "discrepancy_typing": {
            "method_ranking": type_ranking,
            "primary_comparisons": type_paired,
            "exploratory_methods": type_exploratory,
        },
        "fc_source_adjudication": {
            "method_ranking": source_ranking,
            "primary_comparisons": source_paired,
            "exploratory_methods": source_exploratory,
        },
        "inputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "consensus_summary": {"path": str(summary_path), "sha256": sha256(summary_path)},
            "type_predictions": {"path": str(type_path), "sha256": sha256(type_path)},
            "source_predictions": {"path": str(source_path), "sha256": sha256(source_path)},
            "prediction_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
        },
        "cautions": [
            "Both label endpoints use strict dual-Codex consensus rather than human gold.",
            "Full accuracy counts prediction abstention as incorrect and must be reported with coverage.",
            "FC-source metrics are conditional on both strict FC type and strict source consensus.",
            "The v2 cohort is now unsealed and cannot be used to tune another confirmatory method.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_v2_evaluation.json"
    output_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
