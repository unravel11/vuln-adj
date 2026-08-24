#!/usr/bin/env python3
"""Evaluate sealed predictions on strict dual-Codex holdout consensus rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AI_DIR = ROOT / "experiments/ai_adjudicated_gold"
sys.path.insert(0, str(AI_DIR))

import evaluate_affected_versions_source_overlay as shared  # noqa: E402


DEFAULT_CONSENSUS = (
    "results/holdout/affected_versions_v1/affected_versions_holdout_consensus.jsonl"
)
DEFAULT_CONSENSUS_SUMMARY = (
    "results/holdout/affected_versions_v1/affected_versions_holdout_consensus_summary.json"
)
DEFAULT_PREDICTIONS = (
    "results/holdout/affected_versions_v1/sealed_predictions/"
    "affected_versions_holdout_predictions.jsonl"
)
DEFAULT_PREDICTION_MANIFEST = (
    "results/holdout/affected_versions_v1/sealed_predictions/manifest.json"
)
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v1/evaluation"
PRIMARY = "version_token_support_baseline"
COMPARATORS = (
    "canonical_version_token_support_baseline",
    "artifact_bound_branch_graph",
    "package_range_evidence_baseline",
    "package_gated_token_baseline",
)
FORBIDDEN_PREDICTION_KEYS = {
    "gold_label",
    "gold_source",
    "silver_label",
    "silver_source",
    "is_correct",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--consensus-summary", default=DEFAULT_CONSENSUS_SUMMARY)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--prediction-manifest", default=DEFAULT_PREDICTION_MANIFEST)
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


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_prediction_matrix(path: Path) -> dict[str, dict[str, str]]:
    matrix: dict[str, dict[str, str]] = {}
    for line_number, row in enumerate(load_jsonl(path), 1):
        forbidden = FORBIDDEN_PREDICTION_KEYS & set(row)
        if forbidden:
            raise ValueError(f"{path}:{line_number}: prediction contains labels {sorted(forbidden)}")
        sample_id = row.get("sample_id")
        method = row.get("method")
        source = row.get("predicted_source")
        if not sample_id or not method or not source:
            raise ValueError(f"{path}:{line_number}: incomplete prediction identity")
        methods = matrix.setdefault(sample_id, {})
        if method in methods:
            raise ValueError(f"{path}:{line_number}: duplicate sample/method")
        methods[method] = source
    return matrix


def main() -> int:
    args = parse_args()
    consensus_path = resolve(args.consensus)
    consensus_summary_path = resolve(args.consensus_summary)
    prediction_path = resolve(args.predictions)
    prediction_manifest_path = resolve(args.prediction_manifest)
    output_dir = resolve(args.output_dir)
    consensus = load_jsonl(consensus_path)
    consensus_summary = json.loads(consensus_summary_path.read_text(encoding="utf-8"))
    prediction_manifest = json.loads(prediction_manifest_path.read_text(encoding="utf-8"))
    predictions = load_prediction_matrix(prediction_path)

    if prediction_manifest.get("contains_gold_labels") is not False:
        raise ValueError("prediction manifest does not prove a label-free seal")
    if prediction_manifest.get("sealed_before_agent_review") is not True:
        raise ValueError("predictions were not declared sealed before review")
    if prediction_manifest["outputs"]["predictions"]["sha256"] != sha256(prediction_path):
        raise ValueError("sealed prediction hash mismatch")
    if consensus_summary["inputs"]["evidence"]["sha256"] != prediction_manifest["input"]["sha256"]:
        raise ValueError("consensus and sealed predictions use different evidence snapshots")
    if len(consensus) != 100 or len(predictions) != 100:
        raise ValueError("holdout artifacts must cover 100 rows")
    if {row["sample_id"] for row in consensus} != set(predictions):
        raise ValueError("consensus/prediction identity mismatch")
    methods = set(prediction_manifest["methods"])
    if PRIMARY not in methods or not set(COMPARATORS) <= methods:
        raise ValueError("preregistered primary/comparator methods are missing")
    for sample_id, sample_predictions in predictions.items():
        if set(sample_predictions) != methods:
            raise ValueError(f"{sample_id}: incomplete method matrix")

    strict_rows = []
    for gold in consensus:
        if gold["consensus_status"] != "strict_determinate":
            continue
        sample_id = gold["sample_id"]
        strict_rows.append(
            {
                "sample_id": sample_id,
                "gold_source": gold["adjudicated_source"],
                "discrepancy_label": gold["discrepancy_label"],
                "predictions": predictions[sample_id],
            }
        )
    if not strict_rows:
        raise ValueError("strict consensus has no determinate rows")

    metrics = {method: shared.metrics(strict_rows, method) for method in sorted(methods)}
    ranking = [{"method": method, **values} for method, values in metrics.items()]
    ranking.sort(
        key=lambda row: (
            row["accuracy"],
            row["macro_f1_over_supported_labels"],
            row["prediction_coverage"],
            row["method"],
        ),
        reverse=True,
    )
    shared.BOOTSTRAP_REPLICATES = args.bootstrap_replicates
    shared.BOOTSTRAP_SEED = args.bootstrap_seed
    paired = {
        comparator: shared.paired_comparison(
            strict_rows, PRIMARY, comparator, f"{PRIMARY} - {comparator}"
        )
        for comparator in COMPARATORS
    }
    artifact = {
        "artifact_type": "affected_versions_development_disjoint_holdout_evaluation_v1",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_independent_human_holdout_claim": False,
        "production_default_changed": False,
        "cohort_rows": len(consensus),
        "strict_determinate_rows": len(strict_rows),
        "strict_coverage": len(strict_rows) / len(consensus),
        "strict_discrepancy_counts": dict(sorted(Counter(row["discrepancy_label"] for row in strict_rows).items())),
        "strict_source_counts": dict(sorted(Counter(row["gold_source"] for row in strict_rows).items())),
        "preregistered_primary_method": PRIMARY,
        "preregistered_comparators": list(COMPARATORS),
        "method_ranking": ranking,
        "paired_primary_comparisons": paired,
        "inputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "consensus_summary": {"path": str(consensus_summary_path), "sha256": sha256(consensus_summary_path)},
            "predictions": {"path": str(prediction_path), "sha256": sha256(prediction_path)},
            "prediction_manifest": {"path": str(prediction_manifest_path), "sha256": sha256(prediction_manifest_path)},
        },
        "cautions": [
            "The cohort is CVE-disjoint from method development, but labels are dual-Codex rather than human-gold.",
            "Accuracy is conditional on strict consensus coverage and must be reported with it.",
            "No method selection or tuning is permitted from this holdout without converting it into development data.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_evaluation.json"
    output_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
