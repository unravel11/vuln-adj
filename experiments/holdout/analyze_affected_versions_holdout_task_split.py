#!/usr/bin/env python3
"""Post-hoc split of discrepancy typing and source adjudication on the holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/ai_adjudicated_gold"))

import evaluate_affected_versions_source_overlay as shared  # noqa: E402


DEFAULT_CONSENSUS = (
    "results/holdout/affected_versions_v1/affected_versions_holdout_consensus.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/holdout/affected_versions_v1/sealed_predictions/"
    "affected_versions_holdout_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v1/posthoc_task_split"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def method_ranking(rows: list[dict], methods: set[str]) -> list[dict]:
    ranking = [{"method": method, **shared.metrics(rows, method)} for method in sorted(methods)]
    ranking.sort(
        key=lambda row: (
            row["accuracy"],
            row["macro_f1_over_supported_labels"],
            row["prediction_coverage"],
            row["method"],
        ),
        reverse=True,
    )
    return ranking


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Versions Holdout Task Split",
        "",
        "This analysis was defined after holdout labels were unsealed. It diagnoses an evaluation-protocol issue and is not a preregistered method-selection result.",
        "",
        f"Strict joint consensus covers `{artifact['strict_rows']}/{artifact['cohort_rows']}` rows. Only `{artifact['factual_conflict_rows']}` strict rows remain factual conflicts; `{artifact['non_conflict_rows']}` are strict baseline false-positive candidates.",
        "",
        "## Factual-conflict source adjudication",
        "",
        "| Method | Correct | Accuracy | Prediction coverage | Selective accuracy |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in artifact["factual_conflict_method_ranking"]:
        lines.append(
            f"| `{row['method']}` | {row['correct']}/{row['rows']} | {row['accuracy']:.4f} | "
            f"{row['prediction_coverage']:.4f} | {row['selective_accuracy']:.4f} |"
        )
    lines.extend(
        [
            "",
            "All-strict source accuracy is retained as the preregistered result, but it conflates discrepancy typing with source adjudication because representation-discrepancy rows all have source `both`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    consensus_path = resolve(args.consensus)
    prediction_path = resolve(args.predictions)
    output_dir = resolve(args.output_dir)
    consensus = load_jsonl(consensus_path)
    prediction_rows = load_jsonl(prediction_path)
    predictions: dict[str, dict[str, str]] = {}
    methods = set()
    for row in prediction_rows:
        predictions.setdefault(row["sample_id"], {})[row["method"]] = row["predicted_source"]
        methods.add(row["method"])

    strict = []
    for gold in consensus:
        if gold["consensus_status"] != "strict_determinate":
            continue
        strict.append(
            {
                "sample_id": gold["sample_id"],
                "gold_source": gold["adjudicated_source"],
                "discrepancy_label": gold["discrepancy_label"],
                "predictions": predictions[gold["sample_id"]],
            }
        )
    factual = [row for row in strict if row["discrepancy_label"] == "factual_conflict"]
    non_conflict = [row for row in strict if row["discrepancy_label"] != "factual_conflict"]
    if len(strict) != 35 or len(factual) != 16 or len(non_conflict) != 19:
        raise ValueError("expected frozen strict split 35 = 16 factual + 19 non-conflict")

    artifact = {
        "artifact_type": "affected_versions_holdout_posthoc_task_split_v1",
        "analysis_is_posthoc": True,
        "protocol_issue_discovered_after_unseal": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "cohort_rows": len(consensus),
        "strict_rows": len(strict),
        "factual_conflict_rows": len(factual),
        "non_conflict_rows": len(non_conflict),
        "strict_conditional_factual_conflict_fraction": len(factual) / len(strict),
        "strict_label_counts": dict(sorted(Counter(row["discrepancy_label"] for row in strict).items())),
        "factual_conflict_source_counts": dict(sorted(Counter(row["gold_source"] for row in factual).items())),
        "all_strict_method_ranking": method_ranking(strict, methods),
        "factual_conflict_method_ranking": method_ranking(factual, methods),
        "non_conflict_method_ranking": method_ranking(non_conflict, methods),
        "inputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "predictions": {"path": str(prediction_path), "sha256": sha256(prediction_path)},
        },
        "interpretation": [
            "Source adjudication should be evaluated on rows whose discrepancy type is factual_conflict.",
            "The preregistered all-strict metric mixes discrepancy typing and source adjudication.",
            "Representation-discrepancy strict rows all use source both, which favors token methods that overpredict both.",
            "Future protocols must preregister discrepancy detection and source adjudication as separate endpoints.",
        ],
        "cautions": [
            "The task split was analyzed after labels were unsealed.",
            "Only 16 factual-conflict rows have strict dual-Codex consensus.",
            "Both reviewers are Codex agents; real human signoff remains required.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_holdout_task_split.json"
    md_path = output_dir / "affected_versions_holdout_task_split.md"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
