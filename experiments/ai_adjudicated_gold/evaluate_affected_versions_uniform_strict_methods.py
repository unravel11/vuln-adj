#!/usr/bin/env python3
"""Benchmark all current methods on the uniform strict source overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import evaluate_affected_versions_source_overlay as source_overlay_eval
from evaluate_affected_versions_source_overlay import (
    load_jsonl,
    load_method_predictions,
    metrics,
    paired_comparison,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/uniform_strict/"
    "rq3_affected_versions_uniform_strict_source_overlay.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/uniform_evidence_baselines/"
    "affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_FEATURES = (
    "results/rq3_adjudication/artifact_graph_uniform/"
    "affected_versions_artifact_graph_features.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit/uniform_strict"
RAW = "version_token_support_baseline"
CANONICAL = "canonical_version_token_support_baseline"
FALLBACK = "repository_crosswalk_package_gated_canonical_token_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--features", default=DEFAULT_FEATURES)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260715)
    parser.add_argument("--minimum-selective-coverage", type=float, default=0.5)
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


def render_markdown(artifact: dict) -> str:
    best_full = ", ".join(
        f"`{method}`" for method in artifact["best_full_accuracy_methods"]
    )
    best_selective = ", ".join(
        f"`{method}`"
        for method in artifact["best_selective_methods_at_minimum_coverage"]
    )
    lines = [
        "# Affected-Version Uniform Strict Method Benchmark",
        "",
        "This benchmark uses a non-human dual-Codex source overlay and a selection-aware evidence refresh. It is not human-gold or independent holdout performance.",
        "",
        f"Strict source coverage is `{artifact['strict_source_coverage']['determinate']}/{artifact['strict_source_coverage']['total']}`. The best full-accuracy method(s): {best_full}. The best selective method(s) with prediction coverage >= `{artifact['minimum_selective_coverage']:.2f}`: {best_selective}.",
        "",
        "| Method | Correct | Accuracy | Macro-F1 | Prediction coverage | Selective accuracy |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in artifact["method_ranking"]:
        lines.append(
            f"| `{row['method']}` | {row['correct']}/{row['rows']} | "
            f"{row['accuracy']:.4f} | {row['macro_f1_over_supported_labels']:.4f} | "
            f"{row['prediction_coverage']:.4f} | {row['selective_accuracy']:.4f} |"
        )
    paired = artifact["paired_raw_vs_canonical"]
    lines.extend(
        [
            "",
            f"Raw versus canonical accuracy delta is `{paired['observed_accuracy_delta']:.4f}` with 95% interval `[{paired['percentile_95_interval'][0]:.4f}, {paired['percentile_95_interval'][1]:.4f}]`, improvements/regressions `{paired['improvements']}/{paired['regressions']}`, exact p=`{paired['exact_paired_two_sided_pvalue']:.4f}`.",
            "",
            "All inference is exploratory and conditional on the selected AI overlay. Production defaults remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    overlay_path = resolve(args.overlay)
    prediction_path = resolve(args.predictions)
    feature_path = resolve(args.features)
    output_dir = resolve(args.output_dir)
    overlay = load_jsonl(overlay_path)
    features = load_jsonl(feature_path)
    if len(overlay) != 100 or set(overlay) != set(features):
        raise ValueError("overlay and features must cover the same 100 rows")
    methods = load_method_predictions(prediction_path, set(overlay))
    methods["branch_release_graph"] = {
        sample_id: row["base_branch_graph_prediction"]
        for sample_id, row in features.items()
    }
    methods["artifact_bound_branch_graph"] = {
        sample_id: row["predicted_source"] for sample_id, row in features.items()
    }
    methods["branch_graph_then_crosswalk_canonical"] = {
        sample_id: (
            methods[FALLBACK][sample_id]
            if methods["branch_release_graph"][sample_id] == "abstain"
            else methods["branch_release_graph"][sample_id]
        )
        for sample_id in overlay
    }
    methods["artifact_graph_then_crosswalk_canonical"] = {
        sample_id: (
            methods[FALLBACK][sample_id]
            if methods["artifact_bound_branch_graph"][sample_id] == "abstain"
            else methods["artifact_bound_branch_graph"][sample_id]
        )
        for sample_id in overlay
    }

    rows = []
    for sample_id, gold in overlay.items():
        if gold.get("source_gold_status") != "final_determinate":
            continue
        rows.append(
            {
                "sample_id": sample_id,
                "gold_source": gold.get("source_gold_label"),
                "predictions": {
                    method: predictions[sample_id]
                    for method, predictions in methods.items()
                },
            }
        )
    if len(rows) != 31:
        raise ValueError(f"expected 31 uniform strict rows, found {len(rows)}")

    method_metrics = {method: metrics(rows, method) for method in sorted(methods)}
    ranking = [
        {"method": method, **values} for method, values in method_metrics.items()
    ]
    ranking.sort(
        key=lambda row: (
            row["accuracy"],
            row["macro_f1_over_supported_labels"],
            row["prediction_coverage"],
            row["method"],
        ),
        reverse=True,
    )
    selective_candidates = [
        row
        for row in ranking
        if row["prediction_coverage"] >= args.minimum_selective_coverage
    ]
    selective_candidates.sort(
        key=lambda row: (
            row["selective_accuracy"],
            row["prediction_coverage"],
            row["accuracy"],
            row["method"],
        ),
        reverse=True,
    )
    best_full_accuracy = ranking[0]["accuracy"]
    best_selective_accuracy = selective_candidates[0]["selective_accuracy"]
    source_overlay_eval.BOOTSTRAP_REPLICATES = args.bootstrap_replicates
    source_overlay_eval.BOOTSTRAP_SEED = args.bootstrap_seed
    artifact = {
        "artifact_type": "affected_versions_uniform_strict_method_benchmark",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "eligible_for_independent_holdout_claim": False,
        "production_default_changed": False,
        "inputs": {
            "overlay": {"path": str(overlay_path), "sha256": sha256(overlay_path)},
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
            "features": {"path": str(feature_path), "sha256": sha256(feature_path)},
        },
        "strict_source_coverage": {"determinate": len(rows), "total": 100, "rate": len(rows) / 100},
        "minimum_selective_coverage": args.minimum_selective_coverage,
        "method_ranking": ranking,
        "best_full_accuracy_methods": [
            row["method"]
            for row in ranking
            if row["accuracy"] == best_full_accuracy
        ],
        "best_selective_methods_at_minimum_coverage": [
            row["method"]
            for row in selective_candidates
            if row["selective_accuracy"] == best_selective_accuracy
        ],
        "paired_raw_vs_canonical": paired_comparison(
            rows, RAW, CANONICAL, "raw token - canonical token"
        ),
        "cautions": [
            "The strict source overlay is produced by Codex agents, not human annotators.",
            "Agent B disclosed that one full candidate object was visible during schema inspection; the prior source was not used as evidence, but perfect blinding is not claimed.",
            "Evidence refresh and source selection are conditioned on prior AI-gold status.",
            "The artifact rule was designed after inspecting strict-addition failures.",
            "Accuracy and selective accuracy should not be compared without reporting prediction coverage.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_uniform_strict_method_benchmark.json"
    md_path = output_dir / "affected_versions_uniform_strict_method_benchmark.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
