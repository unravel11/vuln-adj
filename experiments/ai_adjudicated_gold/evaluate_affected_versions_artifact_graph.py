#!/usr/bin/env python3
"""Evaluate the artifact-bound graph on the 40/4/44 source-overlay cohorts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import evaluate_affected_versions_source_overlay as source_overlay_eval
from evaluate_affected_versions_source_overlay import (
    SOURCE_LABELS,
    load_jsonl,
    load_method_predictions,
    metrics,
    paired_comparison,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_FEATURES = (
    "results/rq3_adjudication/artifact_graph/"
    "affected_versions_artifact_graph_features.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/artifact_graph"
FALLBACK_METHOD = "repository_crosswalk_package_gated_canonical_token_baseline"
CANONICAL_METHOD = "canonical_version_token_support_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--features", default=DEFAULT_FEATURES)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260715)
    parser.add_argument(
        "--cohort-contract",
        choices=("legacy_mixed", "uniform_strict"),
        default="legacy_mixed",
    )
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Version Artifact-Bound Graph Diagnostic",
        "",
        "This is a selection-aware, non-human AI source-overlay diagnostic. It is not independent holdout or final-paper performance.",
        "",
        "| Cohort | Rows | Canonical | Branch fallback | Artifact graph | Artifact fallback |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    method_names = [
        CANONICAL_METHOD,
        "branch_graph_then_crosswalk_canonical",
        "artifact_bound_branch_graph",
        "artifact_graph_then_crosswalk_canonical",
    ]
    for name in ("original_base", "strict_reaudit_added", "combined"):
        cohort = artifact["cohorts"][name]
        values = [cohort["methods"][method]["correct"] for method in method_names]
        lines.append(
            f"| {name} | {cohort['rows']} | "
            + " | ".join(str(value) for value in values)
            + " |"
        )
    combined = artifact["cohorts"]["combined"]
    versus_branch = combined["paired_artifact_fallback_vs_branch_fallback"]
    versus_canonical = combined["paired_artifact_fallback_vs_canonical"]
    lines.extend(
        [
            "",
            "## Combined paired diagnostics",
            "",
            f"- Versus branch fallback: delta `{versus_branch['observed_accuracy_delta']:.4f}`, 95% interval `[{versus_branch['percentile_95_interval'][0]:.4f}, {versus_branch['percentile_95_interval'][1]:.4f}]`, improvements/regressions `{versus_branch['improvements']}/{versus_branch['regressions']}`, exact p=`{versus_branch['exact_paired_two_sided_pvalue']:.4f}`.",
            f"- Versus canonical: delta `{versus_canonical['observed_accuracy_delta']:.4f}`, 95% interval `[{versus_canonical['percentile_95_interval'][0]:.4f}, {versus_canonical['percentile_95_interval'][1]:.4f}]`, improvements/regressions `{versus_canonical['improvements']}/{versus_canonical['regressions']}`, exact p=`{versus_canonical['exact_paired_two_sided_pvalue']:.4f}`.",
            "",
            "## Boundary",
            "",
            "The rule was designed after inspecting cross-artifact failures, and its evidence overlay refresh selection uses prior AI-gold status. The strict four-row cohort is diagnostic, not an independent generalization set.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    source_overlay_eval.BOOTSTRAP_REPLICATES = args.bootstrap_replicates
    source_overlay_eval.BOOTSTRAP_SEED = args.bootstrap_seed
    overlay_path = resolve(args.overlay)
    feature_path = resolve(args.features)
    prediction_path = resolve(args.predictions)
    output_dir = resolve(args.output_dir)
    overlay = load_jsonl(overlay_path)
    features = load_jsonl(feature_path)
    if len(overlay) != 100 or set(overlay) != set(features):
        raise ValueError("overlay and artifact features must cover the same 100 rows")
    if any(row.get("feature_extraction_uses_gold_labels") is not False for row in features.values()):
        raise ValueError("artifact features must not read gold labels")
    if any(row.get("feature_input_selection_uses_ai_gold_status") is not True for row in features.values()):
        raise ValueError("selection-aware evidence provenance is missing")

    methods = load_method_predictions(prediction_path, set(overlay))
    if FALLBACK_METHOD not in methods or CANONICAL_METHOD not in methods:
        raise ValueError("required canonical/fallback predictions are missing")
    methods["branch_release_graph"] = {
        sample_id: row["base_branch_graph_prediction"]
        for sample_id, row in features.items()
    }
    methods["artifact_bound_branch_graph"] = {
        sample_id: row["predicted_source"] for sample_id, row in features.items()
    }
    methods["branch_graph_then_crosswalk_canonical"] = {
        sample_id: (
            methods[FALLBACK_METHOD][sample_id]
            if methods["branch_release_graph"][sample_id] == "abstain"
            else methods["branch_release_graph"][sample_id]
        )
        for sample_id in overlay
    }
    methods["artifact_graph_then_crosswalk_canonical"] = {
        sample_id: (
            methods[FALLBACK_METHOD][sample_id]
            if methods["artifact_bound_branch_graph"][sample_id] == "abstain"
            else methods["artifact_bound_branch_graph"][sample_id]
        )
        for sample_id in overlay
    }

    rows = []
    for sample_id, gold in overlay.items():
        label = gold.get("source_gold_label")
        status = gold.get("source_gold_status")
        if label is not None and label not in SOURCE_LABELS:
            raise ValueError(f"{sample_id}: invalid source gold label")
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold.get("cve_id"),
                "gold_source": label,
                "gold_status": status,
                "source_decision_origin": gold.get("source_decision_origin"),
                "predictions": {
                    method: predictions[sample_id]
                    for method, predictions in methods.items()
                },
            }
        )

    if args.cohort_contract == "legacy_mixed":
        cohorts = {
            "original_base": [
                row
                for row in rows
                if row["source_decision_origin"]
                == "existing_ai_gold_final_determinate"
            ],
            "strict_reaudit_added": [
                row
                for row in rows
                if row["source_decision_origin"]
                == "dual_agent_strict_source_reaudit"
            ],
            "combined": [
                row for row in rows if row["gold_status"] == "final_determinate"
            ],
        }
        expected = {"original_base": 40, "strict_reaudit_added": 4, "combined": 44}
    else:
        cohorts = {
            "original_base": [
                row
                for row in rows
                if row["source_decision_origin"]
                == "uniform_strict_original_determinate"
            ],
            "strict_reaudit_added": [
                row
                for row in rows
                if row["source_decision_origin"]
                == "uniform_strict_prior_abstain_addition"
            ],
            "combined": [
                row for row in rows if row["gold_status"] == "final_determinate"
            ],
        }
        expected = {
            "original_base": len(cohorts["original_base"]),
            "strict_reaudit_added": len(cohorts["strict_reaudit_added"]),
            "combined": len(cohorts["combined"]),
        }
        if expected["combined"] != (
            expected["original_base"] + expected["strict_reaudit_added"]
        ):
            raise ValueError("uniform strict cohorts do not partition determinate rows")
    evaluated_methods = [
        CANONICAL_METHOD,
        "branch_release_graph",
        "branch_graph_then_crosswalk_canonical",
        "artifact_bound_branch_graph",
        "artifact_graph_then_crosswalk_canonical",
    ]
    cohort_artifacts = {}
    for name, cohort_rows in cohorts.items():
        if len(cohort_rows) != expected[name]:
            raise ValueError(f"{name}: expected {expected[name]} rows")
        cohort_artifacts[name] = {
            "rows": len(cohort_rows),
            "gold_source_counts": dict(
                sorted(Counter(row["gold_source"] for row in cohort_rows).items())
            ),
            "methods": {
                method: metrics(cohort_rows, method) for method in evaluated_methods
            },
            "paired_artifact_fallback_vs_branch_fallback": paired_comparison(
                cohort_rows,
                "artifact_graph_then_crosswalk_canonical",
                "branch_graph_then_crosswalk_canonical",
                "artifact fallback - branch fallback",
            ),
            "paired_artifact_fallback_vs_canonical": paired_comparison(
                cohort_rows,
                "artifact_graph_then_crosswalk_canonical",
                CANONICAL_METHOD,
                "artifact fallback - canonical",
            ),
        }

    changed = [row for row in features.values() if row["prediction_changed"]]
    artifact = {
        "artifact_type": "affected_versions_artifact_graph_diagnostic",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "eligible_for_independent_holdout_claim": False,
        "production_default_changed": False,
        "feature_input_selection_uses_ai_gold_status": True,
        "cohort_contract": args.cohort_contract,
        "inputs": {
            "overlay": {"path": str(overlay_path), "sha256": sha256(overlay_path)},
            "features": {"path": str(feature_path), "sha256": sha256(feature_path)},
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
        },
        "changed_rows": len(changed),
        "changed_sample_ids": sorted(row["sample_id"] for row in changed),
        "cohorts": cohort_artifacts,
        "cautions": [
            "The source overlay and reviewer decisions are AI provenance, not human gold.",
            "The rule was designed after inspecting the four strict source-overlay failures.",
            "The 45-row evidence refresh selection uses prior AI-gold status.",
            "The original 40 and added 4 rows were not adjudicated under one uniform process.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_artifact_graph_diagnostic.json"
    md_path = output_dir / "affected_versions_artifact_graph_diagnostic.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
