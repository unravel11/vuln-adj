#!/usr/bin/env python3
"""Build the residual worklist on the uniform strict source overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from evaluate_affected_versions_source_overlay import (
    load_jsonl,
    load_method_predictions,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/uniform_strict/"
    "rq3_affected_versions_uniform_strict_source_overlay.jsonl"
)
DEFAULT_FEATURES = (
    "results/rq3_adjudication/artifact_graph_uniform/"
    "affected_versions_artifact_graph_features.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/artifact_graph_uniform_strict"
CANONICAL = "canonical_version_token_support_baseline"
FALLBACK = "repository_crosswalk_package_gated_canonical_token_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--features", default=DEFAULT_FEATURES)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
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


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Uniform Strict Artifact-Graph Residuals",
        "",
        "This worklist is derived from a non-human, dual-Codex source overlay. It is not human-gold error analysis.",
        "",
        f"Determinate rows: `{artifact['determinate_rows']}`. Canonical-only correct: `{artifact['canonical_only_correct']}`; artifact-only correct: `{artifact['artifact_only_correct']}`; common misses: `{artifact['common_miss_count']}`.",
        "",
        "| Sample | CVE | Gold | Canonical | Artifact fallback | Base branch | Package category |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in artifact["common_misses"]:
        lines.append(
            f"| `{row['sample_id']}` | `{row['cve_id']}` | `{row['gold_source']}` | "
            f"`{row['canonical_prediction']}` | `{row['artifact_fallback_prediction']}` | "
            f"`{row['base_branch_prediction']}` | `{row['direct_package_category']}` |"
        )
    lines.extend(
        [
            "",
            "The common misses require source authority, temporal revision, and package-local range analysis. This is an inference from the residual pattern and must be validated rather than encoded as five sample-specific rules.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    overlay_path = resolve(args.overlay)
    feature_path = resolve(args.features)
    prediction_path = resolve(args.predictions)
    overlay = load_jsonl(overlay_path)
    features = load_jsonl(feature_path)
    if len(overlay) != 100 or set(overlay) != set(features):
        raise ValueError("overlay and features must cover the same 100 rows")
    methods = load_method_predictions(prediction_path, set(overlay))
    canonical = methods[CANONICAL]
    fallback = methods[FALLBACK]
    rows = []
    for sample_id, gold in overlay.items():
        if gold.get("source_gold_status") != "final_determinate":
            continue
        feature = features[sample_id]
        artifact_prediction = feature["predicted_source"]
        artifact_fallback = (
            fallback[sample_id]
            if artifact_prediction == "abstain"
            else artifact_prediction
        )
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold.get("cve_id"),
                "gold_source": gold.get("source_gold_label"),
                "canonical_prediction": canonical[sample_id],
                "artifact_fallback_prediction": artifact_fallback,
                "base_branch_prediction": feature["base_branch_graph_prediction"],
                "direct_package_category": feature["direct_package_profile"]["category"],
                "artifact_rule_changed_prediction": feature["prediction_changed"],
            }
        )
    common_misses = [
        row
        for row in rows
        if row["canonical_prediction"] != row["gold_source"]
        and row["artifact_fallback_prediction"] != row["gold_source"]
    ]
    artifact = {
        "artifact_type": "affected_versions_uniform_strict_residual_worklist",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "eligible_for_independent_holdout_claim": False,
        "inputs": {
            "overlay": {"path": str(overlay_path), "sha256": sha256(overlay_path)},
            "features": {"path": str(feature_path), "sha256": sha256(feature_path)},
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
        },
        "determinate_rows": len(rows),
        "canonical_correct": sum(
            row["canonical_prediction"] == row["gold_source"] for row in rows
        ),
        "artifact_correct": sum(
            row["artifact_fallback_prediction"] == row["gold_source"] for row in rows
        ),
        "canonical_only_correct": sum(
            row["canonical_prediction"] == row["gold_source"]
            and row["artifact_fallback_prediction"] != row["gold_source"]
            for row in rows
        ),
        "artifact_only_correct": sum(
            row["canonical_prediction"] != row["gold_source"]
            and row["artifact_fallback_prediction"] == row["gold_source"]
            for row in rows
        ),
        "both_correct": sum(
            row["canonical_prediction"] == row["gold_source"]
            and row["artifact_fallback_prediction"] == row["gold_source"]
            for row in rows
        ),
        "common_miss_count": len(common_misses),
        "common_miss_gold_counts": dict(
            sorted(Counter(row["gold_source"] for row in common_misses).items())
        ),
        "common_misses": sorted(common_misses, key=lambda row: row["sample_id"]),
        "caution": (
            "Do not encode sample-specific fixes from this selected residual set. "
            "Validate any source-authority or temporal rule on a frozen holdout."
        ),
    }
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_artifact_graph_uniform_strict_failures.json"
    md_path = output_dir / "affected_versions_artifact_graph_uniform_strict_failures.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
