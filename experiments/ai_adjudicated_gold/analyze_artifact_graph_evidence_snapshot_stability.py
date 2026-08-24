#!/usr/bin/env python3
"""Measure branch/artifact prediction drift after the selection-aware refresh."""

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
DEFAULT_FROZEN_BRANCH = (
    "results/rq3_adjudication/branch_graph/"
    "affected_versions_branch_graph_features.jsonl"
)
DEFAULT_MIXED_ARTIFACT = (
    "results/rq3_adjudication/artifact_graph/"
    "affected_versions_artifact_graph_features.jsonl"
)
DEFAULT_REFRESHED_ARTIFACT = (
    "results/rq3_adjudication/artifact_graph_uniform/"
    "affected_versions_artifact_graph_features.jsonl"
)
DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/artifact_graph_snapshot_stability"
FALLBACK_METHOD = "repository_crosswalk_package_gated_canonical_token_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frozen-branch", default=DEFAULT_FROZEN_BRANCH)
    parser.add_argument("--mixed-artifact", default=DEFAULT_MIXED_ARTIFACT)
    parser.add_argument("--refreshed-artifact", default=DEFAULT_REFRESHED_ARTIFACT)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
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


def with_fallback(predictions: dict[str, str], fallback: dict[str, str]) -> dict[str, str]:
    return {
        sample_id: fallback[sample_id] if value == "abstain" else value
        for sample_id, value in predictions.items()
    }


def comparison(
    before: dict[str, str],
    after: dict[str, str],
    overlay: dict[str, dict],
) -> dict:
    changed = [sample_id for sample_id in before if before[sample_id] != after[sample_id]]
    determinate = [
        sample_id
        for sample_id, row in overlay.items()
        if row.get("source_gold_status") == "final_determinate"
    ]
    before_correct = sum(
        before[sample_id] == overlay[sample_id]["source_gold_label"]
        for sample_id in determinate
    )
    after_correct = sum(
        after[sample_id] == overlay[sample_id]["source_gold_label"]
        for sample_id in determinate
    )
    improvements = sum(
        after[sample_id] == overlay[sample_id]["source_gold_label"]
        and before[sample_id] != overlay[sample_id]["source_gold_label"]
        for sample_id in determinate
    )
    regressions = sum(
        after[sample_id] != overlay[sample_id]["source_gold_label"]
        and before[sample_id] == overlay[sample_id]["source_gold_label"]
        for sample_id in determinate
    )
    return {
        "rows": len(before),
        "changed_rows": len(changed),
        "changed_sample_ids": sorted(changed),
        "transition_counts": [
            {"before": left, "after": right, "count": count}
            for (left, right), count in sorted(
                Counter((before[sid], after[sid]) for sid in changed).items()
            )
        ],
        "legacy_overlay_determinate_rows": len(determinate),
        "before_correct": before_correct,
        "after_correct": after_correct,
        "improvements": improvements,
        "regressions": regressions,
    }


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Version Evidence Snapshot Stability",
        "",
        "The refreshed snapshot is selection-aware. These counts diagnose prediction drift; they are not independent performance estimates.",
        "",
        "| Method | Changed / 100 | Before correct / 44 | After correct / 44 | Improvements | Regressions |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, values in artifact["comparisons"].items():
        lines.append(
            f"| `{name}` | {values['changed_rows']} | {values['before_correct']} | "
            f"{values['after_correct']} | {values['improvements']} | {values['regressions']} |"
        )
    lines.extend(
        [
            "",
            "The legacy 44-row overlay mixes the original 40 labels with four strict additions. A separate uniform strict overlay is required before interpreting the refreshed snapshot as method accuracy.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        "frozen_branch": resolve(args.frozen_branch),
        "mixed_artifact": resolve(args.mixed_artifact),
        "refreshed_artifact": resolve(args.refreshed_artifact),
        "overlay": resolve(args.overlay),
        "predictions": resolve(args.predictions),
    }
    frozen_branch_rows = load_jsonl(paths["frozen_branch"])
    mixed_artifact_rows = load_jsonl(paths["mixed_artifact"])
    refreshed_rows = load_jsonl(paths["refreshed_artifact"])
    overlay = load_jsonl(paths["overlay"])
    if not (
        len(frozen_branch_rows)
        == len(mixed_artifact_rows)
        == len(refreshed_rows)
        == len(overlay)
        == 100
    ) or not (
        set(frozen_branch_rows)
        == set(mixed_artifact_rows)
        == set(refreshed_rows)
        == set(overlay)
    ):
        raise ValueError("stability inputs must cover the same 100 rows")
    methods = load_method_predictions(paths["predictions"], set(overlay))
    fallback = methods[FALLBACK_METHOD]
    frozen_branch = {
        sample_id: row["predicted_source"]
        for sample_id, row in frozen_branch_rows.items()
    }
    refreshed_branch = {
        sample_id: row["base_branch_graph_prediction"]
        for sample_id, row in refreshed_rows.items()
    }
    mixed_artifact = {
        sample_id: row["predicted_source"]
        for sample_id, row in mixed_artifact_rows.items()
    }
    refreshed_artifact = {
        sample_id: row["predicted_source"] for sample_id, row in refreshed_rows.items()
    }
    comparisons = {
        "branch_raw": comparison(frozen_branch, refreshed_branch, overlay),
        "branch_fixed_fallback": comparison(
            with_fallback(frozen_branch, fallback),
            with_fallback(refreshed_branch, fallback),
            overlay,
        ),
        "artifact_raw": comparison(mixed_artifact, refreshed_artifact, overlay),
        "artifact_fixed_fallback": comparison(
            with_fallback(mixed_artifact, fallback),
            with_fallback(refreshed_artifact, fallback),
            overlay,
        ),
    }
    artifact = {
        "artifact_type": "affected_versions_evidence_snapshot_stability",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "eligible_for_independent_holdout_claim": False,
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
        },
        "comparisons": comparisons,
        "cautions": [
            "The refreshed evidence selection uses prior AI-gold status.",
            "The 44-row legacy overlay does not use one uniform strict adjudication process.",
            "Prediction drift can reflect parser sensitivity, changed pages, or newly usable evidence.",
        ],
    }
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_evidence_snapshot_stability.json"
    md_path = output_dir / "affected_versions_evidence_snapshot_stability.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
