#!/usr/bin/env python3
"""Evaluate gold-blind branch/release-graph features against AI-adjudicated gold."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEATURE_INPUT = (
    "results/rq3_adjudication/branch_graph/"
    "affected_versions_branch_graph_features.jsonl"
)
GOLD_INPUT = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
PREDICTIONS_INPUT = "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
CEILING_INPUT = (
    "results/ai_adjudicated_gold/affected_versions_ceiling/"
    "affected_versions_ai_gold_ceiling.json"
)
OUTPUT_DIR = "results/ai_adjudicated_gold/branch_graph"
FALLBACK_METHOD = "repository_crosswalk_package_gated_canonical_token_baseline"
REFERENCE_METHOD = "canonical_version_token_support_baseline"
BOOTSTRAP_REPLICATES = 10000
BOOTSTRAP_SEED = 20260715


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", default=FEATURE_INPUT)
    parser.add_argument("--gold", default=GOLD_INPUT)
    parser.add_argument("--predictions", default=PREDICTIONS_INPUT)
    parser.add_argument("--ceiling", default=CEILING_INPUT)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: Path, key: str = "sample_id") -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            value = row.get(key)
            if not value or value in rows:
                raise ValueError(f"{path}:{line_number}: missing/duplicate {key}")
            rows[value] = row
    return rows


def metrics(rows: list[dict], prediction_key: str) -> dict:
    covered = [row for row in rows if row[prediction_key] != "abstain"]
    correct = [row for row in rows if row[prediction_key] == row["gold_source"]]
    covered_correct = [
        row for row in covered if row[prediction_key] == row["gold_source"]
    ]
    return {
        "rows": len(rows),
        "correct": len(correct),
        "accuracy": len(correct) / len(rows) if rows else 0.0,
        "non_abstain": len(covered),
        "prediction_coverage": len(covered) / len(rows) if rows else 0.0,
        "selective_accuracy": len(covered_correct) / len(covered) if covered else 0.0,
        "prediction_counts": dict(
            sorted(Counter(row[prediction_key] for row in rows).items())
        ),
    }


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def exact_paired_pvalue(improvements: int, regressions: int) -> float:
    discordant = improvements + regressions
    if discordant == 0:
        return 1.0
    tail = min(improvements, regressions)
    probability = sum(math.comb(discordant, k) for k in range(tail + 1)) / (
        2**discordant
    )
    return min(1.0, 2.0 * probability)


def paired_uncertainty(
    rows: list[dict], candidate_key: str, reference_key: str, comparison: str
) -> dict:
    improvements = sum(
        row[candidate_key] == row["gold_source"]
        and row[reference_key] != row["gold_source"]
        for row in rows
    )
    regressions = sum(
        row[candidate_key] != row["gold_source"]
        and row[reference_key] == row["gold_source"]
        for row in rows
    )
    observed = sum(
        (row[candidate_key] == row["gold_source"])
        - (row[reference_key] == row["gold_source"])
        for row in rows
    ) / len(rows)
    strata = {}
    for index, row in enumerate(rows):
        strata.setdefault(row["gold_source"], []).append(index)
    rng = random.Random(BOOTSTRAP_SEED)
    deltas = []
    for _ in range(BOOTSTRAP_REPLICATES):
        selected = []
        for indices in strata.values():
            selected.extend(rng.choice(indices) for _ in indices)
        deltas.append(
            sum(
                (rows[index][candidate_key] == rows[index]["gold_source"])
                - (rows[index][reference_key] == rows[index]["gold_source"])
                for index in selected
            )
            / len(selected)
        )
    return {
        "comparison": comparison,
        "observed_accuracy_delta": observed,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "stratification": "ai_gold_source",
        "percentile_95_interval": [
            percentile(deltas, 0.025),
            percentile(deltas, 0.975),
        ],
        "improvements": improvements,
        "regressions": regressions,
        "both_correct": sum(
            row[candidate_key] == row["gold_source"]
            and row[reference_key] == row["gold_source"]
            for row in rows
        ),
        "both_wrong": sum(
            row[candidate_key] != row["gold_source"]
            and row[reference_key] != row["gold_source"]
            for row in rows
        ),
        "exact_paired_two_sided_pvalue": exact_paired_pvalue(
            improvements, regressions
        ),
        "confirmatory_inference_supported": False,
    }


def markdown(artifact: dict) -> str:
    det = artifact["determinate_ai_gold"]
    common = artifact["prior_seven_method_common_misses"]
    versus_release = artifact["paired_exploratory_comparisons"][
        "branch_hybrid_vs_release_boundary_hybrid"
    ]
    lines = [
        "# Affected_versions branch/release-graph diagnostic",
        "",
        "This is a post-hoc AI-gold diagnostic. Feature extraction is gold-blind, but the representation was designed after residual error inspection. It is not human-gold performance and does not support a production method change.",
        "",
        "## Determinate AI-gold rows",
        "",
        "| Method | Correct | Accuracy | Coverage | Selective accuracy |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in (
        "canonical_token_reference",
        "release_boundary",
        "branch_release_graph",
        "branch_graph_then_crosswalk_canonical",
    ):
        metric = det[name]
        lines.append(
            f"| `{name}` | {metric['correct']}/{metric['rows']} | "
            f"{metric['accuracy']:.4f} | {metric['prediction_coverage']:.4f} | "
            f"{metric['selective_accuracy']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Increment over release-boundary hybrid",
            "",
            (
                f"The branch-graph hybrid changes accuracy by "
                f"`{versus_release['observed_accuracy_delta'] * 100:+.2f}pp` "
                f"with a stratified percentile interval of "
                f"`[{versus_release['percentile_95_interval'][0] * 100:+.2f}, "
                f"{versus_release['percentile_95_interval'][1] * 100:+.2f}]pp`; "
                f"there are `{versus_release['improvements']}` improvements and "
                f"`{versus_release['regressions']}` regressions, exact paired "
                f"two-sided p=`{versus_release['exact_paired_two_sided_pvalue']:.4f}`."
            ),
            "",
            "## Prior seven-method common misses",
            "",
            (
                f"The branch/release-graph diagnostic matches "
                f"`{common['newly_correct']}/{common['rows']}` prior common misses. "
                f"The post-hoc union oracle rises from "
                f"`{common['prior_union_correct']}/{det['rows']}` to "
                f"`{common['union_with_branch_graph_correct']}/{det['rows']}`; "
                "this oracle is not deployable."
            ),
            "",
            "## Boundary",
            "",
            "The candidate adds only conservative structural events for opaque ordinal exceptions, adjacent prerelease boundaries, and explicit endpoint versus open-ended spans. Source conflicts, temporal revisions, ecosystem-specific ordering, and multi-branch snapshot repair remain unresolved.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    feature_path = resolve(args.features)
    gold_path = resolve(args.gold)
    prediction_path = resolve(args.predictions)
    ceiling_path = resolve(args.ceiling)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    features = load_jsonl(feature_path)
    gold = load_jsonl(gold_path)
    if len(features) != 100 or len(gold) != 100 or set(features) != set(gold):
        raise ValueError("feature/gold coverage must be the same 100 sample IDs")
    if any(row.get("feature_extraction_uses_gold") is not False for row in features.values()):
        raise ValueError("feature artifact does not preserve gold-blind provenance")
    if any(row.get("label_is_human") is not False for row in gold.values()):
        raise ValueError("expected AI-adjudicated, non-human gold")

    method_predictions = {FALLBACK_METHOD: {}, REFERENCE_METHOD: {}}
    with prediction_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            method = row.get("method")
            if method in method_predictions:
                method_predictions[method][row["sample_id"]] = row["predicted_source"]
    if any(set(values) != set(features) for values in method_predictions.values()):
        raise ValueError("reference/fallback prediction coverage mismatch")

    rows = []
    for sample_id in sorted(features):
        feature = features[sample_id]
        gold_row = gold[sample_id]
        release = feature["base_release_boundary_prediction"]
        branch = feature["predicted_source"]
        fallback = method_predictions[FALLBACK_METHOD][sample_id]
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold_row.get("cve_id"),
                "ai_gold_status": gold_row.get("ai_gold_status"),
                "gold_source": gold_row.get("annotation", {}).get(
                    "adjudicated_source"
                ),
                "reference_prediction": method_predictions[REFERENCE_METHOD][
                    sample_id
                ],
                "fallback_prediction": fallback,
                "release_boundary_prediction": release,
                "release_hybrid_prediction": release if release != "abstain" else fallback,
                "branch_graph_prediction": branch,
                "branch_hybrid_prediction": branch if branch != "abstain" else fallback,
                "prediction_reason": feature["prediction_reason"],
                "capability_flags": feature["capability_flags"],
            }
        )
    determinate = [row for row in rows if row["ai_gold_status"] == "final_determinate"]
    if len(determinate) != 40:
        raise ValueError(f"expected 40 determinate AI-gold rows, found {len(determinate)}")

    ceiling = json.loads(ceiling_path.read_text(encoding="utf-8"))
    common_ids = {
        row["sample_id"]
        for row in ceiling["tested_method_union_oracle"]["no_method_correct_rows"]
    }
    common_rows = [row for row in determinate if row["sample_id"] in common_ids]
    prior_correct_ids = {
        row["sample_id"] for row in determinate if row["sample_id"] not in common_ids
    }
    branch_correct_ids = {
        row["sample_id"]
        for row in determinate
        if row["branch_graph_prediction"] == row["gold_source"]
    }
    release_correct_ids = {
        row["sample_id"]
        for row in determinate
        if row["release_boundary_prediction"] == row["gold_source"]
    }
    all_flag_counts = Counter()
    for feature in features.values():
        all_flag_counts.update(feature["capability_flags"])

    artifact = {
        "artifact_type": "affected_versions_branch_graph_ai_gold_diagnostic",
        "label_is_human": False,
        "feature_extraction_uses_gold": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "post_hoc_exploratory": True,
        "production_default_changed": False,
        "inputs": {
            "features": {"path": str(feature_path), "sha256": sha256(feature_path)},
            "gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
            "ceiling": {"path": str(ceiling_path), "sha256": sha256(ceiling_path)},
        },
        "gold_coverage": {"determinate": 40, "total": 100, "rate": 0.4},
        "determinate_ai_gold": {
            "rows": len(determinate),
            "canonical_token_reference": metrics(determinate, "reference_prediction"),
            "release_boundary": metrics(determinate, "release_boundary_prediction"),
            "branch_release_graph": metrics(determinate, "branch_graph_prediction"),
            "branch_graph_then_crosswalk_canonical": metrics(
                determinate, "branch_hybrid_prediction"
            ),
        },
        "paired_exploratory_comparisons": {
            "branch_hybrid_vs_canonical_token": paired_uncertainty(
                determinate,
                "branch_hybrid_prediction",
                "reference_prediction",
                "branch_graph_then_crosswalk_canonical - canonical_version_token_support_baseline",
            ),
            "branch_hybrid_vs_release_boundary_hybrid": paired_uncertainty(
                determinate,
                "branch_hybrid_prediction",
                "release_hybrid_prediction",
                "branch_graph_then_crosswalk_canonical - release_boundary_then_crosswalk_canonical",
            ),
        },
        "prior_seven_method_common_misses": {
            "rows": len(common_rows),
            "newly_correct": sum(
                row["branch_graph_prediction"] == row["gold_source"]
                for row in common_rows
            ),
            "prior_union_correct": len(prior_correct_ids),
            "union_with_release_boundary_correct": len(
                prior_correct_ids | release_correct_ids
            ),
            "union_with_branch_graph_correct": len(
                prior_correct_ids | branch_correct_ids
            ),
            "residual_rows": [
                row
                for row in common_rows
                if row["branch_graph_prediction"] != row["gold_source"]
            ],
            "row_diagnostics": common_rows,
        },
        "capability_profile_all_100": {
            "flag_counts": dict(sorted(all_flag_counts.items())),
            "rows_with_any_flag": sum(
                bool(feature["capability_flags"]) for feature in features.values()
            ),
        },
        "cautions": [
            "The representation is gold-blind, but its structural rules were selected after residual error inspection.",
            "All accuracy values are conditional on 40 determinate AI-adjudicated rows; 60 final-abstain rows have no accuracy target.",
            "Leading numeric ordinals do not establish complete ordering for opaque ecosystem versions.",
            "Source conflicts, temporal revisions, multi-branch snapshot repair, and ecosystem-specific ordering remain unresolved.",
            "The candidate and post-hoc union results do not justify changing production defaults.",
        ],
    }
    json_path = output_dir / "affected_versions_branch_graph_ai_gold_diagnostic.json"
    md_path = output_dir / "affected_versions_branch_graph_ai_gold_diagnostic.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
