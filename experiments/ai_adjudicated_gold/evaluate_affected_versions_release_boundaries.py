#!/usr/bin/env python3
"""Evaluate gold-blind release-boundary features against AI-adjudicated gold."""

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
    "results/rq3_adjudication/release_boundary/"
    "affected_versions_release_boundary_features.jsonl"
)
GOLD_INPUT = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
PREDICTIONS_INPUT = "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
CEILING_INPUT = (
    "results/ai_adjudicated_gold/affected_versions_ceiling/"
    "affected_versions_ai_gold_ceiling.json"
)
OUTPUT_DIR = "results/ai_adjudicated_gold/release_boundary"
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
    covered = [r for r in rows if r[prediction_key] != "abstain"]
    correct = [r for r in rows if r[prediction_key] == r["gold_source"]]
    covered_correct = [r for r in covered if r[prediction_key] == r["gold_source"]]
    return {
        "rows": len(rows),
        "correct": len(correct),
        "accuracy": len(correct) / len(rows) if rows else 0.0,
        "non_abstain": len(covered),
        "prediction_coverage": len(covered) / len(rows) if rows else 0.0,
        "selective_accuracy": len(covered_correct) / len(covered) if covered else 0.0,
        "prediction_counts": dict(sorted(Counter(r[prediction_key] for r in rows).items())),
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
    probability = sum(math.comb(discordant, k) for k in range(tail + 1)) / (2**discordant)
    return min(1.0, 2.0 * probability)


def paired_uncertainty(rows: list[dict]) -> dict:
    improvements = sum(
        r["hybrid_prediction"] == r["gold_source"]
        and r["reference_prediction"] != r["gold_source"]
        for r in rows
    )
    regressions = sum(
        r["hybrid_prediction"] != r["gold_source"]
        and r["reference_prediction"] == r["gold_source"]
        for r in rows
    )
    observed = sum(
        (r["hybrid_prediction"] == r["gold_source"])
        - (r["reference_prediction"] == r["gold_source"])
        for r in rows
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
        delta = sum(
            (rows[index]["hybrid_prediction"] == rows[index]["gold_source"])
            - (rows[index]["reference_prediction"] == rows[index]["gold_source"])
            for index in selected
        ) / len(selected)
        deltas.append(delta)
    return {
        "comparison": f"boundary_then_crosswalk_canonical - {REFERENCE_METHOD}",
        "observed_accuracy_delta": observed,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "stratification": "ai_gold_source",
        "percentile_95_interval": [percentile(deltas, 0.025), percentile(deltas, 0.975)],
        "improvements": improvements,
        "regressions": regressions,
        "both_correct": sum(
            r["hybrid_prediction"] == r["gold_source"]
            and r["reference_prediction"] == r["gold_source"]
            for r in rows
        ),
        "both_wrong": sum(
            r["hybrid_prediction"] != r["gold_source"]
            and r["reference_prediction"] != r["gold_source"]
            for r in rows
        ),
        "exact_paired_two_sided_pvalue": exact_paired_pvalue(improvements, regressions),
        "confirmatory_inference_supported": False,
    }


def markdown(artifact: dict) -> str:
    det = artifact["determinate_ai_gold"]
    common = artifact["prior_seven_method_common_misses"]
    lines = [
        "# Affected_versions release-boundary diagnostic",
        "",
        "This is a post-hoc AI-gold diagnostic. Feature extraction is gold-blind, but the experiment was motivated by previously inspected common misses. It is not human-gold performance and does not support a production method change.",
        "",
        "## Determinate AI-gold rows",
        "",
        "| Method | Correct | Accuracy | Coverage | Selective accuracy |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in (
        "canonical_token_reference",
        "release_boundary",
        "boundary_then_crosswalk_canonical",
    ):
        m = det[name]
        lines.append(
            f"| `{name}` | {m['correct']}/{m['rows']} | {m['accuracy']:.4f} | "
            f"{m['prediction_coverage']:.4f} | {m['selective_accuracy']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Paired exploratory comparison",
            "",
            (
                f"Relative to unrestricted canonical token, the hybrid accuracy delta is "
                f"`{artifact['paired_exploratory_comparison']['observed_accuracy_delta'] * 100:+.2f}pp` "
                f"with a stratified percentile interval of "
                f"`[{artifact['paired_exploratory_comparison']['percentile_95_interval'][0] * 100:+.2f}, "
                f"{artifact['paired_exploratory_comparison']['percentile_95_interval'][1] * 100:+.2f}]pp`. "
                f"There are `{artifact['paired_exploratory_comparison']['improvements']}` improvements and "
                f"`{artifact['paired_exploratory_comparison']['regressions']}` regressions; exact paired "
                f"two-sided p=`{artifact['paired_exploratory_comparison']['exact_paired_two_sided_pvalue']:.4f}`. "
                "These are sample-conditional diagnostics, not confirmatory inference."
            ),
            "",
            "## Prior seven-method common misses",
            "",
            f"The release-boundary diagnostic newly matches `{common['newly_correct']}/{common['rows']}` prior common misses and emits a non-abstain decision for `{common['non_abstain']}/{common['rows']}`. The post-hoc union oracle rises from `{common['prior_union_correct']}/{det['rows']}` to `{common['union_with_boundary_correct']}/{det['rows']}`; this oracle is not deployable.",
            "",
            "## Boundary",
            "",
            "The extractor uses cached snippets, lexical claim roles, conservative token equivalence, and parseable interval containment. It does not verify a complete release graph, model branch/backport topology, or replace the 60 abstained rows with truth labels.",
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
        gold_row = gold[sample_id]
        status = gold_row.get("ai_gold_status")
        gold_source = gold_row.get("annotation", {}).get("adjudicated_source")
        boundary = features[sample_id]["predicted_source"]
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold_row.get("cve_id"),
                "ai_gold_status": status,
                "gold_source": gold_source,
                "release_boundary_prediction": boundary,
                "reference_prediction": method_predictions[REFERENCE_METHOD][sample_id],
                "fallback_prediction": method_predictions[FALLBACK_METHOD][sample_id],
                "hybrid_prediction": (
                    boundary
                    if boundary != "abstain"
                    else method_predictions[FALLBACK_METHOD][sample_id]
                ),
                "prediction_reason": features[sample_id]["prediction_reason"],
            }
        )
    determinate = [r for r in rows if r["ai_gold_status"] == "final_determinate"]
    if len(determinate) != 40:
        raise ValueError(f"expected 40 determinate AI-gold rows, found {len(determinate)}")

    ceiling = json.loads(ceiling_path.read_text(encoding="utf-8"))
    oracle = ceiling["tested_method_union_oracle"]
    common_ids = {r["sample_id"] for r in oracle["no_method_correct_rows"]}
    common_rows = [r for r in determinate if r["sample_id"] in common_ids]
    boundary_correct_ids = {
        r["sample_id"]
        for r in determinate
        if r["release_boundary_prediction"] == r["gold_source"]
    }
    prior_correct_ids = {
        r["sample_id"] for r in determinate if r["sample_id"] not in common_ids
    }

    artifact = {
        "artifact_type": "affected_versions_release_boundary_ai_gold_diagnostic",
        "label_is_human": False,
        "feature_extraction_uses_gold": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "post_hoc_exploratory": True,
        "production_default_changed": False,
        "inputs": {
            "features": {"path": str(feature_path), "sha256": sha256(feature_path)},
            "gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
            "predictions": {"path": str(prediction_path), "sha256": sha256(prediction_path)},
            "ceiling": {"path": str(ceiling_path), "sha256": sha256(ceiling_path)},
        },
        "gold_coverage": {"determinate": 40, "total": 100, "rate": 0.4},
        "determinate_ai_gold": {
            "rows": len(determinate),
            "canonical_token_reference": metrics(determinate, "reference_prediction"),
            "release_boundary": metrics(determinate, "release_boundary_prediction"),
            "boundary_then_crosswalk_canonical": metrics(determinate, "hybrid_prediction"),
        },
        "paired_exploratory_comparison": paired_uncertainty(determinate),
        "prior_seven_method_common_misses": {
            "rows": len(common_rows),
            "non_abstain": sum(r["release_boundary_prediction"] != "abstain" for r in common_rows),
            "newly_correct": sum(
                r["release_boundary_prediction"] == r["gold_source"] for r in common_rows
            ),
            "prior_union_correct": len(prior_correct_ids),
            "union_with_boundary_correct": len(prior_correct_ids | boundary_correct_ids),
            "row_diagnostics": common_rows,
        },
        "cautions": [
            "The feature extractor does not read gold, but release-boundary analysis was selected after inspecting prior common misses.",
            "All accuracy values are conditional on 40 determinate AI-adjudicated rows; 60 final-abstain rows have no accuracy target.",
            "Lexical boundary roles and parseable containment are not a complete release graph and do not model all branches, backports, exceptions, or ecosystem ordering.",
            "The hybrid and union results are exploratory and do not justify changing production defaults.",
        ],
    }
    json_path = output_dir / "affected_versions_release_boundary_ai_gold_diagnostic.json"
    md_path = output_dir / "affected_versions_release_boundary_ai_gold_diagnostic.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
