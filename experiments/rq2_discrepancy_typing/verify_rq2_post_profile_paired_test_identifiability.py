#!/usr/bin/env python3
"""Independently verify the RQ2 paired-test identifiability diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "paired_test_identifiability_v1"
)
PROFILES = (
    "current",
    "reference_resource_identity_original_v1",
    "reference_resource_identity_audited_v1",
    "cwe_taxonomy_v1",
    "combined_original_v1",
    "combined_audited_v1",
)
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
ALPHA = 0.05


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", default=DEFAULT_RESULT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked(entry: dict, name: str) -> Path:
    path = Path(entry.get("path", ""))
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def exact_p(first_only: int, second_only: int) -> float:
    total = first_only + second_only
    if total == 0:
        return 1.0
    lower = min(first_only, second_only)
    numerator = sum(math.comb(total, value) for value in range(lower + 1))
    return min(1.0, 2.0 * numerator / (2**total))


def profile_classes(prediction_rows: list[dict]) -> list[list[str]]:
    classes: list[list[str]] = []
    vectors: list[tuple[str, ...]] = []
    for profile in PROFILES:
        vector = tuple(row[profile] for row in prediction_rows)
        if vector in vectors:
            classes[vectors.index(vector)].append(profile)
        else:
            vectors.append(vector)
            classes.append([profile])
    return classes


def pairwise(source_rows: list[dict], prediction_rows: list[dict]) -> list[dict]:
    rows = []
    for first_index, first in enumerate(PROFILES):
        for second in PROFILES[first_index + 1 :]:
            sample_ids = [
                source["sample_id"]
                for source, prediction in zip(source_rows, prediction_rows)
                if prediction[first] != prediction[second]
            ]
            minimum_p = exact_p(0, len(sample_ids)) if sample_ids else 1.0
            rows.append(
                {
                    "first_profile": first,
                    "second_profile": second,
                    "prediction_difference_rows": len(sample_ids),
                    "difference_sample_ids": sample_ids,
                    "minimum_attainable_two_sided_exact_p": minimum_p,
                    "any_gold_assignment_can_reject_alpha_0_05": minimum_p <= ALPHA,
                }
            )
    return rows


def representative(source_rows: list[dict], prediction_rows: list[dict]) -> dict:
    differences = []
    for source, prediction in zip(source_rows, prediction_rows):
        first = prediction["current"]
        second = prediction["cwe_taxonomy_v1"]
        if first != second:
            differences.append(
                {
                    "sample_id": source["sample_id"],
                    "cve_id": source["cve_id"],
                    "field": source["field"],
                    "first_prediction": first,
                    "second_prediction": second,
                }
            )
    effective_counts = Counter()
    p_counts = Counter()
    rejecting = 0
    minimum_p = 1.0
    for assignment in itertools.product(LABELS, repeat=len(differences)):
        first_only = sum(
            label == row["first_prediction"]
            for label, row in zip(assignment, differences)
        )
        second_only = sum(
            label == row["second_prediction"]
            for label, row in zip(assignment, differences)
        )
        value = exact_p(first_only, second_only)
        effective_counts[first_only + second_only] += 1
        p_counts[format(value, ".12g")] += 1
        rejecting += value <= ALPHA
        minimum_p = min(minimum_p, value)
    return {
        "first_profile": "current",
        "second_profile": "cwe_taxonomy_v1",
        "difference_rows": differences,
        "total_label_assignments": len(LABELS) ** len(differences),
        "effective_discordant_row_assignment_counts": {
            str(key): effective_counts[key] for key in sorted(effective_counts)
        },
        "two_sided_exact_p_assignment_counts": {
            key: p_counts[key] for key in sorted(p_counts, key=float)
        },
        "minimum_attainable_two_sided_exact_p": minimum_p,
        "rejecting_assignments_alpha_0_05": rejecting,
        "assignment_counts_are_probabilities": False,
    }


def candidate_power(rows: int, probability: float) -> float:
    return sum(
        math.comb(rows, second_only)
        * (probability**second_only)
        * ((1.0 - probability) ** (rows - second_only))
        for second_only in range(rows + 1)
        if second_only > rows - second_only
        and exact_p(rows - second_only, second_only) <= ALPHA
    )


def minimum_power_rows(probability: float) -> tuple[int, float]:
    for rows in range(1, 251):
        power = candidate_power(rows, probability)
        if power >= 0.80:
            return rows, power
    raise ValueError("power target unavailable")


def at_least_probability(rows: int, rate: float, required: int) -> float:
    if rows < required:
        return 0.0
    below = sum(
        math.comb(rows, value)
        * (rate**value)
        * ((1.0 - rate) ** (rows - value))
        for value in range(required)
    )
    return max(0.0, min(1.0, 1.0 - below))


def minimum_availability_rows(rate: float, required: int, target: float) -> tuple[int, float]:
    for rows in range(required, 100_001):
        probability = at_least_probability(rows, rate, required)
        if probability >= target:
            return rows, probability
    raise ValueError("availability target unavailable")


def main() -> int:
    args = parse_args()
    result_dir = resolve(args.result_dir)
    manifest_path = result_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != (
        "rq2_post_profile_paired_test_identifiability_manifest_v1"
    ):
        raise ValueError("unexpected manifest artifact_type")
    inputs = manifest.get("inputs") or {}
    outputs = manifest.get("outputs") or {}
    sealed_path = checked(inputs.get("sealed_manifest") or {}, "sealed manifest")
    source_path = checked(inputs.get("source_rows") or {}, "source rows")
    prediction_path = checked(inputs.get("predictions") or {}, "predictions")
    checked(inputs.get("contract") or {}, "contract")
    checked(inputs.get("analyzer") or {}, "analyzer")
    verifier_path = checked(inputs.get("verifier") or {}, "verifier")
    if verifier_path != Path(__file__).resolve():
        raise ValueError("manifest is not bound to this verifier")
    analysis_path = checked(outputs.get("analysis") or {}, "analysis")
    checked(outputs.get("markdown") or {}, "markdown")
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    for key, path in (("source_rows", source_path), ("predictions", prediction_path)):
        entry = (sealed.get("outputs") or {}).get(key) or {}
        if Path(entry.get("path", "")) != path or entry.get("sha256") != sha256(path):
            raise ValueError(f"sealed manifest no longer binds {key}")
    source_rows = list(iter_jsonl(source_path))
    prediction_rows = list(iter_jsonl(prediction_path))
    if len(source_rows) != 250 or len(prediction_rows) != 250:
        raise ValueError("expected 250 source and prediction rows")
    if [row.get("sample_id") for row in source_rows] != [
        row.get("sample_id") for row in prediction_rows
    ]:
        raise ValueError("source/prediction order drift")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    expected_classes = profile_classes(prediction_rows)
    expected_pairwise = pairwise(source_rows, prediction_rows)
    expected_representative = representative(source_rows, prediction_rows)
    if analysis.get("profile_prediction_equivalence_classes") != expected_classes:
        raise ValueError("profile equivalence classes do not recompute")
    if analysis.get("pairwise_comparisons") != expected_pairwise:
        raise ValueError("pairwise comparisons do not recompute")
    if analysis.get("representative_assignment_enumeration") != expected_representative:
        raise ValueError("representative assignment enumeration does not recompute")
    if expected_classes != [
        [
            "current",
            "reference_resource_identity_original_v1",
            "reference_resource_identity_audited_v1",
        ],
        ["cwe_taxonomy_v1", "combined_original_v1", "combined_audited_v1"],
    ]:
        raise ValueError("unexpected sealed profile equivalence classes")
    if expected_representative["minimum_attainable_two_sided_exact_p"] != 0.25:
        raise ValueError("unexpected minimum exact p-value")
    if expected_representative["rejecting_assignments_alpha_0_05"] != 0:
        raise ValueError("current cohort unexpectedly supports rejection")
    minimum_rejection_rows = next(
        rows for rows in range(1, 251) if exact_p(0, rows) <= ALPHA
    )
    exact_test = analysis.get("exact_test") or {}
    if exact_test != {
        "name": "conditional_exact_two_sided_mcnemar",
        "alpha": ALPHA,
        "minimum_effective_correctness_discordant_rows_for_any_rejection": 6,
        "minimum_p_at_current_three_prediction_differences": 0.25,
        "any_current_profile_pair_can_reject_under_any_gold_assignment": False,
    } or minimum_rejection_rows != 6:
        raise ValueError("exact-test identifiability summary drift")
    planning = analysis.get("planning_sensitivity") or {}
    expected_power = []
    for probability in (0.70, 0.80, 0.90):
        rows, achieved = minimum_power_rows(probability)
        expected_power.append(
            {
                "second_profile_win_probability": probability,
                "target_power": 0.80,
                "minimum_effective_correctness_discordant_rows": rows,
                "achieved_exact_power": achieved,
            }
        )
    expected_availability = []
    rate = 3 / 250
    for target in (0.80, 0.90, 0.95):
        rows, achieved = minimum_availability_rows(rate, 6, target)
        expected_availability.append(
            {
                "target_probability": target,
                "minimum_future_cohort_rows": rows,
                "achieved_probability": achieved,
            }
        )
    if planning.get("conditional_exact_power") != expected_power:
        raise ValueError("conditional power sensitivity does not recompute")
    if planning.get("future_cohort_difference_availability") != expected_availability:
        raise ValueError("future difference availability does not recompute")
    if (
        planning.get("observed_prediction_difference_rate") != rate
        or planning.get("expected_rows_for_six_differences_at_observed_rate") != 500
        or planning.get("stationary_difference_rate_assumption") is not True
        or planning.get("independent_random_sampling_assumption") is not True
        or planning.get("power_is_conditional_on_correctness_discordance") is not True
        or planning.get("planning_values_are_preregistered_sample_sizes") is not False
    ):
        raise ValueError("planning assumptions or point estimate drift")
    boundary = manifest.get("claim_boundary") or {}
    if boundary != {
        "label_is_human": False,
        "uses_any_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_confirmatory_gain_claim": False,
        "eligible_for_preregistered_power_claim": False,
        "candidate_promotion_allowed": False,
    }:
        raise ValueError("claim boundary drift")
    print(
        "Verified paired-test identifiability: profiles=6 classes=2 "
        "differences=3 min_p=0.2500 rejecting_assignments=0/125"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
