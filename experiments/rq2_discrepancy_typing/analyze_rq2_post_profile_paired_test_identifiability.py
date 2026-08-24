#!/usr/bin/env python3
"""Measure exact paired-test identifiability of the sealed RQ2 profiles."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "paired_test_identifiability_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_paired_test_identifiability_contract_v1.md"
)
PROFILES = (
    "current",
    "reference_resource_identity_original_v1",
    "reference_resource_identity_audited_v1",
    "cwe_taxonomy_v1",
    "combined_original_v1",
    "combined_audited_v1",
)
REPRESENTATIVE_FIRST = "current"
REPRESENTATIVE_SECOND = "cwe_taxonomy_v1"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
EXPECTED_ROWS = 250
EXPECTED_ROWS_PER_FIELD = 50
EXPECTED_REPRESENTATIVE_DIFFERENCES = 3
ALPHA = 0.05


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
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


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def checked_output(manifest: dict, key: str) -> Path:
    entry = (manifest.get("outputs") or {}).get(key) or {}
    path = Path(entry.get("path", ""))
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise ValueError(f"sealed manifest output/hash mismatch for {key}")
    return path


def load_bound_rows(base_dir: Path) -> tuple[Path, Path, Path, list[dict], list[dict]]:
    sealed_path = base_dir / "manifest.sealed.json"
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected sealed cohort artifact_type")
    if sealed.get("selected_rows") != EXPECTED_ROWS:
        raise ValueError("sealed cohort must contain 250 rows")
    source_path = checked_output(sealed, "source_rows")
    prediction_path = checked_output(sealed, "predictions")
    source_rows = list(iter_jsonl(source_path))
    prediction_rows = list(iter_jsonl(prediction_path))
    if len(source_rows) != EXPECTED_ROWS or len(prediction_rows) != EXPECTED_ROWS:
        raise ValueError("expected 250 source and prediction rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    prediction_ids = [row.get("sample_id") for row in prediction_rows]
    if source_ids != prediction_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source/prediction IDs must be unique and ordered identically")
    field_counts = Counter(row.get("field") for row in source_rows)
    if len(field_counts) != 5 or set(field_counts.values()) != {EXPECTED_ROWS_PER_FIELD}:
        raise ValueError("expected five fields with 50 source rows each")
    for source, prediction in zip(source_rows, prediction_rows):
        if (
            source.get("cve_id") != prediction.get("cve_id")
            or source.get("field") != prediction.get("field")
        ):
            raise ValueError(f"{source.get('sample_id')}: source/prediction drift")
        for profile in PROFILES:
            if prediction.get(profile) not in LABELS:
                raise ValueError(
                    f"{source.get('sample_id')}: invalid sealed {profile} label"
                )
    return sealed_path, source_path, prediction_path, source_rows, prediction_rows


def exact_two_sided_mcnemar_p(first_only: int, second_only: int) -> float:
    if first_only < 0 or second_only < 0:
        raise ValueError("discordant counts must be non-negative")
    total = first_only + second_only
    if total == 0:
        return 1.0
    lower = min(first_only, second_only)
    tail_numerator = sum(math.comb(total, value) for value in range(lower + 1))
    return min(1.0, 2.0 * tail_numerator / (2**total))


def minimum_rows_for_any_rejection(alpha: float) -> int:
    for rows in range(1, EXPECTED_ROWS + 1):
        if exact_two_sided_mcnemar_p(0, rows) <= alpha:
            return rows
    raise ValueError("no rejection count found within cohort bound")


def candidate_direction_power(rows: int, second_win_probability: float, alpha: float) -> float:
    if not 0.5 < second_win_probability < 1.0:
        raise ValueError("second-win probability must be between 0.5 and 1")
    power = 0.0
    for second_only in range(rows + 1):
        first_only = rows - second_only
        if second_only <= first_only:
            continue
        if exact_two_sided_mcnemar_p(first_only, second_only) > alpha:
            continue
        power += (
            math.comb(rows, second_only)
            * (second_win_probability**second_only)
            * ((1.0 - second_win_probability) ** first_only)
        )
    return power


def minimum_rows_for_power(
    second_win_probability: float, target_power: float, alpha: float
) -> tuple[int, float]:
    for rows in range(1, EXPECTED_ROWS + 1):
        power = candidate_direction_power(rows, second_win_probability, alpha)
        if power >= target_power:
            return rows, power
    raise ValueError("target power not reached within cohort bound")


def probability_at_least_differences(rows: int, rate: float, required: int) -> float:
    if not 0.0 < rate < 1.0 or required < 1 or rows < 0:
        raise ValueError("invalid binomial planning inputs")
    if rows < required:
        return 0.0
    below = sum(
        math.comb(rows, value)
        * (rate**value)
        * ((1.0 - rate) ** (rows - value))
        for value in range(required)
    )
    return max(0.0, min(1.0, 1.0 - below))


def minimum_cohort_rows_for_difference_probability(
    rate: float, required: int, target_probability: float
) -> tuple[int, float]:
    for rows in range(required, 100_001):
        probability = probability_at_least_differences(rows, rate, required)
        if probability >= target_probability:
            return rows, probability
    raise ValueError("difference-availability target not reached")


def profile_equivalence_classes(prediction_rows: list[dict]) -> list[list[str]]:
    classes: list[list[str]] = []
    vectors: list[tuple[str, ...]] = []
    for profile in PROFILES:
        vector = tuple(row[profile] for row in prediction_rows)
        try:
            index = vectors.index(vector)
        except ValueError:
            vectors.append(vector)
            classes.append([profile])
        else:
            classes[index].append(profile)
    return classes


def pairwise_results(source_rows: list[dict], prediction_rows: list[dict]) -> list[dict]:
    results = []
    for first_index, first in enumerate(PROFILES):
        for second in PROFILES[first_index + 1 :]:
            differences = [
                source["sample_id"]
                for source, prediction in zip(source_rows, prediction_rows)
                if prediction[first] != prediction[second]
            ]
            count = len(differences)
            minimum_p = exact_two_sided_mcnemar_p(0, count) if count else 1.0
            results.append(
                {
                    "first_profile": first,
                    "second_profile": second,
                    "prediction_difference_rows": count,
                    "difference_sample_ids": differences,
                    "minimum_attainable_two_sided_exact_p": minimum_p,
                    "any_gold_assignment_can_reject_alpha_0_05": minimum_p <= ALPHA,
                }
            )
    return results


def enumerate_representative_assignments(
    source_rows: list[dict], prediction_rows: list[dict]
) -> dict:
    differences = []
    for source, prediction in zip(source_rows, prediction_rows):
        first = prediction[REPRESENTATIVE_FIRST]
        second = prediction[REPRESENTATIVE_SECOND]
        if first == second:
            continue
        differences.append(
            {
                "sample_id": source["sample_id"],
                "cve_id": source["cve_id"],
                "field": source["field"],
                "first_prediction": first,
                "second_prediction": second,
            }
        )
    if len(differences) != EXPECTED_REPRESENTATIVE_DIFFERENCES:
        raise ValueError(
            "expected three representative prediction differences, found "
            f"{len(differences)}"
        )
    effective_counts = Counter()
    p_value_counts = Counter()
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
        p_value = exact_two_sided_mcnemar_p(first_only, second_only)
        effective_counts[first_only + second_only] += 1
        p_value_counts[format(p_value, ".12g")] += 1
        rejecting += p_value <= ALPHA
        minimum_p = min(minimum_p, p_value)
    return {
        "first_profile": REPRESENTATIVE_FIRST,
        "second_profile": REPRESENTATIVE_SECOND,
        "difference_rows": differences,
        "total_label_assignments": len(LABELS) ** len(differences),
        "effective_discordant_row_assignment_counts": {
            str(key): effective_counts[key] for key in sorted(effective_counts)
        },
        "two_sided_exact_p_assignment_counts": {
            key: p_value_counts[key]
            for key in sorted(p_value_counts, key=float)
        },
        "minimum_attainable_two_sided_exact_p": minimum_p,
        "rejecting_assignments_alpha_0_05": rejecting,
        "assignment_counts_are_probabilities": False,
    }


def compute_analysis(source_rows: list[dict], prediction_rows: list[dict]) -> dict:
    classes = profile_equivalence_classes(prediction_rows)
    pairwise = pairwise_results(source_rows, prediction_rows)
    representative = enumerate_representative_assignments(source_rows, prediction_rows)
    minimum_rejection_rows = minimum_rows_for_any_rejection(ALPHA)
    difference_rate = EXPECTED_REPRESENTATIVE_DIFFERENCES / EXPECTED_ROWS
    conditional_power = []
    for probability in (0.70, 0.80, 0.90):
        rows, achieved = minimum_rows_for_power(probability, 0.80, ALPHA)
        conditional_power.append(
            {
                "second_profile_win_probability": probability,
                "target_power": 0.80,
                "minimum_effective_correctness_discordant_rows": rows,
                "achieved_exact_power": achieved,
            }
        )
    availability = []
    for target in (0.80, 0.90, 0.95):
        rows, achieved = minimum_cohort_rows_for_difference_probability(
            difference_rate, minimum_rejection_rows, target
        )
        availability.append(
            {
                "target_probability": target,
                "minimum_future_cohort_rows": rows,
                "achieved_probability": achieved,
            }
        )
    return {
        "artifact_type": "rq2_post_profile_paired_test_identifiability_v1",
        "label_source": "complete_enumeration_without_labels",
        "label_is_human": False,
        "uses_any_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_confirmatory_gain_claim": False,
        "eligible_for_preregistered_power_claim": False,
        "candidate_promotion_allowed": False,
        "production_default_changed": False,
        "rows": len(source_rows),
        "profiles": list(PROFILES),
        "profile_prediction_equivalence_classes": classes,
        "pairwise_comparisons": pairwise,
        "representative_assignment_enumeration": representative,
        "exact_test": {
            "name": "conditional_exact_two_sided_mcnemar",
            "alpha": ALPHA,
            "minimum_effective_correctness_discordant_rows_for_any_rejection": (
                minimum_rejection_rows
            ),
            "minimum_p_at_current_three_prediction_differences": (
                representative["minimum_attainable_two_sided_exact_p"]
            ),
            "any_current_profile_pair_can_reject_under_any_gold_assignment": any(
                row["any_gold_assignment_can_reject_alpha_0_05"] for row in pairwise
            ),
        },
        "planning_sensitivity": {
            "observed_prediction_difference_rate": difference_rate,
            "expected_rows_for_six_differences_at_observed_rate": math.ceil(
                minimum_rejection_rows / difference_rate
            ),
            "conditional_exact_power": conditional_power,
            "future_cohort_difference_availability": availability,
            "stationary_difference_rate_assumption": True,
            "independent_random_sampling_assumption": True,
            "power_is_conditional_on_correctness_discordance": True,
            "planning_values_are_preregistered_sample_sizes": False,
        },
        "interpretation": (
            "The six profiles collapse to two sealed prediction vectors. Every "
            "cross-class comparison differs on only three rows, so the smallest "
            "attainable exact two-sided McNemar p-value is 0.25 and no possible "
            "gold assignment can reject at alpha 0.05. Six one-direction "
            "correctness-discordant rows are only the theoretical minimum for any "
            "rejection; the planning sensitivities require explicit assumptions and "
            "are not a confirmatory sample-size result."
        ),
    }


def render_markdown(analysis: dict) -> str:
    representative = analysis["representative_assignment_enumeration"]
    exact_test = analysis["exact_test"]
    planning = analysis["planning_sensitivity"]
    lines = [
        "# RQ2 Post-profile Paired-test Identifiability",
        "",
        f"- Sealed rows: `{analysis['rows']}`",
        "- Prediction-vector equivalence classes: "
        f"`{len(analysis['profile_prediction_equivalence_classes'])}`",
        "- Representative prediction differences: "
        f"`{len(representative['difference_rows'])}`",
        "- Minimum attainable exact two-sided p-value: "
        f"`{representative['minimum_attainable_two_sided_exact_p']:.4f}`",
        "- Rejecting logical assignments at alpha 0.05: "
        f"`{representative['rejecting_assignments_alpha_0_05']}/"
        f"{representative['total_label_assignments']}`",
        "- Theoretical minimum effective discordant rows for any rejection: "
        f"`{exact_test['minimum_effective_correctness_discordant_rows_for_any_rejection']}`",
        "",
        "| Profile equivalence class | Members |",
        "|---:|---|",
    ]
    for index, profiles in enumerate(
        analysis["profile_prediction_equivalence_classes"], start=1
    ):
        lines.append(f"| {index} | {', '.join(profiles)} |")
    lines.extend(
        [
            "",
            "| Effective correctness-discordant rows | Logical assignments |",
            "|---:|---:|",
        ]
    )
    for rows, count in representative[
        "effective_discordant_row_assignment_counts"
    ].items():
        lines.append(f"| {rows} | {count} |")
    lines.extend(
        [
            "",
            "| Assumed second-profile win probability | Effective discordant rows for 80% power |",
            "|---:|---:|",
        ]
    )
    for row in planning["conditional_exact_power"]:
        lines.append(
            f"| {row['second_profile_win_probability']:.2f} | "
            f"{row['minimum_effective_correctness_discordant_rows']} |"
        )
    lines.extend(
        [
            "",
            "No reviewer or gold label is read. Assignment counts are logical cases, "
            "not probabilities. The planning table is conditional on correctness "
            "discordance and does not establish a preregistered sample size, "
            "confirmatory gain, or human-gold result.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    contract_path = resolve(args.contract)
    analyzer_path = Path(__file__).resolve()
    verifier_path = analyzer_path.with_name(
        "verify_rq2_post_profile_paired_test_identifiability.py"
    )
    if not contract_path.is_file() or not verifier_path.is_file():
        raise FileNotFoundError("contract or verifier is missing")
    sealed_path, source_path, prediction_path, source_rows, prediction_rows = (
        load_bound_rows(base_dir)
    )
    analysis = compute_analysis(source_rows, prediction_rows)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "summary.md"
    manifest_path = output_dir / "manifest.json"
    existing = [path for path in (analysis_path, markdown_path, manifest_path) if path.exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing outputs: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "artifact_type": "rq2_post_profile_paired_test_identifiability_manifest_v1",
        "inputs": {
            "sealed_manifest": {"path": str(sealed_path), "sha256": sha256(sealed_path)},
            "source_rows": {"path": str(source_path), "sha256": sha256(source_path)},
            "predictions": {"path": str(prediction_path), "sha256": sha256(prediction_path)},
            "contract": {"path": str(contract_path), "sha256": sha256(contract_path)},
            "analyzer": {"path": str(analyzer_path), "sha256": sha256(analyzer_path)},
            "verifier": {"path": str(verifier_path), "sha256": sha256(verifier_path)},
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": sha256(markdown_path)},
        },
        "claim_boundary": {
            "label_is_human": False,
            "uses_any_labels": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_accuracy_claim": False,
            "eligible_for_confirmatory_gain_claim": False,
            "eligible_for_preregistered_power_claim": False,
            "candidate_promotion_allowed": False,
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Paired-test identifiability: profiles=6 classes="
        f"{len(analysis['profile_prediction_equivalence_classes'])} differences=3 "
        f"min_p={analysis['exact_test']['minimum_p_at_current_three_prediction_differences']:.4f} "
        "any_rejection=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
