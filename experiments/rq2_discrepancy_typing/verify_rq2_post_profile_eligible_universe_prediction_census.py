#!/usr/bin/env python3
"""Independently verify the post-profile eligible-universe prediction census."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for directory in (Path(__file__).resolve().parent, SCRIPTS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from analyze_cwe_taxonomy_variants import (  # noqa: E402
    CweCatalog,
    relation_profile,
    taxonomy_v1_status,
)
from build_field_discrepancies import compare_references  # noqa: E402
from build_rq2_typing_holdout import FIELDS, LABELS, iter_jsonl, unique_by_cve  # noqa: E402
from verify_rq2_post_profile_snapshot import validate as verify_acquisition  # noqa: E402


DEFAULT_RESULT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "eligible_universe_prediction_census_v1"
)
PROFILES = (
    "current",
    "reference_resource_identity_original_v1",
    "reference_resource_identity_audited_v1",
    "cwe_taxonomy_v1",
    "combined_original_v1",
    "combined_audited_v1",
)
EXPECTED_ELIGIBLE_CVES = 5_948
EXPECTED_FIELD_INSTANCES = EXPECTED_ELIGIBLE_CVES * len(FIELDS)
PLANNING_THRESHOLDS = (6, 12, 20, 49)


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


def checked(record: dict, name: str) -> Path:
    path = Path(record.get("path", ""))
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def independent_source_rows(
    field_by_cve: dict[str, dict], eligible: set[str]
) -> list[dict]:
    rows = []
    for field in FIELDS:
        for cve_id in sorted(eligible):
            discrepancy = field_by_cve[cve_id]["field_discrepancies"][field]
            if discrepancy.get("status") not in LABELS:
                raise ValueError(f"{cve_id}: invalid {field} status")
            rows.append(
                {
                    "sample_id": f"rq2_post_profile_universe_v1:{field}:{cve_id}",
                    "cve_id": cve_id,
                    "field": field,
                    "baseline_status": discrepancy["status"],
                    "nvd_value": discrepancy.get("nvd_value"),
                    "ghsa_value": discrepancy.get("ghsa_value"),
                }
            )
    return rows


def independent_predictions(
    source_rows: list[dict], aligned: dict[str, dict], catalog: CweCatalog
) -> list[dict]:
    predictions = []
    for row in source_rows:
        cve_id = row["cve_id"]
        field = row["field"]
        current = row["baseline_status"]
        original_reference = current
        audited_reference = current
        cwe = current
        if field == "references":
            aligned_row = aligned[cve_id]
            nvd = aligned_row.get("nvd") or {}
            ghsa_rows = aligned_row.get("ghsa") or []
            if len(ghsa_rows) != 1:
                raise ValueError(f"{cve_id}: expected one GHSA record")
            original_reference = compare_references(
                nvd,
                ghsa_rows[0],
                normalization_profile="resource_identity_v1",
            )["status"]
            audited_reference = compare_references(
                nvd,
                ghsa_rows[0],
                normalization_profile="resource_identity_audited_v1",
            )["status"]
        elif field == "cwe_ids":
            relation = relation_profile(
                list(row.get("nvd_value") or []),
                list(row.get("ghsa_value") or []),
                catalog,
            )
            cwe = taxonomy_v1_status(current, relation)
        predictions.append(
            {
                "sample_id": row["sample_id"],
                "cve_id": cve_id,
                "field": field,
                "current": current,
                "reference_resource_identity_original_v1": original_reference,
                "reference_resource_identity_audited_v1": audited_reference,
                "cwe_taxonomy_v1": cwe,
                "combined_original_v1": (
                    original_reference if field == "references" else cwe
                ),
                "combined_audited_v1": (
                    audited_reference if field == "references" else cwe
                ),
            }
        )
    return predictions


def equivalence_classes(prediction_rows: list[dict]) -> list[list[str]]:
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


def minimum_p(unique_cves: int) -> float:
    if unique_cves == 0:
        return 1.0
    exponent = 1 - unique_cves
    return 0.0 if exponent < -1_074 else 2.0**exponent


def pairwise(prediction_rows: list[dict]) -> list[dict]:
    rows = []
    for first_index, first in enumerate(PROFILES):
        for second in PROFILES[first_index + 1 :]:
            differences = [row for row in prediction_rows if row[first] != row[second]]
            cve_counts = Counter(row["cve_id"] for row in differences)
            unique_cves = len(cve_counts)
            rows.append(
                {
                    "first_profile": first,
                    "second_profile": second,
                    "prediction_difference_rows": len(differences),
                    "prediction_difference_rate": len(differences)
                    / len(prediction_rows),
                    "difference_unique_cves": unique_cves,
                    "multi_field_difference_cves": sum(
                        count > 1 for count in cve_counts.values()
                    ),
                    "differences_by_field": dict(
                        sorted(Counter(row["field"] for row in differences).items())
                    ),
                    "minimum_attainable_two_sided_exact_p_one_row_per_cve": (
                        minimum_p(unique_cves)
                    ),
                    "minimum_attainable_p_power_of_two_exponent": (
                        None if unique_cves == 0 else 1 - unique_cves
                    ),
                    "theoretical_rejection_capacity_alpha_0_05": unique_cves >= 6,
                    "globally_unique_difference_cves_meet_planning_thresholds": {
                        str(threshold): unique_cves >= threshold
                        for threshold in PLANNING_THRESHOLDS
                    },
                }
            )
    return rows


def expected_difference_rows(prediction_rows: list[dict]) -> list[dict]:
    rows = []
    for row in prediction_rows:
        changed = [profile for profile in PROFILES[1:] if row[profile] != row["current"]]
        if changed:
            rows.append(
                {
                    **{key: row[key] for key in ("sample_id", "cve_id", "field")},
                    **{profile: row[profile] for profile in PROFILES},
                    "changed_profiles_from_current": changed,
                    "label_is_human": False,
                }
            )
    return rows


def difference_counts(prediction_rows: list[dict]) -> dict:
    result = {}
    for profile in PROFILES[1:]:
        changed = [row for row in prediction_rows if row[profile] != row["current"]]
        result[profile] = {
            "rows": len(changed),
            "unique_cves": len({row["cve_id"] for row in changed}),
            "by_field": dict(sorted(Counter(row["field"] for row in changed).items())),
            "by_current_status": dict(
                sorted(Counter(row["current"] for row in changed).items())
            ),
        }
    return result


def changed_set_counts(prediction_rows: list[dict]) -> dict:
    counts = Counter()
    for row in prediction_rows:
        changed = tuple(
            profile for profile in PROFILES[1:] if row[profile] != row["current"]
        )
        if changed:
            counts["|".join(changed)] += 1
    return dict(sorted(counts.items()))


def main() -> int:
    args = parse_args()
    result_dir = resolve(args.result_dir)
    manifest_path = result_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != (
        "rq2_post_profile_eligible_universe_prediction_census_manifest_v1"
    ):
        raise ValueError("unexpected manifest artifact_type")
    inputs = manifest.get("inputs") or {}
    outputs = manifest.get("outputs") or {}
    paths = {name: checked(record, f"input {name}") for name, record in inputs.items()}
    analysis_path = checked(outputs.get("analysis") or {}, "analysis")
    difference_path = checked(
        outputs.get("prediction_difference_rows") or {}, "prediction differences"
    )
    checked(outputs.get("markdown") or {}, "markdown")
    if paths.get("verifier") != Path(__file__).resolve():
        raise ValueError("manifest is not bound to this verifier")
    parent_path = paths["parent_cohort_manifest"]
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    if parent.get("eligible_unique_cves") != EXPECTED_ELIGIBLE_CVES:
        raise ValueError("parent eligible count drift")
    for name, record in (parent.get("inputs") or {}).items():
        path = paths.get(f"parent_input_{name}")
        if path is None or path != Path(record.get("path", "")):
            raise ValueError(f"parent input {name} binding drift")
        if sha256(path) != record.get("sha256"):
            raise ValueError(f"parent input {name} hash drift")
    for name, record in (parent.get("outputs") or {}).items():
        path = paths.get(f"parent_output_{name}")
        if path is None or path != Path(record.get("path", "")):
            raise ValueError(f"parent output {name} binding drift")
        if sha256(path) != record.get("sha256"):
            raise ValueError(f"parent output {name} hash drift")
    acquisition_manifest = json.loads(
        paths["parent_input_acquisition_manifest"].read_text(encoding="utf-8")
    )
    verify_acquisition(acquisition_manifest)
    field_rows = list(
        iter_jsonl(paths["parent_input_field_views"], include_line=True)
    )
    field_by_cve = unique_by_cve(field_rows, "post-profile field views")
    aligned_rows = [
        row
        for row in iter_jsonl(paths["parent_input_aligned"])
        if len(row.get("ghsa") or []) == 1
    ]
    aligned = unique_by_cve(aligned_rows, "single-GHSA aligned rows")
    if set(field_by_cve) != set(aligned):
        raise ValueError("field-view/aligned CVE set drift")
    old_cves = {
        row["cve_id"] for row in iter_jsonl(paths["parent_input_old_aligned"])
    }
    eligible = {
        cve_id
        for cve_id, row in aligned.items()
        if cve_id not in old_cves
        and cve_id.startswith("CVE-2026-")
        and len(row.get("ghsa") or []) == 1
    }
    if len(eligible) != EXPECTED_ELIGIBLE_CVES:
        raise ValueError("eligible universe does not independently recompute")
    source_rows = independent_source_rows(field_by_cve, eligible)
    if len(source_rows) != EXPECTED_FIELD_INSTANCES:
        raise ValueError("field-instance count drift")
    catalog = CweCatalog(paths["parent_input_cwe_xml_zip"])
    prediction_rows = independent_predictions(source_rows, aligned, catalog)
    selected_source = list(iter_jsonl(paths["parent_output_source_rows"]))
    selected_expected = independent_predictions(selected_source, aligned, catalog)
    selected_actual = list(iter_jsonl(paths["parent_output_predictions"]))
    if selected_expected != selected_actual:
        raise ValueError("independent sealed prediction replay drift")
    expected_differences = expected_difference_rows(prediction_rows)
    actual_differences = list(iter_jsonl(difference_path))
    if actual_differences != expected_differences:
        raise ValueError("prediction-difference rows do not recompute")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    field_counts = dict(sorted(Counter(row["field"] for row in source_rows).items()))
    status_counts = {
        field: dict(
            sorted(
                Counter(
                    row["baseline_status"]
                    for row in source_rows
                    if row["field"] == field
                ).items()
            )
        )
        for field in FIELDS
    }
    difference_cves = Counter(row["cve_id"] for row in expected_differences)
    if (
        analysis.get("eligible_unique_cves") != EXPECTED_ELIGIBLE_CVES
        or analysis.get("field_instances") != EXPECTED_FIELD_INSTANCES
        or analysis.get("field_counts") != field_counts
        or analysis.get("current_status_counts_by_field") != status_counts
        or analysis.get("profile_prediction_equivalence_classes")
        != equivalence_classes(prediction_rows)
        or analysis.get("profile_difference_counts_vs_current")
        != difference_counts(prediction_rows)
        or analysis.get("changed_profile_set_counts")
        != changed_set_counts(prediction_rows)
        or analysis.get("union_prediction_difference_rows")
        != len(expected_differences)
        or analysis.get("union_prediction_difference_unique_cves")
        != len(difference_cves)
        or analysis.get("union_multi_field_difference_cves")
        != sum(count > 1 for count in difference_cves.values())
        or analysis.get("pairwise_comparisons") != pairwise(prediction_rows)
    ):
        raise ValueError("census aggregate drift")
    replay = analysis.get("sealed_sample_replay") or {}
    expected_selected_counts = {
        profile: sum(row[profile] != row["current"] for row in selected_actual)
        for profile in PROFILES[1:]
    }
    if replay != {
        "selected_rows": 250,
        "prediction_replay_exact": True,
        "profile_difference_counts_vs_current": expected_selected_counts,
        "sample_rates_are_population_estimates": False,
    }:
        raise ValueError("sealed sample replay summary drift")
    planning = analysis.get("planning_boundary") or {}
    if planning != {
        "prediction_difference_is_correctness_discordance": False,
        "multiple_fields_per_cve_are_independent": False,
        "future_strict_event_time_cohort_required": True,
        "current_snapshot_may_be_relabelled_as_confirmatory": False,
        "one_field_per_cve_or_clustered_inference_required": True,
    }:
        raise ValueError("planning boundary drift")
    boundary = manifest.get("claim_boundary") or {}
    if boundary != {
        "label_is_human": False,
        "uses_any_labels": False,
        "same_snapshot_resampling_performed": False,
        "review_worklist_created": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_confirmatory_gain_claim": False,
        "eligible_for_temporal_generalization_claim": False,
        "eligible_for_preregistered_power_claim": False,
        "candidate_promotion_allowed": False,
    }:
        raise ValueError("claim boundary drift")
    print(
        "Verified eligible-universe prediction census: "
        f"cves={EXPECTED_ELIGIBLE_CVES} instances={EXPECTED_FIELD_INSTANCES} "
        f"difference_rows={len(expected_differences)} "
        f"difference_cves={len(difference_cves)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
