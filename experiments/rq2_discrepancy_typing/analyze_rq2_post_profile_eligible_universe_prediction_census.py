#!/usr/bin/env python3
"""Census frozen profile differences over the complete post-profile universe."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for directory in (Path(__file__).resolve().parent, SCRIPTS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from analyze_cwe_taxonomy_variants import CweCatalog  # noqa: E402
from build_rq2_post_profile_cohort import (  # noqa: E402
    eligible_cves,
    profile_predictions,
    single_ghsa_rows,
)
from build_rq2_typing_holdout import (  # noqa: E402
    FIELDS,
    LABELS,
    iter_jsonl,
    unique_by_cve,
)
from verify_rq2_post_profile_snapshot import validate as verify_acquisition  # noqa: E402


DEFAULT_COHORT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/manifest.sealed.json"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_eligible_universe_prediction_census_contract_v1.md"
)
DEFAULT_OUTPUT_DIR = (
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
ALPHA = 0.05


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-manifest", default=DEFAULT_COHORT_MANIFEST)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def checked_record(record: dict, name: str) -> Path:
    path = Path(record.get("path", ""))
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def census_source_rows(field_by_cve: dict[str, dict], eligible: set[str]) -> list[dict]:
    rows = []
    for field in FIELDS:
        for cve_id in sorted(eligible):
            field_row = field_by_cve[cve_id]
            discrepancy = (field_row.get("field_discrepancies") or {}).get(field) or {}
            status = discrepancy.get("status")
            if status not in LABELS:
                raise ValueError(f"{cve_id}: invalid {field} current status {status!r}")
            rows.append(
                {
                    "sample_id": f"rq2_post_profile_universe_v1:{field}:{cve_id}",
                    "cve_id": cve_id,
                    "field": field,
                    "baseline_status": status,
                    "nvd_value": discrepancy.get("nvd_value"),
                    "ghsa_value": discrepancy.get("ghsa_value"),
                }
            )
    return rows


def profile_equivalence_classes(prediction_rows: list[dict]) -> list[list[str]]:
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


def minimum_attainable_p(maximum_discordant_rows: int) -> float:
    if maximum_discordant_rows == 0:
        return 1.0
    exponent = 1 - maximum_discordant_rows
    return 0.0 if exponent < -1_074 else 2.0**exponent


def pairwise_comparisons(prediction_rows: list[dict]) -> list[dict]:
    comparisons = []
    for first_index, first in enumerate(PROFILES):
        for second in PROFILES[first_index + 1 :]:
            differences = [row for row in prediction_rows if row[first] != row[second]]
            cve_counts = Counter(row["cve_id"] for row in differences)
            unique_cves = len(cve_counts)
            comparisons.append(
                {
                    "first_profile": first,
                    "second_profile": second,
                    "prediction_difference_rows": len(differences),
                    "prediction_difference_rate": len(differences) / len(prediction_rows),
                    "difference_unique_cves": unique_cves,
                    "multi_field_difference_cves": sum(
                        count > 1 for count in cve_counts.values()
                    ),
                    "differences_by_field": dict(
                        sorted(Counter(row["field"] for row in differences).items())
                    ),
                    "minimum_attainable_two_sided_exact_p_one_row_per_cve": (
                        minimum_attainable_p(unique_cves)
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
    return comparisons


def difference_rows(prediction_rows: list[dict]) -> list[dict]:
    rows = []
    for row in prediction_rows:
        changed = [profile for profile in PROFILES[1:] if row[profile] != row["current"]]
        if not changed:
            continue
        rows.append(
            {
                **{key: row[key] for key in ("sample_id", "cve_id", "field")},
                **{profile: row[profile] for profile in PROFILES},
                "changed_profiles_from_current": changed,
                "label_is_human": False,
            }
        )
    return rows


def profile_difference_counts(prediction_rows: list[dict]) -> dict:
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


def changed_profile_set_counts(prediction_rows: list[dict]) -> dict:
    counts = Counter()
    for row in prediction_rows:
        changed = tuple(
            profile for profile in PROFILES[1:] if row[profile] != row["current"]
        )
        if changed:
            counts["|".join(changed)] += 1
    return dict(sorted(counts.items()))


def compute_analysis(
    source_rows: list[dict],
    prediction_rows: list[dict],
    selected_predictions: list[dict],
) -> tuple[dict, list[dict]]:
    if len(source_rows) != EXPECTED_FIELD_INSTANCES:
        raise ValueError(
            f"expected {EXPECTED_FIELD_INSTANCES} census rows, found {len(source_rows)}"
        )
    if len(prediction_rows) != len(source_rows):
        raise ValueError("source/prediction row count mismatch")
    field_counts = Counter(row["field"] for row in source_rows)
    if set(field_counts.values()) != {EXPECTED_ELIGIBLE_CVES}:
        raise ValueError("expected 5,948 rows per field")
    status_counts: dict[str, dict[str, int]] = {}
    for field in FIELDS:
        status_counts[field] = dict(
            sorted(
                Counter(
                    row["baseline_status"]
                    for row in source_rows
                    if row["field"] == field
                ).items()
            )
        )
    differences = difference_rows(prediction_rows)
    difference_cve_counts = Counter(row["cve_id"] for row in differences)
    selected_counts = {
        profile: sum(row[profile] != row["current"] for row in selected_predictions)
        for profile in PROFILES[1:]
    }
    return (
        {
            "artifact_type": (
                "rq2_post_profile_eligible_universe_prediction_census_v1"
            ),
            "label_source": "none_prediction_only",
            "label_is_human": False,
            "uses_any_labels": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_accuracy_claim": False,
            "eligible_for_confirmatory_gain_claim": False,
            "eligible_for_temporal_generalization_claim": False,
            "eligible_for_preregistered_power_claim": False,
            "candidate_promotion_allowed": False,
            "production_default_changed": False,
            "same_snapshot_resampling_performed": False,
            "review_worklist_created": False,
            "eligible_tier": "snapshot_external",
            "eligible_unique_cves": EXPECTED_ELIGIBLE_CVES,
            "fields": list(FIELDS),
            "field_instances": len(source_rows),
            "field_counts": dict(sorted(field_counts.items())),
            "current_status_counts_by_field": status_counts,
            "profiles": list(PROFILES),
            "profile_prediction_equivalence_classes": (
                profile_equivalence_classes(prediction_rows)
            ),
            "profile_difference_counts_vs_current": profile_difference_counts(
                prediction_rows
            ),
            "changed_profile_set_counts": changed_profile_set_counts(prediction_rows),
            "union_prediction_difference_rows": len(differences),
            "union_prediction_difference_unique_cves": len(difference_cve_counts),
            "union_multi_field_difference_cves": sum(
                count > 1 for count in difference_cve_counts.values()
            ),
            "pairwise_comparisons": pairwise_comparisons(prediction_rows),
            "sealed_sample_replay": {
                "selected_rows": len(selected_predictions),
                "prediction_replay_exact": True,
                "profile_difference_counts_vs_current": selected_counts,
                "sample_rates_are_population_estimates": False,
            },
            "planning_thresholds_effective_correctness_discordant_rows": list(
                PLANNING_THRESHOLDS
            ),
            "planning_boundary": {
                "prediction_difference_is_correctness_discordance": False,
                "multiple_fields_per_cve_are_independent": False,
                "future_strict_event_time_cohort_required": True,
                "current_snapshot_may_be_relabelled_as_confirmatory": False,
                "one_field_per_cve_or_clustered_inference_required": True,
            },
            "interpretation": (
                "This census measures deterministic profile disagreement in the "
                "revealed snapshot-external universe. It does not create a new sample "
                "or observe correctness. Counts may guide a later strict event-time "
                "design but cannot establish accuracy, power, or method gain."
            ),
        },
        differences,
    )


def render_markdown(analysis: dict) -> str:
    lines = [
        "# RQ2 Post-profile Eligible-universe Prediction Census",
        "",
        f"- Eligible CVEs: `{analysis['eligible_unique_cves']}`",
        f"- Field instances: `{analysis['field_instances']}`",
        f"- Union difference rows: `{analysis['union_prediction_difference_rows']}`",
        "- Union difference unique CVEs: "
        f"`{analysis['union_prediction_difference_unique_cves']}`",
        "- Prediction-vector equivalence classes: "
        f"`{len(analysis['profile_prediction_equivalence_classes'])}`",
        "- Sealed 250-row prediction replay: `exact`",
        "",
        "| Profile versus current | Difference rows | Unique CVEs | Fields |",
        "|---|---:|---:|---|",
    ]
    for profile, values in analysis["profile_difference_counts_vs_current"].items():
        fields = ", ".join(
            f"{field}:{count}" for field, count in values["by_field"].items()
        )
        lines.append(
            f"| {profile} | {values['rows']} | {values['unique_cves']} | {fields} |"
        )
    lines.extend(
        [
            "",
            "This is a prediction-only census of a revealed snapshot-external universe. "
            "It contains no reviewer or gold label, does not draw another cohort, and "
            "cannot support accuracy, confirmatory gain, temporal generalization, "
            "preregistered power, or promotion.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    cohort_manifest_path = resolve(args.cohort_manifest)
    contract_path = resolve(args.contract)
    output_dir = resolve(args.output_dir)
    analyzer_path = Path(__file__).resolve()
    verifier_path = analyzer_path.with_name(
        "verify_rq2_post_profile_eligible_universe_prediction_census.py"
    )
    for path in (cohort_manifest_path, contract_path, verifier_path):
        if not path.is_file():
            raise FileNotFoundError(path)
    cohort = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected parent cohort artifact_type")
    if (
        cohort.get("selected_tier") != "snapshot_external"
        or cohort.get("eligible_unique_cves") != EXPECTED_ELIGIBLE_CVES
    ):
        raise ValueError("parent eligible universe drift")
    input_paths = {
        name: checked_record(record, f"parent input {name}")
        for name, record in (cohort.get("inputs") or {}).items()
    }
    output_paths = {
        name: checked_record(record, f"parent output {name}")
        for name, record in (cohort.get("outputs") or {}).items()
    }
    if input_paths.get("builder") != analyzer_path.with_name(
        "build_rq2_post_profile_cohort.py"
    ):
        raise ValueError("parent builder path drift")
    acquisition_manifest = json.loads(
        input_paths["acquisition_manifest"].read_text(encoding="utf-8")
    )
    verify_acquisition(acquisition_manifest)
    field_rows = list(iter_jsonl(input_paths["field_views"], include_line=True))
    field_by_cve = unique_by_cve(field_rows, "post-profile field views")
    aligned = unique_by_cve(
        single_ghsa_rows(iter_jsonl(input_paths["aligned"])),
        "post-profile single-GHSA aligned rows",
    )
    if set(field_by_cve) != set(aligned):
        raise ValueError("field-view/aligned CVE set drift")
    old_cves = {row["cve_id"] for row in iter_jsonl(input_paths["old_aligned"])}
    profile_seal = json.loads(input_paths["profile_seal"].read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(
        profile_seal["sealed_at_ns"] / 1_000_000_000, timezone.utc
    )
    eligible = eligible_cves(aligned, old_cves, "snapshot_external", freeze)
    if len(eligible) != EXPECTED_ELIGIBLE_CVES:
        raise ValueError("eligible CVE count drift")
    catalog = CweCatalog(input_paths["cwe_xml_zip"])
    selected_source = list(iter_jsonl(output_paths["source_rows"]))
    selected_predictions = list(iter_jsonl(output_paths["predictions"]))
    replayed = profile_predictions(selected_source, aligned, catalog)
    if replayed != selected_predictions:
        raise ValueError("sealed 250-row prediction replay drift")
    source_rows = census_source_rows(field_by_cve, eligible)
    predictions = profile_predictions(source_rows, aligned, catalog)
    analysis, differences = compute_analysis(
        source_rows, predictions, selected_predictions
    )
    analysis_path = output_dir / "analysis.json"
    differences_path = output_dir / "prediction_difference_rows.jsonl"
    markdown_path = output_dir / "summary.md"
    manifest_path = output_dir / "manifest.json"
    existing = [
        path
        for path in (analysis_path, differences_path, markdown_path, manifest_path)
        if path.exists()
    ]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing outputs: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_jsonl(differences_path, differences)
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    bound_inputs = {
        "parent_cohort_manifest": cohort_manifest_path,
        "contract": contract_path,
        "analyzer": analyzer_path,
        "verifier": verifier_path,
        **{f"parent_input_{name}": path for name, path in input_paths.items()},
        **{f"parent_output_{name}": path for name, path in output_paths.items()},
    }
    manifest = {
        "artifact_type": (
            "rq2_post_profile_eligible_universe_prediction_census_manifest_v1"
        ),
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in bound_inputs.items()
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": sha256(analysis_path)},
            "prediction_difference_rows": {
                "path": str(differences_path),
                "sha256": sha256(differences_path),
            },
            "markdown": {"path": str(markdown_path), "sha256": sha256(markdown_path)},
        },
        "claim_boundary": {
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
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Eligible-universe prediction census: "
        f"cves={analysis['eligible_unique_cves']} "
        f"instances={analysis['field_instances']} "
        f"difference_rows={analysis['union_prediction_difference_rows']} "
        f"difference_cves={analysis['union_prediction_difference_unique_cves']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
