#!/usr/bin/env python3
"""Independently verify the sealed post-profile snapshot development cohort."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
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
from build_rq2_post_profile_cohort import BOUNDARY  # noqa: E402
from build_rq2_typing_holdout import (  # noqa: E402
    FIELDS,
    LABELS,
    blind_row,
    hybrid_stratum_quotas,
    iter_jsonl,
    prediction_row,
    rank_key,
    raw_field_values,
    select_globally_unique_strata,
    sha256,
    unique_by_cve,
)
from verify_rq2_post_profile_snapshot import validate as verify_acquisition  # noqa: E402


DEFAULT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/manifest.sealed.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def checked(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def independent_eligible(
    aligned: dict[str, dict], old_cves: set[str], tier: str, freeze: datetime
) -> set[str]:
    result = set()
    for cve_id, row in aligned.items():
        ghsa = row.get("ghsa") or []
        if cve_id in old_cves or len(ghsa) != 1:
            continue
        if tier == "snapshot_external" and cve_id.startswith("CVE-2026-"):
            result.add(cve_id)
        elif tier == "strict_event_time":
            nvd_time = parse_time((row.get("nvd") or {}).get("published"))
            ghsa_time = parse_time(ghsa[0].get("published"))
            if nvd_time and ghsa_time and nvd_time > freeze and ghsa_time > freeze:
                result.add(cve_id)
    return result


def recompute_prediction(source: dict, aligned: dict, catalog: CweCatalog) -> dict:
    current = source["baseline_status"]
    original_changes: dict[str, str] = {}
    audited_changes: dict[str, str] = {}
    cwe_changes: dict[str, str] = {}
    cve_id = source["cve_id"]
    if source["field"] == "references":
        nvd = aligned.get("nvd") or {}
        ghsa = (aligned.get("ghsa") or [])[0]
        original = compare_references(
            nvd, ghsa, normalization_profile="resource_identity_v1"
        )["status"]
        audited = compare_references(
            nvd, ghsa, normalization_profile="resource_identity_audited_v1"
        )["status"]
        if original != current:
            original_changes[cve_id] = original
        if audited != current:
            audited_changes[cve_id] = audited
    elif source["field"] == "cwe_ids":
        profile = relation_profile(
            list(source.get("nvd_value") or []),
            list(source.get("ghsa_value") or []),
            catalog,
        )
        candidate = taxonomy_v1_status(current, profile)
        if candidate != current:
            cwe_changes[cve_id] = candidate
    return prediction_row(source, original_changes, audited_changes, cwe_changes)


def validate(manifest: dict) -> None:
    if manifest.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected cohort manifest artifact_type")
    if manifest.get("boundary") != BOUNDARY:
        raise ValueError("cohort boundary drift")
    if manifest.get("rows_per_field") != 50 or manifest.get("selected_rows") != 250:
        raise ValueError("cohort size differs from the frozen contract")
    if manifest.get("selected_unique_cves") != 250:
        raise ValueError("cohort CVEs are not globally unique")

    inputs = {name: checked(record, f"inputs.{name}") for name, record in manifest["inputs"].items()}
    outputs = {
        name: checked(record, f"outputs.{name}")
        for name, record in manifest["outputs"].items()
    }
    acquisition_manifest = json.loads(
        inputs["acquisition_manifest"].read_text(encoding="utf-8")
    )
    verify_acquisition(acquisition_manifest)
    acquisition_analysis = json.loads(
        inputs["acquisition_analysis"].read_text(encoding="utf-8")
    )
    availability = acquisition_analysis["availability"]
    if availability["selected_tier_for_next_stage"] != manifest["selected_tier"]:
        raise ValueError("selected tier differs from acquisition")
    if availability["selected_rows_per_field"] != manifest["rows_per_field"]:
        raise ValueError("selected size differs from acquisition")

    source_rows = list(iter_jsonl(outputs["source_rows"]))
    predictions = list(iter_jsonl(outputs["predictions"]))
    blind_a = list(iter_jsonl(outputs["blind_worklist_a"]))
    blind_b = list(iter_jsonl(outputs["blind_worklist_b"]))
    if not all(len(rows) == 250 for rows in (source_rows, predictions, blind_a, blind_b)):
        raise ValueError("sealed output row counts differ")
    source_by_id = unique_by_cve(source_rows, "selected source rows")
    if len(source_by_id) != 250:
        raise ValueError("source rows repeat a CVE")
    if Counter(row["field"] for row in source_rows) != Counter({field: 50 for field in FIELDS}):
        raise ValueError("per-field sample counts differ")
    sample_ids = [f"rq2_post_profile_snapshot_v1:{index:03d}" for index in range(1, 251)]
    if [row["sample_id"] for row in source_rows] != sample_ids:
        raise ValueError("source sample identifiers or order differ")
    if [row["sample_id"] for row in predictions] != sample_ids:
        raise ValueError("prediction sample identifiers or order differ")
    if blind_a != [blind_row(row) for row in source_rows]:
        raise ValueError("reviewer A blind projection drift")
    if blind_b != list(reversed(blind_a)):
        raise ValueError("reviewer B worklist is not exact reverse order")

    field_rows = list(iter_jsonl(inputs["field_views"], include_line=True))
    field_by_cve = unique_by_cve(field_rows, "post-profile field views")
    aligned = unique_by_cve(
        (
            row
            for row in iter_jsonl(inputs["aligned"])
            if len(row.get("ghsa") or []) == 1
        ),
        "post-profile single-GHSA aligned rows",
    )
    old_cves = {row["cve_id"] for row in iter_jsonl(inputs["old_aligned"])}
    profile_seal = json.loads(inputs["profile_seal"].read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(
        profile_seal["sealed_at_ns"] / 1_000_000_000, timezone.utc
    )
    eligible = independent_eligible(aligned, old_cves, manifest["selected_tier"], freeze)
    if len(eligible) != manifest["eligible_unique_cves"]:
        raise ValueError("eligible universe count drift")
    if not set(source_by_id).issubset(eligible):
        raise ValueError("selected source includes an ineligible CVE")

    strata: dict[tuple[str, str], list[dict]] = defaultdict(list)
    counts: dict[tuple[str, str], int] = {}
    quotas: dict[tuple[str, str], int] = {}
    for field in FIELDS:
        by_status: dict[str, list[dict]] = defaultdict(list)
        for cve_id in eligible:
            row = field_by_cve[cve_id]
            status = row["field_discrepancies"][field]["status"]
            if status not in LABELS:
                raise ValueError(f"invalid current status for {cve_id}:{field}")
            by_status[status].append(row)
        field_counts = {status: len(rows) for status, rows in by_status.items()}
        field_quotas = hybrid_stratum_quotas(field_counts, 50)
        for status, quota in field_quotas.items():
            key = (field, status)
            counts[key] = field_counts[status]
            quotas[key] = quota
            strata[key] = sorted(
                by_status[status],
                key=lambda row: rank_key(manifest["seed"], field, status, row["cve_id"]),
            )
    expected_specs = select_globally_unique_strata(strata, quotas)
    expected_specs.sort(
        key=lambda item: rank_key(
            manifest["seed"] + ":global", item[1], item[2], item[0]["cve_id"]
        )
    )
    expected_identity = [(row["cve_id"], field, status) for row, field, status in expected_specs]
    actual_identity = [(row["cve_id"], row["field"], row["baseline_status"]) for row in source_rows]
    if actual_identity != expected_identity:
        raise ValueError("selected rows do not reproduce the frozen sampling algorithm")

    catalog = CweCatalog(inputs["cwe_xml_zip"])
    recomputed = []
    for source, prediction in zip(source_rows, predictions):
        view = field_by_cve[source["cve_id"]]
        current = view["field_discrepancies"][source["field"]]["status"]
        if source["baseline_status"] != current:
            raise ValueError(f"{source['sample_id']}: current status drift")
        expected_nvd, expected_ghsa = raw_field_values(
            aligned[source["cve_id"]], source["field"]
        )
        if source["nvd_value"] != expected_nvd or source["ghsa_value"] != expected_ghsa:
            raise ValueError(f"{source['sample_id']}: raw field projection drift")
        expected_prediction = recompute_prediction(
            source, aligned[source["cve_id"]], catalog
        )
        if prediction != expected_prediction:
            raise ValueError(f"{source['sample_id']}: sealed prediction drift")
        recomputed.append(expected_prediction)

    profiles = manifest["prediction_profiles"][1:]
    difference_counts = {
        profile: sum(row[profile] != row["current"] for row in recomputed)
        for profile in profiles
    }
    difference_rows = sum(
        len({row[profile] for profile in manifest["prediction_profiles"]}) > 1
        for row in recomputed
    )
    if difference_counts != manifest["candidate_profile_prediction_difference_counts"]:
        raise ValueError("candidate profile difference counts drift")
    if difference_rows != manifest["candidate_profile_prediction_difference_rows"]:
        raise ValueError("candidate profile difference row count drift")
    if manifest["candidate_profile_comparison_identifiable"] is not (difference_rows > 0):
        raise ValueError("candidate profile identifiability flag drift")

    sealed_at = manifest["sealed_at_ns"]
    protocol = manifest["review_protocol"]
    for key in ("reviewer_a_output", "reviewer_b_output", "reviewer_a_request_log", "reviewer_b_request_log"):
        path = resolve(protocol[key])
        if path.exists() and path.stat().st_mtime_ns <= sealed_at:
            raise ValueError(f"review artifact predates cohort seal: {path}")


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate(manifest)
    print(
        "Verified post-profile cohort: "
        f"tier={manifest['selected_tier']} rows={manifest['selected_rows']} "
        f"candidate_difference_rows={manifest['candidate_profile_prediction_difference_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
