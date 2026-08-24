#!/usr/bin/env python3
"""Freeze a second affected_versions holdout excluding all prior cohorts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from build_affected_versions_holdout import (
    affected_versions_fc,
    identity,
    identity_commitment,
    iter_jsonl,
    rank_key,
    resolve,
    sha256,
    unique_by_cve,
    validate_unique_identities,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
DEFAULT_DEVELOPMENT_EXCLUSION = (
    "data/annotations/phase_d/affected_versions_fc_manual_check.jsonl"
)
DEFAULT_V1_EXCLUSION = (
    "data/annotations/holdout/affected_versions_v1/source_rows.jsonl"
)
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/affected_versions_v2"
DEFAULT_SEED = "20260715-v2"
DEFAULT_SAMPLE_SIZE = 100
DEFAULT_EXPECTED_FC = 651
DEFAULT_EXPECTED_EXCLUDED = 200
DEFAULT_EXPECTED_ELIGIBLE = 451
SAMPLE_PREFIX = "affected_versions_holdout_v2"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--development-exclusion", default=DEFAULT_DEVELOPMENT_EXCLUSION)
    parser.add_argument("--v1-exclusion", default=DEFAULT_V1_EXCLUSION)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--expected-fc", type=int, default=DEFAULT_EXPECTED_FC)
    parser.add_argument("--expected-excluded", type=int, default=DEFAULT_EXPECTED_EXCLUDED)
    parser.add_argument("--expected-eligible", type=int, default=DEFAULT_EXPECTED_ELIGIBLE)
    return parser.parse_args()


def combine_exclusions(groups: list[tuple[str, dict[str, dict]]]) -> dict[str, dict]:
    combined: dict[str, dict] = {}
    provenance: dict[str, str] = {}
    for name, rows in groups:
        for cve_id, row in rows.items():
            if cve_id in combined:
                raise ValueError(
                    f"exclusion cohorts overlap by cve_id={cve_id}: "
                    f"{provenance[cve_id]} and {name}"
                )
            combined[cve_id] = row
            provenance[cve_id] = name
    return combined


def select_holdout(
    candidates: list[dict], excluded_cve_ids: set[str], seed: str, sample_size: int
) -> tuple[list[dict], int]:
    if sample_size < 1:
        raise ValueError("sample_size must be positive")
    by_cve = unique_by_cve(candidates, "affected_versions FC candidates")
    missing = excluded_cve_ids - set(by_cve)
    if missing:
        raise ValueError(
            "excluded CVEs are no longer affected_versions FC: "
            f"{sorted(missing)[:5]}"
        )
    eligible = [row for cve_id, row in by_cve.items() if cve_id not in excluded_cve_ids]
    if sample_size > len(eligible):
        raise ValueError(f"sample_size={sample_size} exceeds eligible={len(eligible)}")
    eligible.sort(key=lambda row: rank_key(seed, row["cve_id"]))
    return eligible[:sample_size], len(eligible)


def build_source_row(row: dict, index: int) -> dict:
    discrepancy = row["field_discrepancies"]["affected_versions"]
    unified = row["unified_view"]
    return {
        "sample_id": f"{SAMPLE_PREFIX}:{index:03d}",
        "source_line_number": row["_source_line_number"],
        "cve_id": row["cve_id"],
        "nvd_source_id": row.get("nvd_source_id"),
        "ghsa_source_id": row.get("ghsa_source_id"),
        "field": "affected_versions",
        "baseline_status": "factual_conflict",
        "baseline_note": discrepancy.get("note"),
        "nvd_value": discrepancy.get("nvd_value"),
        "ghsa_value": discrepancy.get("ghsa_value"),
        "nvd_context": {
            "severity": unified.get("severity", {}).get("nvd"),
            "published": unified.get("published", {}).get("nvd"),
            "package_names": unified.get("package_names", {}).get("nvd"),
            "references": unified.get("references", {}).get("nvd_urls"),
        },
        "ghsa_context": {
            "severity": unified.get("severity", {}).get("ghsa"),
            "published": unified.get("published", {}).get("ghsa"),
            "package_names": unified.get("package_names", {}).get("ghsa"),
            "references": unified.get("references", {}).get("ghsa_urls"),
        },
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    development_path = resolve(args.development_exclusion)
    v1_path = resolve(args.v1_exclusion)
    output_dir = resolve(args.output_dir)
    for path in (input_path, development_path, v1_path):
        if not path.exists():
            raise FileNotFoundError(path)

    candidates = affected_versions_fc(iter_jsonl(input_path))
    development = unique_by_cve(iter_jsonl(development_path), "development exclusion")
    v1 = unique_by_cve(iter_jsonl(v1_path), "v1 holdout exclusion")
    validate_unique_identities(candidates, "affected_versions FC candidates")
    validate_unique_identities(development.values(), "development exclusion")
    validate_unique_identities(v1.values(), "v1 holdout exclusion")
    exclusions = combine_exclusions([("development", development), ("v1", v1)])
    validate_unique_identities(exclusions.values(), "combined exclusions")

    candidates_by_cve = unique_by_cve(candidates, "affected_versions FC candidates")
    for cve_id, exclusion in exclusions.items():
        current = candidates_by_cve.get(cve_id)
        if current is not None and identity(current) != identity(exclusion):
            raise ValueError(f"exclusion identity drift for {cve_id}")

    selected, eligible_count = select_holdout(
        candidates, set(exclusions), args.seed, args.sample_size
    )
    observed = (len(candidates), len(exclusions), eligible_count)
    expected = (args.expected_fc, args.expected_excluded, args.expected_eligible)
    if observed != expected:
        raise ValueError(f"frozen cohort counts changed: observed={observed}, expected={expected}")

    source_rows = [build_source_row(row, index) for index, row in enumerate(selected, 1)]
    validate_unique_identities(source_rows, "selected v2 holdout")
    for identity_index, name in enumerate(("cve_id", "nvd_source_id", "ghsa_source_id")):
        selected_ids = {identity(row)[identity_index] for row in source_rows}
        excluded_ids = {identity(row)[identity_index] for row in exclusions.values()}
        if selected_ids & excluded_ids:
            raise AssertionError(f"v2 holdout overlaps prior cohorts by {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "source_rows.jsonl"
    write_jsonl(output_path, source_rows)
    selected_cves = [row["cve_id"] for row in source_rows]
    manifest = {
        "artifact_type": "affected_versions_prior_cohort_disjoint_holdout_v2",
        "contains_annotations": False,
        "contains_gold_labels": False,
        "selection_uses_ai_gold": False,
        "selection_uses_method_predictions": False,
        "selection_rows_were_inspected": False,
        "field": "affected_versions",
        "required_baseline_status": "factual_conflict",
        "sampling_algorithm": "ascending_sha256(seed + ':' + cve_id), tie_break_cve_id",
        "seed": args.seed,
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "exclusions": {
            "development": {
                "path": str(development_path),
                "sha256": sha256(development_path),
                "rows": len(development),
                "identity_commitment_sha256": identity_commitment(development.values()),
            },
            "v1_holdout": {
                "path": str(v1_path),
                "sha256": sha256(v1_path),
                "rows": len(v1),
                "identity_commitment_sha256": identity_commitment(v1.values()),
            },
            "combined_rows": len(exclusions),
            "combined_identity_commitment_sha256": identity_commitment(exclusions.values()),
        },
        "fc_candidates": len(candidates),
        "fc_candidate_identity_commitment_sha256": identity_commitment(candidates),
        "eligible_after_exclusion": eligible_count,
        "selected_rows": len(source_rows),
        "selected_cve_commitment_sha256": hashlib.sha256(
            ("\n".join(selected_cves) + "\n").encode("utf-8")
        ).hexdigest(),
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "builder": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "cautions": [
            "The v2 cohort is disjoint by CVE and source identity from the old development and v1 holdout cohorts.",
            "Sampling remains conditional on the deterministic factual-conflict candidate miner.",
            "No labels, predictions, or evidence content are used for selection.",
            "Do not inspect or adjudicate v2 rows until the v2 method and prediction seal are frozen.",
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {output_path}")
    print(f"Wrote {manifest_path}")
    print(f"Selected CVE commitment: {manifest['selected_cve_commitment_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
