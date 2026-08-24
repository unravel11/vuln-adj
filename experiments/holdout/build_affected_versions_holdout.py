#!/usr/bin/env python3
"""Freeze a development-disjoint affected_versions factual-conflict holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
DEFAULT_EXCLUSION = "data/annotations/phase_d/affected_versions_fc_manual_check.jsonl"
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/affected_versions_v1"
DEFAULT_SEED = "20260715"
DEFAULT_SAMPLE_SIZE = 100
DEFAULT_EXPECTED_FC = 651
DEFAULT_EXPECTED_EXCLUDED = 100
DEFAULT_EXPECTED_ELIGIBLE = 551
SAMPLE_PREFIX = "affected_versions_holdout_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--exclusion", default=DEFAULT_EXCLUSION)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--expected-fc", type=int, default=DEFAULT_EXPECTED_FC)
    parser.add_argument(
        "--expected-excluded", type=int, default=DEFAULT_EXPECTED_EXCLUDED
    )
    parser.add_argument(
        "--expected-eligible", type=int, default=DEFAULT_EXPECTED_ELIGIBLE
    )
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


def iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected object")
            row["_source_line_number"] = line_number
            yield row


def unique_by_cve(rows: Iterable[dict], description: str) -> dict[str, dict]:
    by_cve = {}
    for row in rows:
        cve_id = str(row.get("cve_id") or "").strip()
        if not cve_id:
            raise ValueError(f"{description}: row has no cve_id")
        if cve_id in by_cve:
            raise ValueError(f"{description}: duplicate cve_id={cve_id}")
        by_cve[cve_id] = row
    return by_cve


def identity(row: dict) -> tuple[str, str, str]:
    return (
        str(row.get("cve_id") or "").strip(),
        str(row.get("nvd_source_id") or "").strip(),
        str(row.get("ghsa_source_id") or "").strip(),
    )


def validate_unique_identities(rows: Iterable[dict], description: str) -> None:
    identities = [identity(row) for row in rows]
    if any(not all(item) for item in identities):
        raise ValueError(f"{description}: incomplete CVE/NVD/GHSA identity")
    for index, name in enumerate(("cve_id", "nvd_source_id", "ghsa_source_id")):
        values = [item[index] for item in identities]
        if len(values) != len(set(values)):
            raise ValueError(f"{description}: duplicate {name}")
    if len(identities) != len(set(identities)):
        raise ValueError(f"{description}: duplicate identity tuple")


def identity_commitment(rows: Iterable[dict]) -> str:
    values = ["\t".join(identity(row)) for row in rows]
    return hashlib.sha256(("\n".join(sorted(values)) + "\n").encode("utf-8")).hexdigest()


def affected_versions_fc(rows: Iterable[dict]) -> list[dict]:
    return [
        row
        for row in rows
        if row.get("field_discrepancies", {})
        .get("affected_versions", {})
        .get("status")
        == "factual_conflict"
    ]


def rank_key(seed: str, cve_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(f"{seed}:{cve_id}".encode("utf-8")).hexdigest()
    return digest, cve_id


def select_holdout(
    candidates: list[dict], excluded_cve_ids: set[str], seed: str, sample_size: int
) -> tuple[list[dict], int]:
    if sample_size < 1:
        raise ValueError("sample_size must be positive")
    by_cve = unique_by_cve(candidates, "affected_versions FC candidates")
    missing_exclusions = excluded_cve_ids - set(by_cve)
    if missing_exclusions:
        raise ValueError(
            "excluded CVEs are no longer affected_versions FC: "
            f"{sorted(missing_exclusions)[:5]}"
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


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    exclusion_path = resolve(args.exclusion)
    output_dir = resolve(args.output_dir)
    if not input_path.exists() or not exclusion_path.exists():
        raise FileNotFoundError("input and exclusion files must exist")

    candidates = affected_versions_fc(iter_jsonl(input_path))
    exclusions = unique_by_cve(iter_jsonl(exclusion_path), "development exclusion")
    validate_unique_identities(candidates, "affected_versions FC candidates")
    validate_unique_identities(exclusions.values(), "development exclusion")
    candidates_by_cve = unique_by_cve(candidates, "affected_versions FC candidates")
    for cve_id, exclusion in exclusions.items():
        current = candidates_by_cve.get(cve_id)
        if current is not None and identity(current) != identity(exclusion):
            raise ValueError(f"development exclusion identity drift for {cve_id}")
    selected, eligible_count = select_holdout(
        candidates, set(exclusions), args.seed, args.sample_size
    )
    observed = (len(candidates), len(exclusions), eligible_count)
    expected = (args.expected_fc, args.expected_excluded, args.expected_eligible)
    if observed != expected:
        raise ValueError(f"frozen cohort counts changed: observed={observed}, expected={expected}")

    source_rows = [build_source_row(row, index) for index, row in enumerate(selected, 1)]
    validate_unique_identities(source_rows, "selected holdout")
    selected_cves = [row["cve_id"] for row in source_rows]
    if set(selected_cves) & set(exclusions):
        raise AssertionError("holdout overlaps the development exclusion")
    if len(set(selected_cves)) != len(source_rows):
        raise AssertionError("holdout contains duplicate CVEs")
    for index, name in enumerate(("cve_id", "nvd_source_id", "ghsa_source_id")):
        selected_ids = {identity(row)[index] for row in source_rows}
        excluded_ids = {identity(row)[index] for row in exclusions.values()}
        if selected_ids & excluded_ids:
            raise AssertionError(f"holdout overlaps development exclusion by {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "source_rows.jsonl"
    write_jsonl(output_path, source_rows)
    commitment = hashlib.sha256(
        ("\n".join(selected_cves) + "\n").encode("utf-8")
    ).hexdigest()
    manifest = {
        "artifact_type": "affected_versions_development_disjoint_holdout_v1",
        "contains_annotations": False,
        "contains_gold_labels": False,
        "selection_uses_ai_gold": False,
        "selection_uses_method_predictions": False,
        "field": "affected_versions",
        "required_baseline_status": "factual_conflict",
        "sampling_algorithm": "ascending_sha256(seed + ':' + cve_id), tie_break_cve_id",
        "seed": args.seed,
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "development_exclusion": {
            "path": str(exclusion_path),
            "sha256": sha256(exclusion_path),
            "rows": len(exclusions),
            "identity_commitment_sha256": identity_commitment(exclusions.values()),
        },
        "fc_candidates": len(candidates),
        "fc_candidate_identity_commitment_sha256": identity_commitment(candidates),
        "eligible_after_exclusion": eligible_count,
        "selected_rows": len(source_rows),
        "selected_cve_commitment_sha256": commitment,
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "builder": {
            "path": str(Path(__file__).resolve()),
            "sha256": sha256(Path(__file__).resolve()),
        },
        "cautions": [
            "The holdout is disjoint from the 100-row development sample by CVE ID.",
            "Sampling is conditional on the deterministic factual-conflict baseline.",
            "No human or AI labels and no method predictions are used for selection.",
            "The cohort must remain frozen before adjudication and evaluation.",
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {output_path}")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
