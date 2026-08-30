#!/usr/bin/env python3
"""Build the frozen, outcome-independent 100-CVE E0 replay sample."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from temporal_provenance_lib import parse_utc, sha256_file, sha256_text, valid_cve_id


SEED = "temporal-provenance-pilot-v1\n"
ELIGIBILITY_CUTOFF = "2023-12-31T23:59:59Z"
DEFAULT_SAMPLE_SIZE = 100


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--aligned",
        default="data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl",
    )
    parser.add_argument(
        "--output",
        default="experiments/temporal_provenance/e0_sample_v1.json",
    )
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    return parser.parse_args()


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc


def eligible_row(row: dict[str, Any], cutoff: str = ELIGIBILITY_CUTOFF) -> bool:
    cve_id = row.get("cve_id")
    if not valid_cve_id(cve_id):
        return False
    nvd = row.get("nvd") or {}
    nvd_published = nvd.get("published")
    if not isinstance(nvd_published, str):
        return False
    cutoff_time = parse_utc(cutoff)
    try:
        if parse_utc(nvd_published) > cutoff_time:
            return False
    except ValueError:
        return False
    qualifying_ghsa = []
    for ghsa in row.get("ghsa") or []:
        published = ghsa.get("published")
        reviewed = (ghsa.get("source_specific") or {}).get("github_reviewed")
        if reviewed is not True or not isinstance(published, str):
            continue
        try:
            if parse_utc(published) <= cutoff_time:
                qualifying_ghsa.append(ghsa)
        except ValueError:
            continue
    return bool(qualifying_ghsa)


def sample_entry(row: dict[str, Any]) -> dict[str, Any]:
    cve_id = row["cve_id"]
    ghsa_records = []
    for ghsa in row.get("ghsa") or []:
        source_specific = ghsa.get("source_specific") or {}
        published = ghsa.get("published")
        if source_specific.get("github_reviewed") is not True or not isinstance(
            published, str
        ):
            continue
        if parse_utc(published) > parse_utc(ELIGIBILITY_CUTOFF):
            continue
        relative_path = source_specific.get("relative_path")
        if isinstance(relative_path, str):
            ghsa_records.append(
                {
                    "ghsa_id": ghsa.get("source_id"),
                    "published": published,
                    "relative_path": relative_path,
                }
            )
    ghsa_records.sort(key=lambda item: (item["ghsa_id"] or "", item["relative_path"]))
    return {
        "cve_id": cve_id,
        "selection_digest": sha256_text(SEED + cve_id),
        "nvd_published": row["nvd"]["published"],
        "ghsa_records": ghsa_records,
    }


def build_manifest(
    rows: Iterable[dict[str, Any]], sample_size: int = DEFAULT_SAMPLE_SIZE
) -> dict[str, Any]:
    if sample_size <= 0:
        raise ValueError("sample_size must be positive")
    eligible = [row for row in rows if eligible_row(row)]
    candidates = [sample_entry(row) for row in eligible]
    candidates.sort(key=lambda item: (item["selection_digest"], item["cve_id"]))
    selected = candidates[:sample_size]
    status = "sealed" if len(candidates) >= sample_size else "partial_source_universe"
    return {
        "schema_version": "temporal-provenance-e0-sample-v1",
        "status": status,
        "selection_rule": "ascending_sha256_seed_plus_cve_id",
        "selection_seed_literal": SEED,
        "eligibility_cutoff": ELIGIBILITY_CUTOFF,
        "eligible_cves": len(candidates),
        "requested_sample_size": sample_size,
        "selected_cves": len(selected),
        "checkpoints": [
            "2024-01-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
            "2026-05-31T00:00:00Z",
        ],
        "rows": selected,
    }


def main() -> int:
    args = parse_args()
    aligned = Path(args.aligned).resolve()
    output = Path(args.output).resolve()
    manifest = build_manifest(iter_jsonl(aligned), args.sample_size)
    manifest["input"] = {
        "path": str(aligned),
        "sha256": sha256_file(aligned),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(
        f"E0 sample {manifest['status']}: "
        f"eligible={manifest['eligible_cves']} selected={manifest['selected_cves']}"
    )
    print(f"Manifest: {output}")
    return 0 if manifest["status"] == "sealed" else 2


if __name__ == "__main__":
    raise SystemExit(main())

