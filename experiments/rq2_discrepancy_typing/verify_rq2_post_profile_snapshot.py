#!/usr/bin/env python3
"""Independently verify the isolated post-profile snapshot acquisition."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = "results/holdout/rq2_post_profile_snapshot_v1/acquisition/manifest.json"
EXPECTED_BOUNDARY = {
    "collection_after_profile_seal": True,
    "selection_uses_labels": False,
    "contains_annotations": False,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "strict_event_time_claim_requires_strict_tier": True,
    "snapshot_external_is_time_confirmatory": False,
    "production_switch_allowed": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
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
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def tier_size(count: int) -> int:
    if count >= 250:
        return 50
    if count >= 100:
        return 20
    if count >= 25:
        return 5
    return 0


def independent_counts(
    aligned_path: Path, field_views_path: Path, old_path: Path, seal_path: Path
) -> dict:
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(seal["sealed_at_ns"] / 1e9, timezone.utc)
    old = {row["cve_id"] for row in iter_jsonl(old_path)}
    rows = [row for row in iter_jsonl(aligned_path) if len(row.get("ghsa") or []) == 1]
    new_ids = {row["cve_id"] for row in rows}
    field_ids = {row["cve_id"] for row in iter_jsonl(field_views_path)}
    if new_ids != field_ids:
        raise ValueError("normalized row-set mismatch")
    strict = set()
    external = set()
    nvd_after = set()
    ghsa_after = set()
    for row in rows:
        cve_id = row["cve_id"]
        if cve_id in old:
            continue
        nvd_time = timestamp((row.get("nvd") or {}).get("published"))
        ghsa_time = timestamp(row["ghsa"][0].get("published"))
        if cve_id.startswith("CVE-2026-"):
            external.add(cve_id)
        if nvd_time and nvd_time > freeze:
            nvd_after.add(cve_id)
        if ghsa_time and ghsa_time > freeze:
            ghsa_after.add(cve_id)
        if nvd_time and ghsa_time and nvd_time > freeze and ghsa_time > freeze:
            strict.add(cve_id)
    strict_size = tier_size(len(strict))
    external_size = tier_size(len(external))
    selected = "strict_event_time" if strict_size else "snapshot_external" if external_size else "none"
    size = strict_size if strict_size else external_size
    return {
        "profile_freeze_timestamp": freeze.isoformat(),
        "old_aligned_cves": len(old),
        "new_single_ghsa_aligned_cves": len(new_ids),
        "overlap_with_old_aligned": len(new_ids & old),
        "nvd_published_after_profile": len(nvd_after),
        "ghsa_published_after_profile": len(ghsa_after),
        "strict_event_time_unique_cves": len(strict),
        "snapshot_external_unique_cves": len(external),
        "strict_event_time_rows_per_field": strict_size,
        "snapshot_external_rows_per_field": external_size,
        "selected_tier_for_next_stage": selected,
        "selected_rows_per_field": size,
        "selected_total_rows": size * 5,
        "strict_event_time_claim_allowed": selected == "strict_event_time",
        "snapshot_external_is_time_confirmatory": False,
    }


def validate(manifest: dict) -> None:
    if manifest.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("manifest boundary drift")
    checked(manifest["builder"], "builder")
    paths = {name: checked(record, name) for name, record in manifest["inputs"].items()}
    analysis_path = checked(manifest["outputs"]["analysis"], "analysis")
    checked(manifest["outputs"]["summary"], "summary")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    if analysis.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("analysis boundary drift")

    with zipfile.ZipFile(paths["nvd_archive"]) as archive:
        members = [name for name in archive.namelist() if name.endswith(".json")]
    if members != [analysis["sources"]["nvd_zip_member"]]:
        raise ValueError("NVD member drift")
    reviewed = 0
    with tarfile.open(paths["ghsa_archive"], "r:gz") as archive:
        for member in archive:
            if member.isfile() and member.name.endswith(".json") and "/advisories/github-reviewed/" in member.name:
                reviewed += 1
    if reviewed != analysis["sources"]["ghsa_reviewed_archive_members"]:
        raise ValueError("GHSA reviewed-member count drift")
    ls_remote = paths["ghsa_ls_remote"].read_text(encoding="ascii").strip().split()
    if ls_remote != [analysis["sources"]["ghsa_commit"], "refs/heads/main"]:
        raise ValueError("GHSA commit binding drift")

    expected = independent_counts(
        paths["aligned"], paths["field_views"], paths["old_aligned"], paths["profile_seal"]
    )
    reported = analysis["availability"]
    for key, value in expected.items():
        if reported.get(key) != value:
            raise ValueError(f"availability drift for {key}: {reported.get(key)!r} != {value!r}")
    field_stats = json.loads(paths["field_stats"].read_text(encoding="utf-8"))
    if field_stats["processed_pairs"] != expected["new_single_ghsa_aligned_cves"]:
        raise ValueError("field-view processed count drift")
    bootstrap = json.loads(paths["bootstrap_summary"].read_text(encoding="utf-8"))
    if bootstrap != analysis["bootstrap"]:
        raise ValueError("bootstrap summary drift")
    if analysis["acquisition_started_at_ns"] <= 0 or analysis["acquisition_completed_at_ns"] < analysis["acquisition_started_at_ns"]:
        raise ValueError("acquisition timestamps invalid")
    seal = json.loads(paths["profile_seal"].read_text(encoding="utf-8"))
    if analysis["acquisition_started_at_ns"] <= seal["sealed_at_ns"]:
        raise ValueError("acquisition did not occur after profile seal")


def main() -> int:
    args = parse_args()
    path = resolve(args.manifest)
    if not path.is_file():
        raise FileNotFoundError(path)
    validate(json.loads(path.read_text(encoding="utf-8")))
    analysis_path = checked(
        json.loads(path.read_text(encoding="utf-8"))["outputs"]["analysis"], "analysis"
    )
    availability = json.loads(analysis_path.read_text(encoding="utf-8"))["availability"]
    print(
        "Verified post-profile snapshot: "
        f"strict={availability['strict_event_time_unique_cves']} "
        f"external={availability['snapshot_external_unique_cves']} "
        f"tier={availability['selected_tier_for_next_stage']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
