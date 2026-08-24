#!/usr/bin/env python3
"""Independently verify the label-free post-profile acquisition delta."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_rq2_post_profile_snapshot import validate as verify_acquisition  # noqa: E402


DEFAULT_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v2/"
    "acquisition_delta_v1_to_v2/manifest.json"
)
EXPECTED_BOUNDARY = {
    "contains_annotations": False,
    "selection_uses_labels": False,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "strict_cohort_freeze_requires_at_least_25_unique_cves": True,
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


def load(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            row_key = row.get(key)
            if not row_key or row_key in rows:
                raise ValueError(f"{path}:{line_number}: invalid or duplicate {key}")
            rows[row_key] = row
    return rows


def delta(previous: dict[str, dict], current: dict[str, dict], freeze: datetime) -> dict:
    previous_ids = set(previous)
    current_ids = set(current)
    added = sorted(current_ids - previous_ids)
    removed = sorted(previous_ids - current_ids)
    changed = sorted(
        key for key in previous_ids & current_ids if previous[key] != current[key]
    )
    after = sorted(
        key
        for key, row in current.items()
        if (published := parse_time(row.get("published"))) is not None
        and published > freeze
    )
    added_after = sorted(
        key
        for key in added
        if (published := parse_time(current[key].get("published"))) is not None
        and published > freeze
    )
    return {
        "previous_count": len(previous),
        "current_count": len(current),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added_ids": added,
        "removed_ids": removed,
        "changed_ids": changed,
        "published_after_profile_count": len(after),
        "published_after_profile_ids": after,
        "added_after_profile_count": len(added_after),
        "added_after_profile_ids": added_after,
    }


def validate(manifest: dict) -> dict:
    if manifest.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("delta boundary drift")
    checked(manifest["builder"], "builder")
    paths = {name: checked(record, name) for name, record in manifest["inputs"].items()}
    analysis_path = checked(manifest["outputs"]["analysis"], "analysis")
    checked(manifest["outputs"]["summary"], "summary")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    if analysis.get("boundary") != EXPECTED_BOUNDARY:
        raise ValueError("analysis boundary drift")

    previous_acquisition = json.loads(
        paths["previous_acquisition_manifest"].read_text(encoding="utf-8")
    )
    current_acquisition = json.loads(
        paths["current_acquisition_manifest"].read_text(encoding="utf-8")
    )
    verify_acquisition(previous_acquisition)
    verify_acquisition(current_acquisition)
    previous_profile = previous_acquisition["inputs"]["profile_seal"]["sha256"]
    current_profile = current_acquisition["inputs"]["profile_seal"]["sha256"]
    if previous_profile != current_profile or previous_profile != sha256(paths["profile_seal"]):
        raise ValueError("profile-seal binding drift")
    seal = json.loads(paths["profile_seal"].read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(seal["sealed_at_ns"] / 1e9, timezone.utc)
    if analysis.get("profile_freeze_timestamp") != freeze.isoformat():
        raise ValueError("profile freeze timestamp drift")

    for source in ("nvd", "ghsa"):
        expected = delta(
            load(paths[f"previous_{source}"], "source_id"),
            load(paths[f"current_{source}"], "source_id"),
            freeze,
        )
        if analysis["source_deltas"].get(source) != expected:
            raise ValueError(f"{source} source delta drift")

    previous_aligned = load(paths["previous_aligned"], "cve_id")
    current_aligned = load(paths["current_aligned"], "cve_id")
    aligned_expected = delta(previous_aligned, current_aligned, freeze)
    previous_single = {
        key: row
        for key, row in previous_aligned.items()
        if len(row.get("ghsa") or []) == 1
    }
    current_single = {
        key: row
        for key, row in current_aligned.items()
        if len(row.get("ghsa") or []) == 1
    }
    single_expected = delta(previous_single, current_single, freeze)
    observed_alignment = analysis["alignment_delta"]
    for key, value in aligned_expected.items():
        if observed_alignment.get(key) != value:
            raise ValueError(f"aligned delta drift for {key}")
    extra_expected = {
        "previous_single_ghsa_count": len(previous_single),
        "current_single_ghsa_count": len(current_single),
        "added_single_ghsa_count": single_expected["added_count"],
        "removed_single_ghsa_count": single_expected["removed_count"],
        "changed_single_ghsa_count": single_expected["changed_count"],
        "added_single_ghsa_ids": single_expected["added_ids"],
        "removed_single_ghsa_ids": single_expected["removed_ids"],
        "changed_single_ghsa_ids": single_expected["changed_ids"],
        "field_views_byte_identical": (
            sha256(paths["previous_field_views"])
            == sha256(paths["current_field_views"])
        ),
    }
    for key, value in extra_expected.items():
        if observed_alignment.get(key) != value:
            raise ValueError(f"single-GHSA alignment drift for {key}")

    current_analysis_path = resolve(current_acquisition["outputs"]["analysis"]["path"])
    current_analysis = json.loads(current_analysis_path.read_text(encoding="utf-8"))
    strict_count = current_analysis["availability"]["strict_event_time_unique_cves"]
    source_ghsa_after = analysis["source_deltas"]["ghsa"][
        "published_after_profile_count"
    ]
    if strict_count >= 25:
        expected_decision = "freeze_strict_event_time_cohort"
        expected_bottleneck = "none"
    elif source_ghsa_after == 0:
        expected_decision = "wait_for_bilateral_post_freeze_records"
        expected_bottleneck = "no_ghsa_records_published_after_profile_freeze"
    else:
        expected_decision = "wait_for_bilateral_post_freeze_matches"
        expected_bottleneck = "fewer_than_25_strict_single_ghsa_matches"
    readiness = analysis["strict_event_time_readiness"]
    expected_readiness = {
        "minimum_unique_cves": 25,
        "previous_unique_cves": analysis["acquisitions"]["previous"][
            "strict_event_time_unique_cves"
        ],
        "current_unique_cves": strict_count,
        "cohort_freeze_allowed": strict_count >= 25,
        "decision": expected_decision,
        "bottleneck": expected_bottleneck,
    }
    if readiness != expected_readiness:
        raise ValueError("strict event-time readiness drift")
    return analysis


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    analysis = validate(manifest)
    readiness = analysis["strict_event_time_readiness"]
    print(
        "Verified acquisition delta: "
        f"strict={readiness['current_unique_cves']} "
        f"decision={readiness['decision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
