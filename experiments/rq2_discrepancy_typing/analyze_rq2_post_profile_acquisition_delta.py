#!/usr/bin/env python3
"""Compare two post-profile acquisitions without using any review labels."""

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


DEFAULT_PREVIOUS_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/acquisition/manifest.json"
)
DEFAULT_CURRENT_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v2/acquisition/manifest.json"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v2/acquisition_delta_v1_to_v2"
)
SCHEMA_VERSION = "rq2_post_profile_acquisition_delta_v1"
BOUNDARY = {
    "contains_annotations": False,
    "selection_uses_labels": False,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "strict_cohort_freeze_requires_at_least_25_unique_cves": True,
    "production_switch_allowed": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-manifest", default=DEFAULT_PREVIOUS_MANIFEST)
    parser.add_argument("--current-manifest", default=DEFAULT_CURRENT_MANIFEST)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def portable(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


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


def load_jsonl(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            value = row.get(key)
            if not value:
                raise ValueError(f"{path}:{line_number}: missing {key}")
            if value in rows:
                raise ValueError(f"{path}:{line_number}: duplicate {key}={value}")
            rows[value] = row
    return rows


def record_delta(
    previous: dict[str, dict],
    current: dict[str, dict],
    freeze: datetime,
) -> dict:
    previous_ids = set(previous)
    current_ids = set(current)
    common_ids = previous_ids & current_ids
    added_ids = sorted(current_ids - previous_ids)
    removed_ids = sorted(previous_ids - current_ids)
    changed_ids = sorted(key for key in common_ids if previous[key] != current[key])
    published_after_profile_ids = sorted(
        key
        for key, row in current.items()
        if (published := parse_time(row.get("published"))) is not None
        and published > freeze
    )
    added_after_profile_ids = sorted(
        key
        for key in added_ids
        if (published := parse_time(current[key].get("published"))) is not None
        and published > freeze
    )
    return {
        "previous_count": len(previous),
        "current_count": len(current),
        "added_count": len(added_ids),
        "removed_count": len(removed_ids),
        "changed_count": len(changed_ids),
        "added_ids": added_ids,
        "removed_ids": removed_ids,
        "changed_ids": changed_ids,
        "published_after_profile_count": len(published_after_profile_ids),
        "published_after_profile_ids": published_after_profile_ids,
        "added_after_profile_count": len(added_after_profile_ids),
        "added_after_profile_ids": added_after_profile_ids,
    }


def acquisition_paths(manifest: dict) -> dict[str, Path]:
    aligned = resolve(manifest["inputs"]["aligned"]["path"])
    bootstrap_dir = aligned.parents[1]
    return {
        "nvd": bootstrap_dir / "nvd/nvd_2026.normalized.jsonl",
        "ghsa": bootstrap_dir / "ghsa/ghsa.normalized.jsonl",
        "aligned": aligned,
        "field_views": resolve(manifest["inputs"]["field_views"]["path"]),
        "analysis": resolve(manifest["outputs"]["analysis"]["path"]),
        "profile_seal": resolve(manifest["inputs"]["profile_seal"]["path"]),
    }


def manifest_record(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(path)
    return {"path": portable(path), "sha256": sha256(path)}


def acquisition_summary(manifest: dict, analysis: dict) -> dict:
    availability = analysis["availability"]
    return {
        "acquisition_started_at_ns": analysis["acquisition_started_at_ns"],
        "acquisition_completed_at_ns": analysis["acquisition_completed_at_ns"],
        "nvd_archive_sha256": manifest["inputs"]["nvd_archive"]["sha256"],
        "ghsa_archive_sha256": manifest["inputs"]["ghsa_archive"]["sha256"],
        "ghsa_commit": analysis["sources"]["ghsa_commit"],
        "nvd_records": analysis["bootstrap"]["nvd_records"],
        "ghsa_records": analysis["bootstrap"]["ghsa_records"],
        "single_ghsa_matches": analysis["bootstrap"]["matched_rows"],
        "strict_event_time_unique_cves": availability[
            "strict_event_time_unique_cves"
        ],
        "snapshot_external_unique_cves": availability[
            "snapshot_external_unique_cves"
        ],
    }


def summary_markdown(analysis: dict) -> str:
    previous = analysis["acquisitions"]["previous"]
    current = analysis["acquisitions"]["current"]
    nvd = analysis["source_deltas"]["nvd"]
    ghsa = analysis["source_deltas"]["ghsa"]
    alignment = analysis["alignment_delta"]
    readiness = analysis["strict_event_time_readiness"]
    return "\n".join(
        [
            "# RQ2 Post-Profile Acquisition Delta v1 to v2",
            "",
            "> Label-free availability audit. This artifact contains no correctness labels.",
            "",
            f"- Profile freeze: `{analysis['profile_freeze_timestamp']}`",
            f"- GHSA commit: `{previous['ghsa_commit']}` -> `{current['ghsa_commit']}`",
            f"- NVD records: `{previous['nvd_records']}` -> `{current['nvd_records']}` "
            f"(added `{nvd['added_count']}`, changed `{nvd['changed_count']}`)",
            f"- NVD records published after freeze: `{nvd['published_after_profile_count']}` "
            f"(newly added after freeze `{nvd['added_after_profile_count']}`)",
            f"- GHSA records: `{previous['ghsa_records']}` -> `{current['ghsa_records']}` "
            f"(added `{ghsa['added_count']}`, changed `{ghsa['changed_count']}`)",
            f"- GHSA records published after freeze: `{ghsa['published_after_profile_count']}`",
            f"- Single-GHSA matches: `{alignment['previous_single_ghsa_count']}` -> "
            f"`{alignment['current_single_ghsa_count']}`; matched rows changed "
            f"`{alignment['changed_single_ghsa_count']}`",
            f"- Field-view byte identity: `{alignment['field_views_byte_identical']}`",
            f"- Strict event-time CVEs: `{readiness['current_unique_cves']}`; "
            f"minimum to freeze a five-row-per-field cohort: "
            f"`{readiness['minimum_unique_cves']}`",
            f"- Decision: `{readiness['decision']}`",
            f"- Bottleneck: `{readiness['bottleneck']}`",
            "",
            "No new cohort is frozen because the strict event-time eligibility threshold is not met.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    previous_manifest_path = resolve(args.previous_manifest)
    current_manifest_path = resolve(args.current_manifest)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    previous_manifest = json.loads(previous_manifest_path.read_text(encoding="utf-8"))
    current_manifest = json.loads(current_manifest_path.read_text(encoding="utf-8"))
    verify_acquisition(previous_manifest)
    verify_acquisition(current_manifest)
    previous_paths = acquisition_paths(previous_manifest)
    current_paths = acquisition_paths(current_manifest)

    if sha256(previous_paths["profile_seal"]) != sha256(current_paths["profile_seal"]):
        raise ValueError("acquisitions do not bind the same profile seal")
    seal = json.loads(current_paths["profile_seal"].read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(seal["sealed_at_ns"] / 1e9, timezone.utc)
    previous_analysis = json.loads(previous_paths["analysis"].read_text(encoding="utf-8"))
    current_analysis = json.loads(current_paths["analysis"].read_text(encoding="utf-8"))

    source_deltas = {
        source: record_delta(
            load_jsonl(previous_paths[source], "source_id"),
            load_jsonl(current_paths[source], "source_id"),
            freeze,
        )
        for source in ("nvd", "ghsa")
    }
    previous_aligned = load_jsonl(previous_paths["aligned"], "cve_id")
    current_aligned = load_jsonl(current_paths["aligned"], "cve_id")
    aligned_delta = record_delta(previous_aligned, current_aligned, freeze)
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
    single_delta = record_delta(previous_single, current_single, freeze)
    strict_count = current_analysis["availability"]["strict_event_time_unique_cves"]
    if strict_count >= 25:
        decision = "freeze_strict_event_time_cohort"
        bottleneck = "none"
    elif source_deltas["ghsa"]["published_after_profile_count"] == 0:
        decision = "wait_for_bilateral_post_freeze_records"
        bottleneck = "no_ghsa_records_published_after_profile_freeze"
    else:
        decision = "wait_for_bilateral_post_freeze_matches"
        bottleneck = "fewer_than_25_strict_single_ghsa_matches"

    analysis = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_acquisition_delta",
        "boundary": dict(BOUNDARY),
        "profile_freeze_timestamp": freeze.isoformat(),
        "acquisitions": {
            "previous": acquisition_summary(previous_manifest, previous_analysis),
            "current": acquisition_summary(current_manifest, current_analysis),
        },
        "source_deltas": source_deltas,
        "alignment_delta": {
            **aligned_delta,
            "previous_single_ghsa_count": len(previous_single),
            "current_single_ghsa_count": len(current_single),
            "added_single_ghsa_count": single_delta["added_count"],
            "removed_single_ghsa_count": single_delta["removed_count"],
            "changed_single_ghsa_count": single_delta["changed_count"],
            "added_single_ghsa_ids": single_delta["added_ids"],
            "removed_single_ghsa_ids": single_delta["removed_ids"],
            "changed_single_ghsa_ids": single_delta["changed_ids"],
            "field_views_byte_identical": (
                sha256(previous_paths["field_views"])
                == sha256(current_paths["field_views"])
            ),
        },
        "strict_event_time_readiness": {
            "minimum_unique_cves": 25,
            "previous_unique_cves": previous_analysis["availability"][
                "strict_event_time_unique_cves"
            ],
            "current_unique_cves": strict_count,
            "cohort_freeze_allowed": strict_count >= 25,
            "decision": decision,
            "bottleneck": bottleneck,
        },
    }
    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(canonical_json(analysis), encoding="utf-8")
    summary_path.write_text(summary_markdown(analysis), encoding="utf-8")

    inputs = {
        "previous_acquisition_manifest": previous_manifest_path,
        "current_acquisition_manifest": current_manifest_path,
        "profile_seal": current_paths["profile_seal"],
        "previous_nvd": previous_paths["nvd"],
        "current_nvd": current_paths["nvd"],
        "previous_ghsa": previous_paths["ghsa"],
        "current_ghsa": current_paths["ghsa"],
        "previous_aligned": previous_paths["aligned"],
        "current_aligned": current_paths["aligned"],
        "previous_field_views": previous_paths["field_views"],
        "current_field_views": current_paths["field_views"],
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_acquisition_delta_manifest",
        "boundary": dict(BOUNDARY),
        "builder": manifest_record(Path(__file__)),
        "inputs": {name: manifest_record(path) for name, path in inputs.items()},
        "outputs": {
            "analysis": manifest_record(analysis_path),
            "summary": manifest_record(summary_path),
        },
    }
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    print(
        "Analyzed acquisition delta: "
        f"nvd_added={source_deltas['nvd']['added_count']} "
        f"ghsa_added={source_deltas['ghsa']['added_count']} "
        f"strict={strict_count} decision={decision}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
