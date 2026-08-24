#!/usr/bin/env python3
"""Acquire and normalize an isolated post-profile NVD-GHSA snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_post_profile_snapshot_v1"
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2026.json.zip"
GHSA_REPO = "https://github.com/github/advisory-database.git"
PROFILE_SEAL = "data/annotations/holdout/rq2_typing_v1/manifest.sealed.json"
OLD_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
CONTRACT = "docs/annotation_guidelines/rq2_post_profile_time_cohort_contract_v1.md"
RAW_DIR = "data/raw/time_cohort/rq2_post_profile_snapshot_v1"
PROCESSED_DIR = "data/processed/time_cohort/rq2_post_profile_snapshot_v1"
RESULT_DIR = "results/holdout/rq2_post_profile_snapshot_v1/acquisition"
BOUNDARY = {
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
    parser.add_argument("--raw-dir", default=RAW_DIR)
    parser.add_argument("--processed-dir", default=PROCESSED_DIR)
    parser.add_argument("--result-dir", default=RESULT_DIR)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
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


def network_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        env.pop(key, None)
    return env


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=network_env(),
        text=True,
        capture_output=True,
        check=True,
    )


def resolve_ghsa_commit() -> str:
    result = run(
        [
            "git",
            "-c",
            "http.https://github.com.proxy=",
            "-c",
            "https.https://github.com.proxy=",
            "ls-remote",
            GHSA_REPO,
            "refs/heads/main",
        ]
    )
    parts = result.stdout.strip().split()
    if len(parts) != 2 or parts[1] != "refs/heads/main" or len(parts[0]) != 40:
        raise ValueError(f"unexpected GHSA ls-remote output: {result.stdout!r}")
    return parts[0]


def download(url: str, destination: Path, headers: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".part")
    if temp.exists():
        temp.unlink()
    result = run(
        [
            "curl",
            "--fail",
            "--location",
            "--retry",
            "5",
            "--connect-timeout",
            "60",
            "--dump-header",
            str(headers),
            "--output",
            str(temp),
            "--write-out",
            "%{http_code}\n%{url_effective}\n",
            url,
        ]
    )
    output = result.stdout.strip().splitlines()
    if not output or output[0] != "200":
        raise RuntimeError(f"download failed for {url}: {result.stdout!r}")
    if not temp.is_file() or temp.stat().st_size == 0:
        raise RuntimeError(f"empty download for {url}")
    temp.replace(destination)


def validate_nvd(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".json")]
        if len(names) != 1:
            raise ValueError(f"expected one NVD JSON member, found {names!r}")
        with archive.open(names[0]) as handle:
            prefix = handle.read(256)
    if b"vulnerabilities" not in prefix:
        raise ValueError("NVD archive does not begin with a CVE 2.0 payload")
    return names[0]


def validate_ghsa(path: Path) -> int:
    reviewed = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if (
                member.isfile()
                and member.name.endswith(".json")
                and "/advisories/github-reviewed/" in member.name
            ):
                reviewed += 1
    if reviewed == 0:
        raise ValueError("GHSA archive has no reviewed advisory JSON")
    return reviewed


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


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


def adaptive_rows_per_field(unique_cves: int) -> int:
    if unique_cves >= 250:
        return 50
    if unique_cves >= 100:
        return 20
    if unique_cves >= 25:
        return 5
    return 0


def availability_analysis(
    aligned_path: Path,
    field_views_path: Path,
    old_aligned_path: Path,
    profile_seal_path: Path,
) -> dict:
    seal = json.loads(profile_seal_path.read_text(encoding="utf-8"))
    freeze = datetime.fromtimestamp(seal["sealed_at_ns"] / 1_000_000_000, timezone.utc)
    old_cves = {row["cve_id"] for row in iter_jsonl(old_aligned_path)}
    aligned = {
        row["cve_id"]: row
        for row in iter_jsonl(aligned_path)
        if len(row.get("ghsa") or []) == 1
    }
    field_rows = list(iter_jsonl(field_views_path))
    field_cves = {row["cve_id"] for row in field_rows}
    if field_cves != set(aligned):
        raise ValueError("field-view/aligned one-GHSA CVE set drift")

    snapshot_external = set()
    strict_event_time = set()
    nvd_after = set()
    ghsa_after = set()
    for cve_id, row in aligned.items():
        if cve_id in old_cves:
            continue
        if cve_id.startswith("CVE-2026-"):
            snapshot_external.add(cve_id)
        nvd_time = parse_time((row.get("nvd") or {}).get("published"))
        ghsa_time = parse_time((row.get("ghsa") or [{}])[0].get("published"))
        if nvd_time and nvd_time > freeze:
            nvd_after.add(cve_id)
        if ghsa_time and ghsa_time > freeze:
            ghsa_after.add(cve_id)
        if nvd_time and ghsa_time and nvd_time > freeze and ghsa_time > freeze:
            strict_event_time.add(cve_id)

    status_counts = {
        tier: {
            field: dict(sorted(Counter(
                row["field_discrepancies"][field]["status"]
                for row in field_rows
                if row["cve_id"] in cves
            ).items()))
            for field in ("severity", "published", "references", "affected_versions", "cwe_ids")
        }
        for tier, cves in (
            ("strict_event_time", strict_event_time),
            ("snapshot_external", snapshot_external),
        )
    }
    strict_size = adaptive_rows_per_field(len(strict_event_time))
    external_size = adaptive_rows_per_field(len(snapshot_external))
    selected_tier = (
        "strict_event_time"
        if strict_size
        else "snapshot_external"
        if external_size
        else "none"
    )
    selected_rows_per_field = strict_size if strict_size else external_size
    return {
        "profile_freeze_timestamp": freeze.isoformat(),
        "old_aligned_cves": len(old_cves),
        "new_single_ghsa_aligned_cves": len(aligned),
        "overlap_with_old_aligned": len(set(aligned) & old_cves),
        "nvd_published_after_profile": len(nvd_after),
        "ghsa_published_after_profile": len(ghsa_after),
        "strict_event_time_unique_cves": len(strict_event_time),
        "snapshot_external_unique_cves": len(snapshot_external),
        "strict_event_time_rows_per_field": strict_size,
        "snapshot_external_rows_per_field": external_size,
        "selected_tier_for_next_stage": selected_tier,
        "selected_rows_per_field": selected_rows_per_field,
        "selected_total_rows": selected_rows_per_field * 5,
        "status_counts": status_counts,
        "strict_event_time_claim_allowed": selected_tier == "strict_event_time",
        "snapshot_external_is_time_confirmatory": False,
    }


def summary_markdown(analysis: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Post-Profile Snapshot Acquisition v1",
            "",
            "> Acquisition and availability audit only; contains no labels.",
            "",
            f"- GHSA commit: `{analysis['sources']['ghsa_commit']}`",
            f"- NVD records / GHSA records / single-GHSA matches: "
            f"`{analysis['bootstrap']['nvd_records']}/"
            f"{analysis['bootstrap']['ghsa_records']}/"
            f"{analysis['availability']['new_single_ghsa_aligned_cves']}`",
            f"- Strict post-profile event-time CVEs: "
            f"`{analysis['availability']['strict_event_time_unique_cves']}`",
            f"- Snapshot-external CVE-2026 CVEs: "
            f"`{analysis['availability']['snapshot_external_unique_cves']}`",
            f"- Next-stage tier / rows per field / total rows: "
            f"`{analysis['availability']['selected_tier_for_next_stage']}/"
            f"{analysis['availability']['selected_rows_per_field']}/"
            f"{analysis['availability']['selected_total_rows']}`",
            "",
            "The snapshot-external tier is development-only and cannot be reported as "
            "post-profile event-time confirmation.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    raw_dir = resolve(args.raw_dir)
    processed_dir = resolve(args.processed_dir)
    result_dir = resolve(args.result_dir)
    protected = [raw_dir, processed_dir, result_dir]
    if any(path.exists() for path in protected):
        if not args.force:
            raise FileExistsError("snapshot outputs exist; use --force only before annotation")
        for path in protected:
            if path.exists():
                shutil.rmtree(path)
    raw_dir.mkdir(parents=True)
    result_dir.mkdir(parents=True)

    started_ns = time.time_ns()
    profile_seal = resolve(PROFILE_SEAL)
    old_aligned = resolve(OLD_ALIGNED)
    contract = resolve(CONTRACT)
    for path in (profile_seal, old_aligned, contract):
        if not path.is_file():
            raise FileNotFoundError(path)

    ghsa_commit = resolve_ghsa_commit()
    ls_remote_path = raw_dir / "ghsa_main_ls_remote.txt"
    ls_remote_path.write_text(f"{ghsa_commit}\trefs/heads/main\n", encoding="ascii")
    nvd_zip = raw_dir / "nvdcve-2.0-2026.json.zip"
    nvd_headers = raw_dir / "nvdcve-2.0-2026.headers.txt"
    ghsa_archive = raw_dir / f"advisory-database-{ghsa_commit}.tar.gz"
    ghsa_headers = raw_dir / "advisory-database.headers.txt"
    download(NVD_URL, nvd_zip, nvd_headers)
    download(
        f"https://codeload.github.com/github/advisory-database/tar.gz/{ghsa_commit}",
        ghsa_archive,
        ghsa_headers,
    )
    nvd_member = validate_nvd(nvd_zip)
    reviewed_members = validate_ghsa(ghsa_archive)

    run(
        [
            sys.executable,
            "scripts/build_initial_corpus.py",
            "--raw-dir",
            str(raw_dir),
            "--output-dir",
            str(processed_dir / "bootstrap"),
            "--nvd-glob",
            nvd_zip.name,
            "--nvd-output-name",
            "nvd_2026.normalized.jsonl",
            "--ghsa-archive",
            str(ghsa_archive),
            "--ghsa-dir",
            str(raw_dir / "not_extracted"),
        ]
    )
    aligned_path = processed_dir / "bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
    discrepancy_dir = processed_dir / "discrepancies"
    run(
        [
            sys.executable,
            "scripts/build_field_discrepancies.py",
            "--aligned-path",
            str(aligned_path),
            "--output-dir",
            str(discrepancy_dir),
        ]
    )
    field_views = discrepancy_dir / "nvd_ghsa_field_views.jsonl"
    bootstrap_summary = processed_dir / "bootstrap/manifests/bootstrap_summary.json"
    field_stats = discrepancy_dir / "field_discrepancy_stats.json"
    bootstrap = json.loads(bootstrap_summary.read_text(encoding="utf-8"))
    availability = availability_analysis(aligned_path, field_views, old_aligned, profile_seal)
    completed_ns = time.time_ns()

    analysis = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_snapshot_acquisition",
        "boundary": dict(BOUNDARY),
        "acquisition_started_at_ns": started_ns,
        "acquisition_completed_at_ns": completed_ns,
        "sources": {
            "nvd_url": NVD_URL,
            "nvd_zip_member": nvd_member,
            "ghsa_repository": GHSA_REPO,
            "ghsa_commit": ghsa_commit,
            "ghsa_reviewed_archive_members": reviewed_members,
        },
        "bootstrap": bootstrap,
        "availability": availability,
    }
    analysis_path = result_dir / "analysis.json"
    summary_path = result_dir / "summary.md"
    manifest_path = result_dir / "manifest.json"
    analysis_path.write_text(canonical_json(analysis), encoding="utf-8")
    summary_path.write_text(summary_markdown(analysis), encoding="utf-8")

    inputs = {
        "contract": contract,
        "profile_seal": profile_seal,
        "old_aligned": old_aligned,
        "nvd_archive": nvd_zip,
        "nvd_headers": nvd_headers,
        "ghsa_archive": ghsa_archive,
        "ghsa_headers": ghsa_headers,
        "ghsa_ls_remote": ls_remote_path,
        "bootstrap_summary": bootstrap_summary,
        "aligned": aligned_path,
        "field_views": field_views,
        "field_stats": field_stats,
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_post_profile_snapshot_acquisition_manifest",
        "boundary": dict(BOUNDARY),
        "inputs": {
            name: {"path": portable(path), "sha256": sha256(path)}
            for name, path in inputs.items()
        },
        "builder": {"path": portable(Path(__file__)), "sha256": sha256(Path(__file__))},
        "outputs": {
            "analysis": {"path": portable(analysis_path), "sha256": sha256(analysis_path)},
            "summary": {"path": portable(summary_path), "sha256": sha256(summary_path)},
        },
    }
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    print(
        "Acquired post-profile snapshot: "
        f"strict={availability['strict_event_time_unique_cves']} "
        f"external={availability['snapshot_external_unique_cves']} "
        f"tier={availability['selected_tier_for_next_stage']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
