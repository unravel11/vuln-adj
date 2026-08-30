#!/usr/bin/env python3
"""Materialize pinned Git record states for the frozen E0 sample."""

from __future__ import annotations

import argparse
import io
import json
import subprocess
import tarfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from temporal_provenance_lib import (
    canonical_json,
    cvelist_v5_path,
    fkie_nvd_path,
    project_cvelist_v5_record,
    project_ghsa_record,
    project_nvd_record,
    sha256_bytes,
)


SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "ghsa_advisory_database": {
        "directory": "ghsa-advisory-database",
        "path_builder": None,
        "projector": project_ghsa_record,
    },
    "cvelist_v5": {
        "directory": "cvelistV5",
        "path_builder": cvelist_v5_path,
        "projector": project_cvelist_v5_record,
    },
    "fkie_nvd_json_data_feeds": {
        "directory": "nvd-json-data-feeds",
        "path_builder": fkie_nvd_path,
        "projector": project_nvd_record,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        default="experiments/temporal_provenance/e0_sample_v1.json",
    )
    parser.add_argument(
        "--source-pins",
        default="experiments/temporal_provenance/source_pins_v1.json",
    )
    parser.add_argument(
        "--repositories-root",
        default="data/raw/temporal_provenance/pilot_v1/repositories",
    )
    parser.add_argument(
        "--output-dir",
        default="data/processed/temporal_provenance/pilot_v1/e0_git_states",
    )
    return parser.parse_args()


def run_git(
    repo: Path, *args: str, binary: bool = False, attempts: int = 1
) -> str | bytes:
    if attempts <= 0:
        raise ValueError("attempts must be positive")
    detail = "unknown error"
    for attempt in range(attempts):
        completed = subprocess.run(
            [
                "git",
                "-c",
                "http.version=HTTP/1.1",
                "-C",
                str(repo),
                *args,
            ],
            check=False,
            capture_output=True,
            text=not binary,
        )
        if completed.returncode == 0:
            return completed.stdout
        stderr = completed.stderr
        if isinstance(stderr, bytes):
            detail = stderr.decode("utf-8", errors="replace").strip()
        else:
            detail = stderr.strip()
        retryable = any(
            marker in detail
            for marker in (
                "SSL_ERROR_SYSCALL",
                "unable to access",
                "Connection reset",
                "The requested URL returned error: 5",
            )
        )
        if not retryable or attempt + 1 == attempts:
            break
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"git {' '.join(args)} failed for {repo}: {detail}")


def existing_paths(repo: Path, commit: str, paths: list[str]) -> set[str]:
    if not paths:
        return set()
    output = run_git(repo, "ls-tree", "-r", "--name-only", commit, "--", *paths)
    assert isinstance(output, str)
    return {line for line in output.splitlines() if line}


def archive_records(repo: Path, commit: str, paths: list[str]) -> dict[str, bytes]:
    existing = sorted(existing_paths(repo, commit, paths))
    if not existing:
        return {}
    archive = run_git(
        repo,
        "archive",
        "--format=tar",
        commit,
        "--",
        *existing,
        binary=True,
        attempts=4,
    )
    assert isinstance(archive, bytes)
    records = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
        for member in handle:
            if not member.isfile():
                continue
            extracted = handle.extractfile(member)
            if extracted is not None:
                records[member.name] = extracted.read()
    return records


def ghsa_paths(sample: dict[str, Any]) -> dict[str, list[str]]:
    result = {}
    for row in sample["rows"]:
        result[row["cve_id"]] = [
            item["relative_path"] for item in row.get("ghsa_records") or []
        ]
    return result


def single_paths(
    sample: dict[str, Any], path_builder: Callable[[str], str]
) -> dict[str, list[str]]:
    return {row["cve_id"]: [path_builder(row["cve_id"])] for row in sample["rows"]}


def states_for_source(
    source_name: str,
    repo: Path,
    source_pin: dict[str, Any],
    paths_by_cve: dict[str, list[str]],
    projector: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    snapshots = {"current": source_pin["head"]}
    snapshots.update(source_pin["checkpoints"])
    all_paths = sorted({path for paths in paths_by_cve.values() for path in paths})
    rows = []
    for snapshot_name, commit_metadata in snapshots.items():
        if commit_metadata is None:
            for cve_id, paths in sorted(paths_by_cve.items()):
                for path in paths:
                    rows.append(
                        {
                            "source": source_name,
                            "snapshot": snapshot_name,
                            "commit": None,
                            "cve_id": cve_id,
                            "path": path,
                            "status": "checkpoint_unavailable",
                        }
                    )
            continue
        commit = commit_metadata["commit"]
        archived = archive_records(repo, commit, all_paths)
        for cve_id, paths in sorted(paths_by_cve.items()):
            for path in paths:
                raw = archived.get(path)
                if raw is None:
                    rows.append(
                        {
                            "source": source_name,
                            "snapshot": snapshot_name,
                            "commit": commit,
                            "cve_id": cve_id,
                            "path": path,
                            "status": "absent",
                        }
                    )
                    continue
                try:
                    record = json.loads(raw)
                    projection = projector(record)
                    status = "present"
                    error = None
                except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
                    projection = None
                    status = "parse_error"
                    error = f"{type(exc).__name__}: {exc}"
                row = {
                    "source": source_name,
                    "snapshot": snapshot_name,
                    "commit": commit,
                    "commit_time": commit_metadata["committer_time"],
                    "cve_id": cve_id,
                    "path": path,
                    "status": status,
                    "raw_sha256": sha256_bytes(raw),
                    "raw_size": len(raw),
                    "projection": projection,
                }
                if error is not None:
                    row["error"] = error
                rows.append(row)
    return rows


def main() -> int:
    args = parse_args()
    sample_path = Path(args.sample).resolve()
    pins_path = Path(args.source_pins).resolve()
    repositories_root = Path(args.repositories_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    pins = json.loads(pins_path.read_text(encoding="utf-8"))
    if sample.get("status") != "sealed" or sample.get("selected_cves") != 100:
        raise ValueError("E0 sample must be sealed with exactly 100 CVEs")
    if pins.get("status") != "pinned":
        raise ValueError("Source pins are not sealed")

    output_dir.mkdir(parents=True, exist_ok=True)
    all_rows = []
    repository_heads = {}
    for source_name, spec in SOURCE_SPECS.items():
        repo = repositories_root / spec["directory"]
        source_pin = pins["sources"][source_name]
        actual_head = run_git(repo, "rev-parse", "HEAD")
        assert isinstance(actual_head, str)
        repository_heads[source_name] = actual_head.strip()
        pinned_commit = source_pin["head"]["commit"]
        run_git(repo, "cat-file", "-e", f"{pinned_commit}^{{commit}}")
        if source_name == "ghsa_advisory_database":
            paths_by_cve = ghsa_paths(sample)
        else:
            paths_by_cve = single_paths(sample, spec["path_builder"])
        rows = states_for_source(
            source_name,
            repo,
            source_pin,
            paths_by_cve,
            spec["projector"],
        )
        source_output = output_dir / f"{source_name}.jsonl"
        with source_output.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(canonical_json(row) + "\n")
        all_rows.extend(rows)
        print(f"{source_name}: {len(rows)} states -> {source_output}")

    counts = Counter(
        (row["source"], row["snapshot"], row["status"]) for row in all_rows
    )
    manifest = {
        "schema_version": "temporal-provenance-e0-git-states-v1",
        "sample_schema": sample["schema_version"],
        "source_pins_schema": pins["schema_version"],
        "rows": len(all_rows),
        "counts": [
            {
                "source": source,
                "snapshot": snapshot,
                "status": status,
                "count": count,
            }
            for (source, snapshot, status), count in sorted(counts.items())
        ],
        "source_files": {
            source_name: f"{source_name}.jsonl" for source_name in SOURCE_SPECS
        },
        "repository_transport_heads": repository_heads,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Manifest: {manifest_path}")
    current_failures = [
        row for row in all_rows if row["snapshot"] == "current" and row["status"] != "present"
    ]
    return 0 if not current_failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
