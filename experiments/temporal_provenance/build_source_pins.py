#!/usr/bin/env python3
"""Pin source repository commits and checkpoint states for pilot V1."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CHECKPOINTS = [
    "2024-01-01T00:00:00Z",
    "2025-01-01T00:00:00Z",
    "2026-05-31T00:00:00Z",
]

SOURCE_DIRS = {
    "ghsa_advisory_database": "ghsa-advisory-database",
    "cvelist_v5": "cvelistV5",
    "fkie_nvd_json_data_feeds": "nvd-json-data-feeds",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repositories-root",
        default="data/raw/temporal_provenance/pilot_v1/repositories",
    )
    parser.add_argument(
        "--output",
        default="experiments/temporal_provenance/source_pins_v1.json",
    )
    return parser.parse_args()


def git(repo: Path, *args: str, allow_empty: bool = False) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        if allow_empty:
            return None
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed for {repo}: {detail}")
    value = completed.stdout.strip()
    return value or None


def commit_metadata(repo: Path, commit: str) -> dict[str, str]:
    value = git(repo, "show", "-s", "--format=%H%x00%aI%x00%cI", commit)
    assert value is not None
    commit_id, author_time, committer_time = value.split("\x00")
    return {
        "commit": commit_id,
        "author_time": author_time,
        "committer_time": committer_time,
    }


def source_pin(logical_name: str, repo: Path) -> dict[str, Any]:
    if not (repo / ".git").is_dir():
        raise FileNotFoundError(f"Missing Git repository: {repo}")
    head = git(repo, "rev-parse", "HEAD")
    assert head is not None
    origin = git(repo, "remote", "get-url", "origin")
    roots = (git(repo, "rev-list", "--max-parents=0", head) or "").splitlines()
    checkpoint_pins = {}
    for checkpoint in CHECKPOINTS:
        checkpoint_commit = git(
            repo,
            "rev-list",
            "-1",
            "--first-parent",
            f"--before={checkpoint}",
            head,
            allow_empty=True,
        )
        checkpoint_pins[checkpoint] = (
            commit_metadata(repo, checkpoint_commit) if checkpoint_commit else None
        )
    return {
        "logical_name": logical_name,
        "directory_name": repo.name,
        "origin": origin,
        "head": commit_metadata(repo, head),
        "root_commits": roots,
        "object_format": git(repo, "rev-parse", "--show-object-format"),
        "partial_clone_promisor": git(
            repo, "config", "--bool", "--get", "remote.origin.promisor", allow_empty=True
        )
        == "true",
        "partial_clone_filter": git(
            repo, "config", "--get", "remote.origin.partialclonefilter", allow_empty=True
        ),
        "checkpoints": checkpoint_pins,
    }


def build_manifest(repositories_root: Path) -> dict[str, Any]:
    sources = {}
    for logical_name, directory_name in SOURCE_DIRS.items():
        sources[logical_name] = source_pin(
            logical_name, repositories_root / directory_name
        )
    return {
        "schema_version": "temporal-provenance-source-pins-v1",
        "status": "pinned",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "checkpoints": CHECKPOINTS,
        "sources": sources,
        "source_ceiling": {
            "ghsa_advisory_database": "provider_public_mirror_git",
            "cvelist_v5": "official_cve_list_git_cache",
            "fkie_nvd_json_data_feeds": "community_nvd_api_reconstruction_not_nvd_endorsed",
        },
    }


def main() -> int:
    args = parse_args()
    repositories_root = Path(args.repositories_root).resolve()
    output = Path(args.output).resolve()
    manifest = build_manifest(repositories_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"Pinned {len(manifest['sources'])} sources: {output}")
    for name, source in manifest["sources"].items():
        print(f"{name}: {source['head']['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

