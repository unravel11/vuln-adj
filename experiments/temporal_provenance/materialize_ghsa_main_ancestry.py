#!/usr/bin/env python3
"""Materialize the complete pinned GHSA main first-parent ancestry.

The traversal deliberately has no date limiting. Encoded Git timestamps are
reported only after parent/child topology has been materialized.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ghsa_accepted_event_lib import ghsa_id_from_path
from temporal_provenance_lib import canonical_json, parse_utc, sha256_bytes


COMMIT_PREFIX = "@@@"


@dataclass
class ParsedCommit:
    oid: str
    parents: list[str]
    author_time: str
    committer_time: str
    subject: str
    changes: list[dict[str, Any]] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-pins",
        default="experiments/temporal_provenance/source_pins_v1.json",
    )
    parser.add_argument(
        "--repository",
        default=(
            "data/raw/temporal_provenance/pilot_v1/repositories_full/"
            "ghsa-advisory-database"
        ),
    )
    parser.add_argument(
        "--raw-output",
        default=(
            "data/raw/temporal_provenance/pilot_v1/ghsa_main_ancestry/"
            "git_log_name_status.txt"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=(
            "data/processed/temporal_provenance/pilot_v1/ghsa_main_ancestry"
        ),
    )
    return parser.parse_args()


def git(repository: Path, *arguments: str) -> bytes:
    command = ["git", "-C", str(repository), *arguments]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git command failed ({completed.returncode}): {message}")
    return completed.stdout


def build_log(repository: Path, pinned_commit: str) -> bytes:
    return git(
        repository,
        "-c",
        "core.quotepath=false",
        "log",
        "--first-parent",
        "--reverse",
        "--root",
        "-m",
        "--find-renames=50%",
        "--format=@@@%H%x09%P%x09%aI%x09%cI%x09%s",
        "--name-status",
        pinned_commit,
    )


def parse_change_line(line: str) -> dict[str, Any]:
    parts = line.split("\t")
    status = parts[0]
    if status.startswith(("R", "C")):
        if len(parts) != 3:
            raise ValueError(f"invalid rename/copy line: {line!r}")
        return {"status": status, "old_path": parts[1], "new_path": parts[2]}
    if len(parts) != 2:
        raise ValueError(f"invalid name-status line: {line!r}")
    if status == "D":
        return {"status": status, "old_path": parts[1], "new_path": None}
    return {"status": status, "old_path": None, "new_path": parts[1]}


def parse_log(raw: bytes) -> list[ParsedCommit]:
    commits: list[ParsedCommit] = []
    current: ParsedCommit | None = None
    text = raw.decode("utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        if line.startswith(COMMIT_PREFIX):
            fields = line[len(COMMIT_PREFIX) :].split("\t", 4)
            if len(fields) != 5:
                raise ValueError(f"invalid commit record at line {line_number}")
            oid, parents, author_time, committer_time, subject = fields
            current = ParsedCommit(
                oid=oid,
                parents=parents.split() if parents else [],
                author_time=author_time,
                committer_time=committer_time,
                subject=subject,
            )
            commits.append(current)
            continue
        if current is None:
            raise ValueError(f"change before first commit at line {line_number}")
        current.changes.append(parse_change_line(line))
    if not commits:
        raise ValueError("empty Git ancestry log")
    return commits


def validate_topology(commits: list[ParsedCommit], pinned_commit: str) -> list[dict[str, Any]]:
    failures = []
    if commits[-1].oid != pinned_commit:
        failures.append(
            {"kind": "pinned_tip_mismatch", "expected": pinned_commit, "actual": commits[-1].oid}
        )
    for position, commit in enumerate(commits):
        if position == 0:
            if commit.parents:
                failures.append(
                    {"kind": "first_parent_root_has_parent", "oid": commit.oid}
                )
            continue
        expected_parent = commits[position - 1].oid
        actual_parent = commit.parents[0] if commit.parents else None
        if actual_parent != expected_parent:
            failures.append(
                {
                    "kind": "first_parent_chain_break",
                    "oid": commit.oid,
                    "expected_first_parent": expected_parent,
                    "actual_first_parent": actual_parent,
                }
            )
    return failures


def commit_rows(commits: list[ParsedCommit]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = []
    clock_anomalies = []
    previous_time = None
    for position, commit in enumerate(commits):
        committer_time = parse_utc(commit.committer_time)
        anomaly = previous_time is not None and committer_time < previous_time
        if anomaly:
            clock_anomalies.append(
                {
                    "position": position,
                    "oid": commit.oid,
                    "previous_oid": commits[position - 1].oid,
                    "previous_committer_time": commits[position - 1].committer_time,
                    "committer_time": commit.committer_time,
                }
            )
        previous_time = committer_time
        advisory_paths = []
        ghsa_ids = set()
        advisory_change_count = 0
        for change in commit.changes:
            change_has_advisory = False
            for key in ("old_path", "new_path"):
                path = change.get(key)
                if not path:
                    continue
                ghsa_id = ghsa_id_from_path(path)
                if ghsa_id:
                    change_has_advisory = True
                    advisory_paths.append(path)
                    ghsa_ids.add(ghsa_id)
            if change_has_advisory:
                advisory_change_count += 1
        rows.append(
            {
                "position": position,
                "oid": commit.oid,
                "parents": commit.parents,
                "first_parent": commit.parents[0] if commit.parents else None,
                "author_time": commit.author_time,
                "committer_time": commit.committer_time,
                "clock_anomaly_from_previous": anomaly,
                "subject": commit.subject,
                "is_merge": len(commit.parents) > 1,
                "changed_file_count": len(commit.changes),
                "changed_advisory_file_count": advisory_change_count,
                "touched_advisory_path_count": len(set(advisory_paths)),
                "changed_ghsa_count": len(ghsa_ids),
            }
        )
    return rows, clock_anomalies


def advisory_change_rows(commits: list[ParsedCommit]) -> list[dict[str, Any]]:
    rows = []
    for position, commit in enumerate(commits):
        for change_position, change in enumerate(commit.changes):
            old_id = ghsa_id_from_path(change.get("old_path") or "")
            new_id = ghsa_id_from_path(change.get("new_path") or "")
            if old_id is None and new_id is None:
                continue
            rows.append(
                {
                    "commit_position": position,
                    "commit_oid": commit.oid,
                    "first_parent": commit.parents[0] if commit.parents else None,
                    "committer_time": commit.committer_time,
                    "change_position": change_position,
                    "status": change["status"],
                    "old_path": change.get("old_path"),
                    "new_path": change.get("new_path"),
                    "old_ghsa_id": old_id,
                    "new_ghsa_id": new_id,
                    "path_migration": bool(
                        old_id and new_id and old_id == new_id and change.get("old_path") != change.get("new_path")
                    ),
                }
            )
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> bytes:
    payload = b"".join((canonical_json(row) + "\n").encode("utf-8") for row in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def main() -> int:
    args = parse_args()
    source_pins_path = Path(args.source_pins).resolve()
    repository = Path(args.repository).resolve()
    raw_output = Path(args.raw_output).resolve()
    output_dir = Path(args.output_dir).resolve()
    pins = json.loads(source_pins_path.read_text(encoding="utf-8"))
    source = pins["sources"]["ghsa_advisory_database"]
    pinned_commit = source["head"]["commit"]
    object_type = git(repository, "cat-file", "-t", pinned_commit).decode().strip()
    if object_type != "commit":
        raise ValueError(f"pinned GHSA object is not a commit: {pinned_commit}")
    object_format = git(repository, "rev-parse", "--show-object-format").decode().strip()
    if object_format != source.get("object_format"):
        raise ValueError("repository object format differs from source pin")

    raw = build_log(repository, pinned_commit)
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    raw_output.write_bytes(raw)
    commits = parse_log(raw)
    topology_failures = validate_topology(commits, pinned_commit)
    rows, clock_anomalies = commit_rows(commits)
    changes = advisory_change_rows(commits)
    commits_path = output_dir / "commits.jsonl"
    changes_path = output_dir / "advisory_changes.jsonl"
    commits_bytes = write_jsonl(commits_path, rows)
    changes_bytes = write_jsonl(changes_path, changes)
    strata = Counter()
    for row in rows:
        count = row["changed_advisory_file_count"]
        if count == 1:
            strata["1"] += 1
        elif 2 <= count <= 9:
            strata["2-9"] += 1
        elif 10 <= count <= 99:
            strata["10-99"] += 1
        elif count >= 100:
            strata[">=100"] += 1
        else:
            strata["0"] += 1
    status = "complete" if not topology_failures else "topology_invalid"
    manifest = {
        "schema_version": "ghsa-main-first-parent-ancestry-v1",
        "status": status,
        "source_pin": pinned_commit,
        "repository": str(repository),
        "origin": git(repository, "remote", "get-url", "origin").decode().strip(),
        "object_format": object_format,
        "traversal": {
            "first_parent": True,
            "reverse": True,
            "root_diff": True,
            "date_limits": False,
            "merge_diff": "-m with --first-parent (Git 2.27 compatible)",
            "rename_threshold": "50%",
        },
        "commit_count": len(rows),
        "merge_commit_count": sum(row["is_merge"] for row in rows),
        "advisory_change_rows": len(changes),
        "clock_anomaly_count": len(clock_anomalies),
        "clock_anomalies": clock_anomalies,
        "topology_failures": topology_failures,
        "changed_advisory_path_commit_strata": dict(sorted(strata.items())),
        "raw_log": {
            "path": str(raw_output),
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
        },
        "commits": {
            "path": str(commits_path),
            "sha256": sha256_bytes(commits_bytes),
            "records": len(rows),
        },
        "advisory_changes": {
            "path": str(changes_path),
            "sha256": sha256_bytes(changes_bytes),
            "records": len(changes),
        },
        "claim_ceiling": (
            "Git topology and encoded timestamps only; not public exposure time, "
            "field semantics, accepted disposition, or factual correction."
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"GHSA main ancestry {status}: commits={len(rows)} "
        f"advisory_changes={len(changes)} clock_anomalies={len(clock_anomalies)}"
    )
    print(f"Manifest: {manifest_path}")
    return 0 if status == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
