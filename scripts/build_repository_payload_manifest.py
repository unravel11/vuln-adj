#!/usr/bin/env python3
"""Build or verify the hash inventory for retained, Git-ignored payloads."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path


SCHEMA = "vuln-adj-retained-local-payloads-v1"
DEFAULT_ROOTS = (
    "data/raw",
    "data/processed",
    "data/evidence_cache",
    "data/external",
    "data/annotations/ai_adjudicated_gold",
    "data/annotations/expert_candidate",
    "data/annotations/holdout",
    "data/annotations/phase_d",
    "data/annotations/rq2/consistency_review",
    "data/annotations/rq2/cwe_taxonomy_impact_human_review",
    "data/annotations/rq2/reference_normalization_impact_human_review",
    "data/annotations/rq3",
    "results",
    "docs/related_work_papers",
    "paper/cose",
)
DEFAULT_OUTPUT = "docs/repository_hygiene/retained_local_payloads.sha256.tsv"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def candidate_paths(repo: Path, roots: tuple[str, ...]) -> list[str]:
    paths: list[str] = []
    for root_text in roots:
        root = repo / root_text
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(f"refusing to hash symlink: {path}")
            if not path.is_file():
                continue
            relative = path.relative_to(repo).as_posix()
            if "\t" in relative or "\n" in relative:
                raise RuntimeError(f"unsupported path characters: {relative!r}")
            paths.append(relative)
    return sorted(set(paths))


def ignored_paths(repo: Path, roots: tuple[str, ...]) -> list[str]:
    candidates = candidate_paths(repo, roots)
    if not candidates:
        return []
    encoded = b"\0".join(os.fsencode(path) for path in candidates) + b"\0"
    completed = subprocess.run(
        ["git", "check-ignore", "-z", "--stdin"],
        cwd=repo,
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
    return sorted(
        os.fsdecode(item)
        for item in completed.stdout.split(b"\0")
        if item
    )


def build_rows(repo: Path, roots: tuple[str, ...]) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    for relative in ignored_paths(repo, roots):
        path = repo / relative
        rows.append((sha256_file(path), path.stat().st_size, relative))
    return rows


def write_manifest(
    output: Path, rows: list[tuple[str, int, str]], roots: tuple[str, ...]
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = sum(size for _, size, _ in rows)
    lines = [
        f"# schema={SCHEMA}",
        f"# roots={','.join(roots)}",
        f"# file_count={len(rows)}",
        f"# total_bytes={total_bytes}",
        "sha256\tbytes\tpath",
    ]
    lines.extend(f"{digest}\t{size}\t{path}" for digest, size, path in rows)
    payload = "\n".join(lines) + "\n"
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output.parent, delete=False
    ) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    temporary.replace(output)


def read_manifest(path: Path) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or line == "sha256\tbytes\tpath":
                continue
            digest, size_text, relative = line.split("\t", 2)
            rows.append((digest, int(size_text), relative))
    return rows


def verify_manifest(repo: Path, output: Path, roots: tuple[str, ...]) -> None:
    expected = read_manifest(output)
    current_ignored = ignored_paths(repo, roots)
    expected_paths = [relative for _, _, relative in expected]
    if current_ignored != expected_paths:
        missing = sorted(set(expected_paths) - set(current_ignored))
        extra = sorted(set(current_ignored) - set(expected_paths))
        raise RuntimeError(
            f"payload path set changed: missing={len(missing)} extra={len(extra)}"
        )
    for expected_digest, expected_size, relative in expected:
        path = repo / relative
        actual_size = path.stat().st_size
        if actual_size != expected_size:
            raise RuntimeError(
                f"size mismatch for {relative}: {actual_size} != {expected_size}"
            )
        actual_digest = sha256_file(path)
        if actual_digest != expected_digest:
            raise RuntimeError(f"sha256 mismatch for {relative}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path(DEFAULT_OUTPUT))
    parser.add_argument("--root", action="append", dest="roots")
    parser.add_argument("--verify", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = args.repo.resolve()
    roots = tuple(args.roots or DEFAULT_ROOTS)
    output = args.output
    if not output.is_absolute():
        output = repo / output
    if args.verify:
        verify_manifest(repo, output, roots)
        rows = read_manifest(output)
        print(
            "PASS: retained payload manifest verified; "
            f"files={len(rows)} bytes={sum(size for _, size, _ in rows)}"
        )
        return 0
    rows = build_rows(repo, roots)
    write_manifest(output, rows, roots)
    print(
        "WROTE: retained payload manifest; "
        f"files={len(rows)} bytes={sum(size for _, size, _ in rows)} output={output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
