#!/usr/bin/env python3
"""Download a GHSA advisory-database snapshot for offline processing."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


DEFAULT_URL = (
    "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"
)
DEFAULT_REPO_URL = "https://github.com/github/advisory-database.git"
DEFAULT_REF = "main"
SPARSE_PATHS = ["advisories/github-reviewed", "advisories/unreviewed"]
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = "data/raw/ghsa/advisory-database-main.tar.gz"
DEFAULT_EXTRACT_DIR = "data/raw/ghsa/advisory-database"


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found in PATH: {name}")


def validate_archive(archive_path: Path) -> None:
    """Fully walk the tar stream so truncated gzip files are rejected."""
    json_members = 0
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar:
            if member.isfile() and member.name.endswith(".json"):
                json_members += 1
    if json_members == 0:
        raise RuntimeError(f"Downloaded archive has no advisory JSON files: {archive_path}")


def build_network_env() -> dict[str, str]:
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


def build_git_command(repo_url: str) -> list[str]:
    command = ["git"]
    if repo_url.startswith("https://github.com/"):
        # Local git config on this machine pins GitHub to a dead socks proxy.
        command.extend(
            [
                "-c",
                "http.https://github.com.proxy=",
                "-c",
                "https.https://github.com.proxy=",
            ]
        )
    return command


def download_via_git_archive(
    destination: Path, repo_url: str = DEFAULT_REPO_URL, ref: str = DEFAULT_REF
) -> None:
    ensure_tool("git")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_destination = destination.with_suffix(destination.suffix + ".part")
    archive_prefix = f"{Path(repo_url).stem}-{ref}"
    last_error: str | None = None

    for attempt in range(1, 4):
        with tempfile.TemporaryDirectory(prefix="ghsa_git_clone_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo_dir = tmp_path / "advisory-database"

            clone_command = build_git_command(repo_url) + [
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "--branch",
                ref,
                "--single-branch",
                repo_url,
                str(repo_dir),
            ]
            clone_result = subprocess.run(
                clone_command,
                text=True,
                capture_output=True,
                env=build_network_env(),
            )
            if clone_result.returncode != 0:
                stderr = (clone_result.stderr or "").strip()
                last_error = (
                    f"git sparse clone failed with code {clone_result.returncode}"
                    + (f": {stderr}" if stderr else "")
                )
                print(
                    f"git fallback attempt {attempt}/3 failed during clone: {last_error}",
                    file=sys.stderr,
                )
                continue

            sparse_command = ["git", "-C", str(repo_dir), "sparse-checkout", "set", *SPARSE_PATHS]
            sparse_result = subprocess.run(
                sparse_command,
                text=True,
                capture_output=True,
                env=build_network_env(),
            )
            if sparse_result.returncode != 0:
                stderr = (sparse_result.stderr or "").strip()
                last_error = (
                    f"git sparse-checkout failed with code {sparse_result.returncode}"
                    + (f": {stderr}" if stderr else "")
                )
                print(
                    f"git fallback attempt {attempt}/3 failed during sparse checkout: {last_error}",
                    file=sys.stderr,
                )
                continue

            if temp_destination.exists():
                temp_destination.unlink()
            with tarfile.open(temp_destination, "w:gz") as tar:
                for sparse_path in SPARSE_PATHS:
                    source = repo_dir / sparse_path
                    if source.exists():
                        tar.add(source, arcname=f"{archive_prefix}/{sparse_path}")

            validate_archive(temp_destination)
            temp_destination.replace(destination)
            print(
                "Download complete via git fallback: "
                f"{destination} ({destination.stat().st_size} bytes)",
                file=sys.stderr,
            )
            return

    raise RuntimeError(last_error or "git fallback failed")


def download_file(url: str, destination: Path, retries: int = 5, timeout: int = 60) -> None:
    ensure_tool("curl")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_destination = destination.with_suffix(destination.suffix + ".part")

    if destination.exists():
        try:
            validate_archive(destination)
            print(f"Archive already valid, skipping download: {destination}", file=sys.stderr)
            return
        except Exception:
            destination.unlink()

    if temp_destination.exists():
        try:
            validate_archive(temp_destination)
            temp_destination.replace(destination)
            print(
                f"Recovered valid archive from partial download: {destination}",
                file=sys.stderr,
            )
            return
        except Exception:
            pass

    last_error: str | None = None
    can_resume = True
    for attempt in range(1, retries + 1):
        try:
            use_resume = can_resume and temp_destination.exists() and temp_destination.stat().st_size > 0
            if use_resume:
                print(
                    f"Attempt {attempt}/{retries}: resuming from byte {temp_destination.stat().st_size}",
                    file=sys.stderr,
                )
            else:
                if temp_destination.exists():
                    temp_destination.unlink()
                print(f"Attempt {attempt}/{retries}: starting fresh download", file=sys.stderr)

            command = [
                "curl",
                "--fail",
                "--location",
                "--output",
                str(temp_destination),
                "--connect-timeout",
                str(timeout),
                "--http1.1",
                "--speed-time",
                "180",
                "--speed-limit",
                "256",
                url,
            ]
            if use_resume:
                command[3:3] = ["--continue-at", "-"]

            completed = subprocess.run(
                command,
                text=True,
                capture_output=True,
                env=build_network_env(),
            )
            if completed.returncode != 0:
                stderr = (completed.stderr or "").strip()
                last_error = f"curl exited with code {completed.returncode}"
                if stderr:
                    print(stderr, file=sys.stderr)
                if "Cannot resume" in stderr or "doesn't seem to support byte ranges" in stderr:
                    can_resume = False
                    if temp_destination.exists():
                        temp_destination.unlink()
                print(
                    f"Download attempt {attempt}/{retries} failed: {last_error}",
                    file=sys.stderr,
                )
                continue
            validate_archive(temp_destination)
            temp_destination.replace(destination)
            print(
                f"Download complete: {destination} ({destination.stat().st_size} bytes)",
                file=sys.stderr,
            )
            return
        except (EOFError, OSError, tarfile.TarError, RuntimeError) as exc:
            last_error = str(exc)
            if temp_destination.exists():
                temp_destination.unlink()
            print(
                f"Download attempt {attempt}/{retries} failed: {exc}",
                file=sys.stderr,
            )

    if url == DEFAULT_URL:
        print(
            "curl download did not produce a valid archive; falling back to shallow git clone.",
            file=sys.stderr,
        )
        download_via_git_archive(destination)
        return

    if temp_destination.exists():
        temp_destination.unlink()
    if destination.exists():
        try:
            validate_archive(destination)
        except Exception:
            destination.unlink()

    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(
        f"Failed to download a valid GHSA snapshot after {retries} attempts{detail}"
    )


def extract_archive(archive_path: Path, extract_dir: Path) -> None:
    extract_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ghsa_extract_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(tmp_path)

        roots = [p for p in tmp_path.iterdir() if p.is_dir()]
        if len(roots) != 1:
            raise RuntimeError("Unexpected GHSA snapshot layout")

        extracted_root = roots[0]
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        shutil.copytree(extracted_root, extract_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch the GitHub advisory-database snapshot."
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help="Snapshot URL. Defaults to the official codeload tarball.",
    )
    parser.add_argument(
        "--archive",
        default=DEFAULT_ARCHIVE,
        help="Where to store the downloaded tar.gz archive.",
    )
    parser.add_argument(
        "--extract-dir",
        default=DEFAULT_EXTRACT_DIR,
        help="Directory to extract the snapshot into.",
    )
    parser.add_argument(
        "--skip-extract",
        action="store_true",
        help="Only download the tar.gz archive and skip extraction.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="How many times to retry a failed download.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    archive_path = resolve_path(args.archive)
    extract_dir = resolve_path(args.extract_dir)

    try:
        print(f"Downloading GHSA snapshot to {archive_path} ...", file=sys.stderr)
        download_file(args.url, archive_path, retries=args.retries)
        print(f"Saved archive: {archive_path}", file=sys.stderr)

        if not args.skip_extract:
            print(f"Extracting archive into {extract_dir} ...", file=sys.stderr)
            extract_archive(archive_path, extract_dir)
            print(f"Extracted snapshot: {extract_dir}", file=sys.stderr)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
