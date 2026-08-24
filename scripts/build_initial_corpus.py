#!/usr/bin/env python3
"""Build initial normalized NVD/GHSA datasets and CVE-based alignments."""

from __future__ import annotations

import argparse
import io
import json
import shutil
import subprocess
import tarfile
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


NVD_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required tool not found in PATH: {name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize NVD and GHSA records into aligned JSONL datasets."
    )
    parser.add_argument(
        "--raw-dir",
        default="data/raw",
        help="Directory containing raw NVD files and optional GHSA snapshot.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/processed/bootstrap",
        help="Directory for normalized outputs.",
    )
    parser.add_argument(
        "--nvd-glob",
        default="nvdcve-2.0-*.json*",
        help="Glob pattern for raw NVD files inside --raw-dir.",
    )
    parser.add_argument(
        "--nvd-output-name",
        default="nvd_2023_2025.normalized.jsonl",
        help="Filename for normalized NVD JSONL inside the output nvd directory.",
    )
    parser.add_argument(
        "--ghsa-archive",
        default="data/raw/ghsa/advisory-database-main.tar.gz",
        help="GHSA tar.gz snapshot path.",
    )
    parser.add_argument(
        "--ghsa-dir",
        default="data/raw/ghsa/advisory-database",
        help="Extracted GHSA advisory-database path.",
    )
    parser.add_argument(
        "--include-unreviewed",
        action="store_true",
        help="Include unreviewed GHSA advisories in addition to github-reviewed.",
    )
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def resolve_nvd_inputs(raw_dir: Path, pattern: str) -> list[Path]:
    selected_by_year: dict[str, Path] = {}
    for path in sorted(raw_dir.glob(pattern)):
        year = path.name.split("-")[2].split(".")[0]
        current = selected_by_year.get(year)
        if current is None:
            selected_by_year[year] = path
            continue
        # Prefer plain JSON when both .json and .json.zip exist for the same year.
        if current.suffix == ".zip" and path.suffix == ".json":
            selected_by_year[year] = path
    return [selected_by_year[year] for year in sorted(selected_by_year)]


def choose_nvd_metric(metrics: dict) -> tuple[str | None, dict | None]:
    for key in NVD_METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        preferred = next(
            (
                entry
                for entry in entries
                if entry.get("type") == "Primary"
                or entry.get("source") == "nvd@nist.gov"
            ),
            entries[0],
        )
        return key, preferred
    return None, None


def extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    cwe_ids: set[str] = set()
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if isinstance(value, str) and value.startswith("CWE-"):
                cwe_ids.add(value)
    return sorted(cwe_ids)


def normalize_reference(reference: dict) -> dict:
    url = reference.get("url")
    host = urlparse(url).netloc.lower() if url else None
    return {
        "url": url,
        "host": host,
        "source": reference.get("source"),
        "tags": reference.get("tags") or [],
    }


def parse_cpe_criteria(criteria: str | None) -> dict:
    if not criteria:
        return {"vendor": None, "product": None, "version": None}
    parts = criteria.split(":")
    return {
        "vendor": parts[3] if len(parts) > 3 else None,
        "product": parts[4] if len(parts) > 4 else None,
        "version": parts[5] if len(parts) > 5 else None,
    }


def walk_nvd_nodes(nodes: list[dict]) -> Iterable[dict]:
    for node in nodes or []:
        for match in node.get("cpeMatch", []) or []:
            yield match
        yield from walk_nvd_nodes(node.get("children", []) or [])


def normalize_nvd_match(match: dict) -> dict:
    parsed = parse_cpe_criteria(match.get("criteria"))
    return {
        "source_type": "cpe",
        "criteria": match.get("criteria"),
        "vendor": parsed["vendor"],
        "product": parsed["product"],
        "package_name": parsed["product"],
        "ecosystem": None,
        "version": parsed["version"],
        "introduced": match.get("versionStartIncluding")
        or match.get("versionStartExcluding"),
        "fixed": None,
        "version_start_including": match.get("versionStartIncluding"),
        "version_start_excluding": match.get("versionStartExcluding"),
        "version_end_including": match.get("versionEndIncluding"),
        "version_end_excluding": match.get("versionEndExcluding"),
        "vulnerable": match.get("vulnerable"),
    }


def normalize_nvd_affected(configurations: list[dict]) -> list[dict]:
    affected = []
    for config in configurations or []:
        for match in walk_nvd_nodes(config.get("nodes", []) or []):
            # Non-vulnerable CPE matches express applicability constraints, not
            # affected products or versions.
            if match.get("vulnerable") is False:
                continue
            affected.append(normalize_nvd_match(match))
    return affected


def normalize_nvd_record(cve: dict) -> dict:
    metric_key, metric_entry = choose_nvd_metric(cve.get("metrics") or {})
    cvss = metric_entry.get("cvssData") if metric_entry else {}
    descriptions = [
        item.get("value")
        for item in cve.get("descriptions", [])
        if item.get("lang") == "en" and item.get("value")
    ]

    return {
        "source": "nvd",
        "source_id": cve.get("id"),
        "cve_id": cve.get("id"),
        "aliases": [cve.get("id")] if cve.get("id") else [],
        "summary": descriptions[0] if descriptions else None,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "severity": {
            "metric_key": metric_key,
            "score": cvss.get("baseScore"),
            "label": cvss.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "source": metric_entry.get("source") if metric_entry else None,
        },
        "cwe_ids": extract_cwe_ids(cve.get("weaknesses") or []),
        "references": [
            normalize_reference(reference) for reference in cve.get("references", []) or []
        ],
        "affected": normalize_nvd_affected(cve.get("configurations") or []),
        "source_specific": {
            "vuln_status": cve.get("vulnStatus"),
        },
    }


def iter_nvd_cves(path: Path) -> Iterable[dict]:
    ensure_tool("jq")
    if path.suffix == ".zip":
        unzip = subprocess.Popen(["unzip", "-p", str(path)], stdout=subprocess.PIPE)
        jq = subprocess.Popen(
            ["jq", "-c", ".vulnerabilities[].cve"],
            stdin=unzip.stdout,
            stdout=subprocess.PIPE,
            text=True,
        )
        if unzip.stdout is not None:
            unzip.stdout.close()
        assert jq.stdout is not None
        for line in jq.stdout:
            yield json.loads(line)
        jq.wait()
        unzip.wait()
        if jq.returncode != 0:
            raise RuntimeError(f"jq failed while processing {path}")
    else:
        jq = subprocess.Popen(
            ["jq", "-c", ".vulnerabilities[].cve", str(path)],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert jq.stdout is not None
        for line in jq.stdout:
            yield json.loads(line)
        jq.wait()
        if jq.returncode != 0:
            raise RuntimeError(f"jq failed while processing {path}")


def iter_ghsa_json_sources(
    ghsa_dir: Path, ghsa_archive: Path, include_unreviewed: bool
) -> Iterable[tuple[str, bytes]]:
    wanted_prefixes = ["advisories/github-reviewed/"]
    if include_unreviewed:
        wanted_prefixes.append("advisories/unreviewed/")

    if ghsa_dir.exists():
        for json_path in sorted(ghsa_dir.rglob("*.json")):
            rel = json_path.relative_to(ghsa_dir).as_posix()
            if any(rel.startswith(prefix) for prefix in wanted_prefixes):
                yield rel, json_path.read_bytes()
        return

    if ghsa_archive.exists():
        with tarfile.open(ghsa_archive, "r:gz") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                normalized_name = member.name.split("/", 1)[1]
                if any(normalized_name.startswith(prefix) for prefix in wanted_prefixes):
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    yield normalized_name, extracted.read()
        return

    raise FileNotFoundError(
        f"Neither GHSA directory nor archive found: {ghsa_dir} / {ghsa_archive}"
    )


def is_valid_ghsa_dir(path: Path) -> bool:
    return path.exists() and (path / "advisories").is_dir()


def is_valid_ghsa_archive(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return False
    try:
        with tarfile.open(path, "r:gz") as tar:
            json_members = 0
            for member in tar:
                if member.name.endswith(".json") and "/advisories/" in member.name:
                    json_members += 1
    except (tarfile.TarError, EOFError, OSError):
        return False
    return json_members > 0


def pick_cve_alias(aliases: list[str]) -> str | None:
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    return None


def normalize_ghsa_affected(record: dict) -> list[dict]:
    affected = []
    for item in record.get("affected", []) or []:
        package = item.get("package") or {}
        ranges = item.get("ranges") or []
        versions = item.get("versions") or []

        if not ranges and not versions:
            affected.append(
                {
                    "source_type": "ghsa",
                    "criteria": None,
                    "vendor": None,
                    "product": package.get("name"),
                    "package_name": package.get("name"),
                    "ecosystem": package.get("ecosystem"),
                    "version": None,
                    "introduced": None,
                    "fixed": None,
                    "version_start_including": None,
                    "version_start_excluding": None,
                    "version_end_including": None,
                    "version_end_excluding": None,
                    "vulnerable": True,
                }
            )

        for range_item in ranges:
            events = range_item.get("events") or []
            introduced = [e.get("introduced") for e in events if "introduced" in e]
            fixed = [e.get("fixed") for e in events if "fixed" in e]
            last_known = versions[-1] if versions else None
            affected.append(
                {
                    "source_type": "ghsa",
                    "criteria": None,
                    "vendor": None,
                    "product": package.get("name"),
                    "package_name": package.get("name"),
                    "ecosystem": package.get("ecosystem"),
                    "version": last_known,
                    "introduced": introduced[0] if introduced else None,
                    "fixed": fixed[0] if fixed else None,
                    "version_start_including": introduced[0] if introduced else None,
                    "version_start_excluding": None,
                    "version_end_including": None,
                    "version_end_excluding": fixed[0] if fixed else None,
                    "vulnerable": True,
                }
            )
    return affected


def normalize_ghsa_record(record: dict, relative_path: str) -> dict:
    aliases = record.get("aliases") or []
    severity_items = record.get("severity") or []
    severity = severity_items[0] if severity_items else {}
    db_specific = record.get("database_specific") or {}

    return {
        "source": "ghsa",
        "source_id": record.get("id"),
        "cve_id": pick_cve_alias(aliases),
        "aliases": aliases,
        "summary": record.get("summary"),
        "published": record.get("published"),
        "last_modified": record.get("modified"),
        "severity": {
            "metric_key": severity.get("type"),
            "score": None,
            "label": db_specific.get("severity"),
            "vector": severity.get("score"),
            "source": "github-advisory-database",
        },
        "cwe_ids": sorted(db_specific.get("cwe_ids") or []),
        "references": [
            normalize_reference(reference) for reference in record.get("references", []) or []
        ],
        "affected": normalize_ghsa_affected(record),
        "source_specific": {
            "github_reviewed": db_specific.get("github_reviewed"),
            "github_reviewed_at": db_specific.get("github_reviewed_at"),
            "nvd_published_at": db_specific.get("nvd_published_at"),
            "relative_path": relative_path,
        },
    }


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    count = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def build_nvd_dataset(nvd_paths: list[Path], output_path: Path) -> tuple[int, dict[str, int]]:
    year_counts: dict[str, int] = defaultdict(int)

    def rows() -> Iterable[dict]:
        for path in nvd_paths:
            year = path.name.split("-")[2].split(".")[0]
            for cve in iter_nvd_cves(path):
                year_counts[year] += 1
                yield normalize_nvd_record(cve)

    count = write_jsonl(output_path, rows())
    return count, dict(sorted(year_counts.items()))


def build_ghsa_dataset(
    ghsa_dir: Path, ghsa_archive: Path, include_unreviewed: bool, output_path: Path
) -> tuple[int, dict[str, int]]:
    year_counts: dict[str, int] = defaultdict(int)

    def rows() -> Iterable[dict]:
        for rel_path, raw_bytes in iter_ghsa_json_sources(
            ghsa_dir, ghsa_archive, include_unreviewed
        ):
            record = json.load(io.TextIOWrapper(io.BytesIO(raw_bytes), encoding="utf-8"))
            parts = rel_path.split("/")
            if len(parts) >= 3:
                year_counts[parts[2]] += 1
            yield normalize_ghsa_record(record, rel_path)

    try:
        count = write_jsonl(output_path, rows())
    except (tarfile.TarError, EOFError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Failed to read GHSA snapshot. The archive or extracted directory is "
            "incomplete or corrupted. Re-run fetch_ghsa_snapshot.py."
        ) from exc
    return count, dict(sorted(year_counts.items()))


def build_alignment(
    nvd_path: Path, ghsa_path: Path, output_path: Path
) -> tuple[int, int]:
    ghsa_by_cve: dict[str, list[dict]] = defaultdict(list)
    with ghsa_path.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            cve_id = record.get("cve_id")
            if cve_id:
                ghsa_by_cve[cve_id].append(record)

    matched = 0
    emitted = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        with nvd_path.open(encoding="utf-8") as nvd_handle:
            for line in nvd_handle:
                nvd_record = json.loads(line)
                cve_id = nvd_record.get("cve_id")
                ghsa_records = ghsa_by_cve.get(cve_id, [])
                if ghsa_records:
                    matched += 1
                handle.write(
                    json.dumps(
                        {
                            "cve_id": cve_id,
                            "nvd": nvd_record,
                            "ghsa": ghsa_records,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                emitted += 1
    return emitted, matched


def main() -> int:
    args = parse_args()
    raw_dir = resolve_path(args.raw_dir)
    output_dir = resolve_path(args.output_dir)
    ghsa_archive = resolve_path(args.ghsa_archive)
    ghsa_dir = resolve_path(args.ghsa_dir)

    nvd_paths = resolve_nvd_inputs(raw_dir, args.nvd_glob)
    if not nvd_paths:
        raise FileNotFoundError(f"No NVD files matched: {raw_dir / args.nvd_glob}")

    if Path(args.nvd_output_name).name != args.nvd_output_name:
        raise ValueError("--nvd-output-name must be a filename, not a path")
    nvd_output = output_dir / "nvd" / args.nvd_output_name
    ghsa_output = output_dir / "ghsa" / "ghsa.normalized.jsonl"
    align_output = output_dir / "aligned" / "nvd_ghsa_by_cve.jsonl"
    manifest_output = output_dir / "manifests" / "bootstrap_summary.json"

    nvd_count, nvd_year_counts = build_nvd_dataset(nvd_paths, nvd_output)

    ghsa_count = 0
    ghsa_year_counts: dict[str, int] = {}
    ghsa_source_available = False
    if is_valid_ghsa_dir(ghsa_dir):
        ghsa_source_available = True
    elif is_valid_ghsa_archive(ghsa_archive):
        ghsa_source_available = True
    elif ghsa_dir.exists() or ghsa_archive.exists():
        print(
            "Warning: GHSA snapshot exists but is incomplete or invalid. "
            "Skipping GHSA until you re-run fetch_ghsa_snapshot.py successfully.",
            file=sys.stderr,
        )

    if ghsa_source_available:
        try:
            ghsa_count, ghsa_year_counts = build_ghsa_dataset(
                ghsa_dir, ghsa_archive, args.include_unreviewed, ghsa_output
            )
            aligned_rows, matched_rows = build_alignment(
                nvd_output, ghsa_output, align_output
            )
        except RuntimeError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
            ghsa_count, ghsa_year_counts = 0, {}
            aligned_rows, matched_rows = 0, 0
    else:
        aligned_rows, matched_rows = 0, 0

    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.write_text(
        json.dumps(
            {
                "nvd_files": [str(path) for path in nvd_paths],
                "nvd_records": nvd_count,
                "nvd_year_counts": nvd_year_counts,
                "ghsa_records": ghsa_count,
                "ghsa_year_counts": ghsa_year_counts,
                "aligned_rows": aligned_rows,
                "matched_rows": matched_rows,
                "include_unreviewed": args.include_unreviewed,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"NVD normalized:   {nvd_output} ({nvd_count} records)")
    if ghsa_count:
        print(f"GHSA normalized:  {ghsa_output} ({ghsa_count} records)")
        print(f"CVE alignments:   {align_output} ({matched_rows} matched)")
    else:
        print("GHSA normalized:  skipped (snapshot not present)")
    print(f"Manifest:         {manifest_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
