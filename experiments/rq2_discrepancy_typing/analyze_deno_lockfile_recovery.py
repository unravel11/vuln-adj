#!/usr/bin/env python3
"""Recover the fixed Deno product-to-runtime edge from official Cargo.lock files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "deno_lockfile_recovery_v1"
SAMPLE_ID = "artifact_lineage_unseen_ecosystem_v1:cratesio"
CVE_ID = "CVE-2025-48888"
DEFAULT_COHORT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_unseen_ecosystem_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/affected_versions_deno_lockfile_recovery_contract_v1.md"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/deno_lockfile_recovery_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "deno_lockfile_recovery_v1"
)
RELEASES_URL = "https://api.github.com/repos/denoland/deno/releases?per_page=100&page={page}"
RUNTIME_CATALOG_URL = "https://crates.io/api/v1/crates/deno_runtime"
LOCKFILE_URL = "https://raw.githubusercontent.com/denoland/deno/{tag}/Cargo.lock"
MAX_RESPONSE_BYTES = 12_000_000
MAX_RELEASE_PAGES = 20
STABLE_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")

LOWER_PRODUCT = (1, 41, 3)
UPPER_PRODUCT = (2, 3, 2)
LOWER_RUNTIME = (0, 150, 0)
UPPER_RUNTIME = (0, 212, 0)
DIRECT_SPANS = (
    ((1, 41, 3), (2, 1, 13)),
    ((2, 2, 0), (2, 2, 13)),
    ((2, 3, 0), (2, 3, 2)),
)
EXPECTED_NVD_SIGNATURE = [
    {"end": "2.1.13", "end_inclusive": False, "kind": "range", "start": "1.41.3", "start_inclusive": True},
    {"end": "2.2.13", "end_inclusive": False, "kind": "range", "start": "2.2.0", "start_inclusive": True},
    {"end": "2.3.2", "end_inclusive": False, "kind": "range", "start": "2.3.0", "start_inclusive": True},
]
EXPECTED_GHSA_SIGNATURES = {
    "deno": EXPECTED_NVD_SIGNATURE,
    "deno_runtime": [
        {"end": "0.212.0", "end_inclusive": False, "kind": "range", "start": "0.150.0", "start_inclusive": True}
    ],
}


@dataclass(frozen=True, order=True)
class StableVersion:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "StableVersion | None":
        match = STABLE_TAG.fullmatch(raw)
        if match is None:
            return None
        return cls(*(int(value) for value in match.groups()))

    def text(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def as_tuple(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", default=DEFAULT_COHORT_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return bytes_sha256(path.read_bytes())


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def cache_paths(cache_dir: Path, key: str) -> tuple[Path, Path]:
    return cache_dir / f"{key}.response", cache_dir / f"{key}.fetch.json"


def fetch_or_load(
    key: str,
    url: str,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[bytes, dict, tuple[Path, Path]]:
    response_path, metadata_path = cache_paths(cache_dir, key)
    if response_path.exists() and metadata_path.exists() and not refresh:
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != url:
            raise ValueError(f"cached URL drift for {key}")
        if metadata.get("response_sha256") != bytes_sha256(body):
            raise ValueError(f"cached response hash mismatch for {key}")
        return body, metadata, (response_path, metadata_path)

    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "vuln-adj-deno-lockfile-recovery/1.0",
        },
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                status = response.status
                content_type = response.headers.get("Content-Type")
                body = response.read(MAX_RESPONSE_BYTES + 1)
            break
        except HTTPError as exc:
            status = exc.code
            content_type = exc.headers.get("Content-Type") if exc.headers else None
            body = exc.read(MAX_RESPONSE_BYTES + 1)
            break
        except (TimeoutError, URLError) as exc:
            last_error = exc
            if attempt == 2:
                raise RuntimeError(f"failed to fetch {url}: {exc}") from exc
            time.sleep(2**attempt)
    else:  # pragma: no cover
        raise RuntimeError(f"failed to fetch {url}: {last_error}")

    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response exceeds byte limit for {key}")
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "url": url,
        "http_status": status,
        "content_type": content_type,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "response_sha256": bytes_sha256(body),
        "response_bytes": len(body),
    }
    response_path.write_bytes(body)
    write_json(metadata_path, metadata)
    return body, metadata, (response_path, metadata_path)


def load_fixed_row(cohort_path: Path, manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["output"]["sha256"] != file_sha256(cohort_path):
        raise ValueError("sealed cohort hash mismatch")
    rows = [
        json.loads(line)
        for line in cohort_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    matches = [row for row in rows if row.get("sample_id") == SAMPLE_ID]
    if len(matches) != 1:
        raise ValueError(f"expected one fixed Deno row, found {len(matches)}")
    row = matches[0]
    checks = {
        "cve_id": row.get("cve_id") == CVE_ID,
        "field": row.get("field") == "affected_versions",
        "ecosystem": row.get("ecosystem") == "crates.io",
        "nvd_subject": row.get("nvd_subject") == "deno",
        "ghsa_subjects": row.get("ghsa_subjects") == ["deno", "deno_runtime"],
        "nvd_signature": row.get("nvd_range_signature") == EXPECTED_NVD_SIGNATURE,
        "ghsa_signatures": row.get("ghsa_component_range_signatures") == EXPECTED_GHSA_SIGNATURES,
        "non_human_boundary": row.get("label_is_human") is False
        and row.get("eligible_for_human_gold_claim") is False,
    }
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise ValueError(f"fixed Deno row drift: {failed}")
    return row


def eligible_releases(page_documents: list[list[dict]]) -> dict[StableVersion, str]:
    releases: dict[StableVersion, str] = {}
    duplicates: list[str] = []
    for page in page_documents:
        for item in page:
            if item.get("draft") is not False or item.get("prerelease") is not False:
                continue
            tag = item.get("tag_name")
            version = StableVersion.parse(tag) if isinstance(tag, str) else None
            if version is None:
                continue
            if version in releases:
                duplicates.append(version.text())
            else:
                releases[version] = tag
    if duplicates:
        raise ValueError(f"duplicate eligible release versions: {sorted(set(duplicates))}")
    return releases


def select_product_domain(releases: dict[StableVersion, str]) -> dict:
    lower = StableVersion(*LOWER_PRODUCT)
    upper = StableVersion(*UPPER_PRODUCT)
    ordered = sorted(releases)
    core = [version for version in ordered if lower <= version <= upper]
    before = [version for version in ordered if version < lower]
    after = [version for version in ordered if version > upper]
    if not core or not before or not after:
        raise ValueError("could not establish fixed core product window and both anchors")
    predecessor = before[-1]
    successor = after[0]
    required_boundaries = {
        StableVersion.parse(raw)
        for raw in ("1.41.3", "2.1.13", "2.2.0", "2.2.13", "2.3.0", "2.3.2")
    }
    missing = sorted(version.text() for version in required_boundaries if version not in releases)
    return {
        "core": core,
        "predecessor": predecessor,
        "successor": successor,
        "missing_boundaries": missing,
        "selected": [predecessor, *core, successor],
    }


def parse_runtime_catalog(body: bytes) -> dict[str, dict]:
    document = json.loads(body)
    crate = document.get("crate") or {}
    if crate.get("id") != "deno_runtime":
        raise ValueError("runtime catalog identity mismatch")
    versions = {}
    for item in document.get("versions") or []:
        raw = item.get("num")
        parsed = StableVersion.parse(raw) if isinstance(raw, str) else None
        if parsed is not None:
            versions[parsed.text()] = {"yanked": bool(item.get("yanked"))}
    if not versions:
        raise ValueError("runtime catalog has no stable semantic versions")
    return versions


def parse_lockfile_runtime(body: bytes) -> dict:
    document = tomllib.loads(body.decode("utf-8"))
    matches = [item for item in document.get("package", []) if item.get("name") == "deno_runtime"]
    if len(matches) != 1:
        return {"passed": False, "match_count": len(matches), "runtime_version": None}
    raw = matches[0].get("version")
    parsed = StableVersion.parse(raw) if isinstance(raw, str) else None
    return {
        "passed": parsed is not None,
        "match_count": 1,
        "runtime_version": parsed.text() if parsed is not None else None,
    }


def in_spans(version: StableVersion, spans: tuple) -> bool:
    value = version.as_tuple()
    return any(lower <= value < upper for lower, upper in spans)


def set_relation(nvd: set[str], ghsa: set[str]) -> str:
    if nvd == ghsa:
        return "equal"
    if nvd < ghsa:
        return "nvd_subset_of_ghsa"
    if ghsa < nvd:
        return "ghsa_subset_of_nvd"
    if nvd & ghsa:
        return "overlap"
    return "disjoint"


def relation_candidate(relation: str | None) -> str:
    if relation == "equal":
        return "representation_discrepancy"
    if relation in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    if relation in {"overlap", "disjoint"}:
        return "factual_conflict"
    return "uncertain"


def render_markdown(analysis: dict) -> str:
    gate = analysis["gate"]
    sets = analysis["product_sets"]
    lines = [
        "# Deno Lockfile Recovery Diagnostic v1",
        "",
        f"- CVE: `{analysis['cve_id']}`",
        f"- Product releases in core window: `{analysis['release_domain']['core_count']}`",
        f"- Exact lockfile mappings: `{analysis['mapping_summary']['valid_mapping_count']}/{analysis['mapping_summary']['required_mapping_count']}`",
        f"- Projection gate: `{gate['status']}`",
        f"- Set relation: `{gate['set_relation']}`",
        f"- Non-human development candidate: `{gate['development_typing_candidate']}`",
        "- `label_is_human=false`",
        "",
        "## Product sets",
        "",
        f"- NVD direct: `{len(sets['nvd_direct'])}`",
        f"- GHSA direct: `{len(sets['ghsa_direct'])}`",
        f"- GHSA runtime projection: `{len(sets['ghsa_runtime_projected'])}`",
        f"- GHSA union: `{len(sets['ghsa_union'])}`",
        f"- Runtime-only additions: `{', '.join(sets['runtime_only_additions']) or 'none'}`",
        "",
        "This post-no-go diagnostic tests one official build-lock mapping. It is not human gold, accuracy evidence, or a general Rust ecosystem result.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    cohort_dir = resolve(args.cohort_dir)
    cohort_path = cohort_dir / "cohort.jsonl"
    cohort_manifest_path = cohort_dir / "manifest.sealed.json"
    contract_path = resolve(args.contract)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite Deno recovery result: {output_dir}")
    row = load_fixed_row(cohort_path, cohort_manifest_path)
    if not contract_path.is_file():
        raise FileNotFoundError(contract_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_artifacts: list[Path] = []

    page_documents = []
    page_counts = []
    for page_number in range(1, MAX_RELEASE_PAGES + 1):
        key = f"deno_github_releases_page_{page_number:03d}"
        body, metadata, paths = fetch_or_load(
            key,
            RELEASES_URL.format(page=page_number),
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        cache_artifacts.extend(paths)
        if metadata.get("http_status") != 200:
            raise ValueError(f"release page {page_number} returned {metadata.get('http_status')}")
        document = json.loads(body)
        if not isinstance(document, list):
            raise ValueError(f"release page {page_number} is not a list")
        page_documents.append(document)
        page_counts.append(len(document))
        if not document:
            break
    else:
        raise ValueError("release pagination did not reach an empty page")

    releases = eligible_releases(page_documents)
    domain = select_product_domain(releases)

    catalog_body, catalog_metadata, catalog_paths = fetch_or_load(
        "deno_runtime_crates_catalog",
        RUNTIME_CATALOG_URL,
        cache_dir,
        timeout_seconds=args.timeout_seconds,
        refresh=args.refresh,
    )
    cache_artifacts.extend(catalog_paths)
    if catalog_metadata.get("http_status") != 200:
        raise ValueError(f"runtime catalog returned {catalog_metadata.get('http_status')}")
    runtime_catalog = parse_runtime_catalog(catalog_body)

    lock_results: dict[str, dict] = {}
    selected = domain["selected"]

    def fetch_lock(version: StableVersion) -> tuple[StableVersion, bytes, dict, tuple[Path, Path]]:
        tag = releases[version]
        key = f"deno_{version.text().replace('.', '_')}_cargo_lock"
        return (
            version,
            *fetch_or_load(
                key,
                LOCKFILE_URL.format(tag=quote(tag, safe="")),
                cache_dir,
                timeout_seconds=args.timeout_seconds,
                refresh=args.refresh,
            ),
        )

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(fetch_lock, version): version for version in selected}
        for future in as_completed(futures):
            version, body, metadata, paths = future.result()
            cache_artifacts.extend(paths)
            parsed = {"passed": False, "match_count": 0, "runtime_version": None}
            parse_error = None
            if metadata.get("http_status") == 200:
                try:
                    parsed = parse_lockfile_runtime(body)
                except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError) as exc:
                    parse_error = f"{type(exc).__name__}: {exc}"
            runtime_version = parsed["runtime_version"]
            catalog_backed = runtime_version in runtime_catalog if runtime_version else False
            lock_results[version.text()] = {
                "product_version": version.text(),
                "tag": releases[version],
                "url": LOCKFILE_URL.format(tag=quote(releases[version], safe="")),
                "http_status": metadata.get("http_status"),
                "runtime_match_count": parsed["match_count"],
                "runtime_version": runtime_version,
                "catalog_backed": catalog_backed,
                "runtime_yanked": runtime_catalog.get(runtime_version, {}).get("yanked") if runtime_version else None,
                "parse_error": parse_error,
                "passed": metadata.get("http_status") == 200 and parsed["passed"] and catalog_backed,
            }

    ordered_mappings = [lock_results[version.text()] for version in selected]
    valid_mappings = [item for item in ordered_mappings if item["passed"]]
    exact_complete = len(valid_mappings) == len(selected)
    monotonic = False
    if exact_complete:
        runtime_order = [StableVersion.parse(item["runtime_version"]) for item in ordered_mappings]
        monotonic = all(left <= right for left, right in zip(runtime_order, runtime_order[1:]))

    predecessor_mapping = lock_results[domain["predecessor"].text()]
    successor_mapping = lock_results[domain["successor"].text()]
    predecessor_runtime = StableVersion.parse(predecessor_mapping["runtime_version"] or "")
    successor_runtime = StableVersion.parse(successor_mapping["runtime_version"] or "")
    lower_anchor_passed = (
        predecessor_mapping["passed"]
        and predecessor_runtime is not None
        and predecessor_runtime.as_tuple() < LOWER_RUNTIME
    )
    upper_anchor_passed = (
        successor_mapping["passed"]
        and successor_runtime is not None
        and successor_runtime.as_tuple() >= UPPER_RUNTIME
    )

    core_versions = domain["core"]
    direct = {version.text() for version in core_versions if in_spans(version, DIRECT_SPANS)}
    runtime_projected = set()
    if exact_complete:
        for version in core_versions:
            runtime = StableVersion.parse(lock_results[version.text()]["runtime_version"])
            if runtime is not None and LOWER_RUNTIME <= runtime.as_tuple() < UPPER_RUNTIME:
                runtime_projected.add(version.text())
    ghsa_union = direct | runtime_projected

    checks = {
        "fixed_input_row": True,
        "complete_release_pagination": bool(page_documents) and page_counts[-1] == 0,
        "both_product_anchors": bool(domain["predecessor"] and domain["successor"]),
        "direct_boundaries_in_product_domain": not domain["missing_boundaries"],
        "exact_lockfile_mapping_complete": exact_complete,
        "runtime_versions_catalog_backed": exact_complete,
        "mapping_monotonic_nondecreasing": monotonic,
        "predecessor_below_runtime_lower": lower_anchor_passed,
        "successor_at_or_above_runtime_upper": upper_anchor_passed,
    }
    failed_checks = [name for name, passed in checks.items() if not passed]
    projection_passed = not failed_checks
    relation = set_relation(direct, ghsa_union) if projection_passed else None
    candidate = relation_candidate(relation)
    status = (
        "pass_deno_lockfile_projection_development_only"
        if projection_passed
        else "no_go_deno_lockfile_recovery_unstable"
    )

    analysis = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "deno_lockfile_recovery_analysis",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_id": SAMPLE_ID,
        "cve_id": CVE_ID,
        "input_source_line_number": row.get("source_line_number"),
        "release_domain": {
            "source": "official_github_releases",
            "page_counts": page_counts,
            "eligible_stable_release_count": len(releases),
            "core_lower": StableVersion(*LOWER_PRODUCT).text(),
            "core_upper": StableVersion(*UPPER_PRODUCT).text(),
            "core_count": len(core_versions),
            "core_versions": [version.text() for version in core_versions],
            "predecessor": domain["predecessor"].text(),
            "successor": domain["successor"].text(),
            "missing_direct_boundaries": domain["missing_boundaries"],
        },
        "mapping_summary": {
            "required_mapping_count": len(selected),
            "valid_mapping_count": len(valid_mappings),
            "monotonic_nondecreasing": monotonic,
            "predecessor_runtime": predecessor_mapping["runtime_version"],
            "successor_runtime": successor_mapping["runtime_version"],
            "mappings": ordered_mappings,
        },
        "product_sets": {
            "nvd_direct": sorted(direct, key=lambda raw: StableVersion.parse(raw)),
            "ghsa_direct": sorted(direct, key=lambda raw: StableVersion.parse(raw)),
            "ghsa_runtime_projected": sorted(runtime_projected, key=lambda raw: StableVersion.parse(raw)),
            "ghsa_union": sorted(ghsa_union, key=lambda raw: StableVersion.parse(raw)),
            "runtime_only_additions": sorted(runtime_projected - direct, key=lambda raw: StableVersion.parse(raw)),
        },
        "gate": {
            "status": status,
            "passed": projection_passed,
            "checks": checks,
            "failed_checks": failed_checks,
            "set_relation": relation,
            "development_typing_candidate": candidate,
            "advancement_count": 1 if projection_passed else 0,
            "advancement_required": 1,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "production_switch_allowed": False,
        },
        "boundary": {
            "post_no_go_recovery": True,
            "development_diagnostic_only": True,
            "accuracy_claim_allowed": False,
            "reviewer_agreement_claim_allowed": False,
            "generalization_claim_allowed": False,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "analysis.md"
    manifest_path = output_dir / "manifest.json"
    write_json(analysis_path, analysis)
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "deno_lockfile_recovery_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": file_sha256(cohort_path)},
            "cohort_manifest": {"path": str(cohort_manifest_path), "sha256": file_sha256(cohort_manifest_path)},
            "contract": {"path": str(contract_path), "sha256": file_sha256(contract_path)},
            "code": {"path": str(Path(__file__).resolve()), "sha256": file_sha256(Path(__file__).resolve())},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": file_sha256(path)}
            for path in sorted(set(cache_artifacts))
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": file_sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": file_sha256(markdown_path)},
        },
        "gate": analysis["gate"],
        "boundary": analysis["boundary"],
    }
    write_json(manifest_path, manifest)
    print(f"Wrote {analysis_path}")
    print(f"Product releases: {len(core_versions)}")
    print(f"Exact mappings: {len(valid_mappings)}/{len(selected)}")
    print(f"Gate: {status}")
    print(f"Relation: {relation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
