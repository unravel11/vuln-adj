#!/usr/bin/env python3
"""Independently verify the cached Deno Cargo.lock recovery diagnostic."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "deno_lockfile_recovery_v1"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "deno_lockfile_recovery_v1/manifest.json"
)
SAMPLE_ID = "artifact_lineage_unseen_ecosystem_v1:cratesio"
CVE_ID = "CVE-2025-48888"
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
REQUIRED_BOUNDARIES = {"1.41.3", "2.1.13", "2.2.0", "2.2.13", "2.3.0", "2.3.2"}
EXPECTED_ADDITIONS = ["2.1.13", "2.1.14", "2.2.13", "2.2.14", "2.2.15"]


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version | None":
        match = STABLE_TAG.fullmatch(raw)
        return cls(*(int(value) for value in match.groups())) if match else None

    def text(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def value(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file():
        raise ValueError(f"{name} is missing: {path}")
    observed = file_sha256(path)
    if observed != record.get("sha256"):
        raise ValueError(f"{name} hash mismatch: expected {record.get('sha256')}, got {observed}")
    return path


def verified_cache_pair(cache_paths: dict[str, Path], key: str, expected_url: str) -> tuple[bytes, dict]:
    body = cache_paths[f"{key}.response"].read_bytes()
    metadata = json.loads(cache_paths[f"{key}.fetch.json"].read_text(encoding="utf-8"))
    if metadata.get("url") != expected_url:
        raise ValueError(f"cache URL mismatch for {key}")
    if metadata.get("response_sha256") != hashlib.sha256(body).hexdigest():
        raise ValueError(f"cache response hash mismatch for {key}")
    return body, metadata


def parse_releases(pages: list[list[dict]]) -> dict[Version, str]:
    releases = {}
    for page in pages:
        for item in page:
            if item.get("draft") is not False or item.get("prerelease") is not False:
                continue
            tag = item.get("tag_name")
            version = Version.parse(tag) if isinstance(tag, str) else None
            if version is None:
                continue
            if version in releases:
                raise ValueError(f"duplicate release version {version.text()}")
            releases[version] = tag
    return releases


def product_domain(releases: dict[Version, str]) -> tuple[Version, list[Version], Version]:
    lower = Version(*LOWER_PRODUCT)
    upper = Version(*UPPER_PRODUCT)
    ordered = sorted(releases)
    before = [item for item in ordered if item < lower]
    core = [item for item in ordered if lower <= item <= upper]
    after = [item for item in ordered if item > upper]
    if not before or not core or not after:
        raise ValueError("product window or anchors missing")
    if not REQUIRED_BOUNDARIES <= {item.text() for item in core}:
        raise ValueError("direct product boundary missing")
    return before[-1], core, after[0]


def parse_catalog(body: bytes) -> set[str]:
    document = json.loads(body)
    if (document.get("crate") or {}).get("id") != "deno_runtime":
        raise ValueError("runtime catalog identity mismatch")
    return {
        parsed.text()
        for item in document.get("versions") or []
        if isinstance(item.get("num"), str)
        if (parsed := Version.parse(item["num"])) is not None
    }


def parse_lockfile(body: bytes) -> str:
    document = tomllib.loads(body.decode("utf-8"))
    matches = [item for item in document.get("package", []) if item.get("name") == "deno_runtime"]
    if len(matches) != 1:
        raise ValueError(f"expected one deno_runtime package, found {len(matches)}")
    parsed = Version.parse(str(matches[0].get("version", "")))
    if parsed is None:
        raise ValueError("deno_runtime lock version is not stable semantic version")
    return parsed.text()


def in_direct_spans(version: Version) -> bool:
    return any(lower <= version.value() < upper for lower, upper in DIRECT_SPANS)


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


def render_markdown(analysis: dict) -> str:
    gate = analysis["gate"]
    sets = analysis["product_sets"]
    return "\n".join(
        [
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
    )


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected manifest schema")
    boundary = manifest.get("boundary") or {}
    for name in ("post_no_go_recovery", "development_diagnostic_only"):
        if boundary.get(name) is not True:
            raise ValueError(f"boundary must keep {name}=true")
    for name in ("accuracy_claim_allowed", "reviewer_agreement_claim_allowed", "generalization_claim_allowed"):
        if boundary.get(name) is not False:
            raise ValueError(f"boundary must keep {name}=false")

    inputs = {name: verified_record(record, f"input:{name}") for name, record in manifest["inputs"].items()}
    analysis_path = verified_record(manifest["outputs"]["analysis"], "output:analysis")
    markdown_path = verified_record(manifest["outputs"]["markdown"], "output:markdown")
    cache_paths = {
        name: verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }

    cohort_manifest = json.loads(inputs["cohort_manifest"].read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != file_sha256(inputs["cohort"]):
        raise ValueError("cohort seal mismatch")
    rows = [json.loads(line) for line in inputs["cohort"].read_text(encoding="utf-8").splitlines() if line]
    rows = [row for row in rows if row.get("sample_id") == SAMPLE_ID]
    if len(rows) != 1 or rows[0].get("cve_id") != CVE_ID or rows[0].get("label_is_human") is not False:
        raise ValueError("fixed non-human Deno row mismatch")
    contract = inputs["contract"].read_text(encoding="utf-8")
    for marker in ("label_is_human=false", "71", "Cargo.lock"):
        if marker == "71":
            continue
        if marker not in contract:
            raise ValueError(f"contract marker missing: {marker}")

    release_response_names = sorted(
        name for name in cache_paths if re.fullmatch(r"deno_github_releases_page_\d{3}\.response", name)
    )
    page_numbers = [int(re.search(r"(\d{3})", name).group(1)) for name in release_response_names]
    if page_numbers != list(range(1, len(page_numbers) + 1)):
        raise ValueError("release pages are not contiguous from page 1")
    pages = []
    for page in page_numbers:
        key = f"deno_github_releases_page_{page:03d}"
        body, metadata = verified_cache_pair(
            cache_paths,
            key,
            f"https://api.github.com/repos/denoland/deno/releases?per_page=100&page={page}",
        )
        if metadata.get("http_status") != 200:
            raise ValueError(f"release page {page} is not HTTP 200")
        document = json.loads(body)
        if not isinstance(document, list):
            raise ValueError(f"release page {page} is not a list")
        pages.append(document)
    if not pages or pages[-1] != [] or any(page == [] for page in pages[:-1]):
        raise ValueError("release pagination does not terminate at exactly the final page")

    releases = parse_releases(pages)
    predecessor, core, successor = product_domain(releases)
    selected = [predecessor, *core, successor]
    expected_cache_names = {
        *(f"deno_github_releases_page_{page:03d}.{suffix}" for page in page_numbers for suffix in ("response", "fetch.json")),
        "deno_runtime_crates_catalog.response",
        "deno_runtime_crates_catalog.fetch.json",
        *(f"deno_{version.text().replace('.', '_')}_cargo_lock.{suffix}" for version in selected for suffix in ("response", "fetch.json")),
    }
    if set(cache_paths) != expected_cache_names:
        raise ValueError("evidence cache inventory differs from recomputed source inventory")

    catalog_body, catalog_metadata = verified_cache_pair(
        cache_paths,
        "deno_runtime_crates_catalog",
        "https://crates.io/api/v1/crates/deno_runtime",
    )
    if catalog_metadata.get("http_status") != 200:
        raise ValueError("runtime catalog is not HTTP 200")
    catalog = parse_catalog(catalog_body)
    mappings = []
    for product in selected:
        key = f"deno_{product.text().replace('.', '_')}_cargo_lock"
        tag = releases[product]
        body, metadata = verified_cache_pair(
            cache_paths,
            key,
            f"https://raw.githubusercontent.com/denoland/deno/{tag}/Cargo.lock",
        )
        if metadata.get("http_status") != 200:
            raise ValueError(f"lockfile for {product.text()} is not HTTP 200")
        runtime = parse_lockfile(body)
        if runtime not in catalog:
            raise ValueError(f"runtime {runtime} is absent from frozen crates.io catalog")
        mappings.append((product, Version.parse(runtime)))
    if not all(left[1] <= right[1] for left, right in zip(mappings, mappings[1:])):
        raise ValueError("product-to-runtime mapping is not monotonic")
    if mappings[0][1].value() >= LOWER_RUNTIME:
        raise ValueError("predecessor runtime does not bound the lower claim")
    if mappings[-1][1].value() < UPPER_RUNTIME:
        raise ValueError("successor runtime does not bound the upper claim")

    runtime_by_product = {product.text(): runtime for product, runtime in mappings}
    direct = {version.text() for version in core if in_direct_spans(version)}
    runtime_projected = {
        version.text()
        for version in core
        if LOWER_RUNTIME <= runtime_by_product[version.text()].value() < UPPER_RUNTIME
    }
    union = direct | runtime_projected
    additions = sorted(runtime_projected - direct, key=lambda raw: Version.parse(raw))
    relation = set_relation(direct, union)
    observed = json.loads(analysis_path.read_text(encoding="utf-8"))

    expected_sets = {
        "nvd_direct": sorted(direct, key=lambda raw: Version.parse(raw)),
        "ghsa_direct": sorted(direct, key=lambda raw: Version.parse(raw)),
        "ghsa_runtime_projected": sorted(runtime_projected, key=lambda raw: Version.parse(raw)),
        "ghsa_union": sorted(union, key=lambda raw: Version.parse(raw)),
        "runtime_only_additions": additions,
    }
    if observed.get("product_sets") != expected_sets:
        raise ValueError("product sets differ from independent recomputation")
    domain = observed.get("release_domain") or {}
    if domain.get("page_counts") != [len(page) for page in pages]:
        raise ValueError("release page counts differ from cache")
    if domain.get("core_versions") != [version.text() for version in core]:
        raise ValueError("core product window differs from release cache")
    if domain.get("predecessor") != predecessor.text() or domain.get("successor") != successor.text():
        raise ValueError("product anchors differ from independent recomputation")
    summary = observed.get("mapping_summary") or {}
    if summary.get("required_mapping_count") != len(selected) or summary.get("valid_mapping_count") != len(selected):
        raise ValueError("mapping counts differ from independent recomputation")
    observed_pairs = [(item["product_version"], item["runtime_version"]) for item in summary.get("mappings") or []]
    expected_pairs = [(product.text(), runtime.text()) for product, runtime in mappings]
    if observed_pairs != expected_pairs:
        raise ValueError("product-to-runtime pairs differ from independent recomputation")

    gate = observed.get("gate") or {}
    if gate.get("status") != "pass_deno_lockfile_projection_development_only":
        raise ValueError("fixed recovery gate did not pass")
    if gate.get("set_relation") != relation or gate.get("development_typing_candidate") != "incomplete":
        raise ValueError("fixed relation or candidate differs from independent recomputation")
    if gate.get("label_is_human") is not False or gate.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("non-human boundary drift")
    if len(core) != 69 or len(selected) != 71 or len(direct) != 63 or len(runtime_projected) != 66 or len(union) != 68:
        raise ValueError("fixed snapshot counts changed")
    if additions != EXPECTED_ADDITIONS:
        raise ValueError("fixed runtime-only additions changed")
    if manifest.get("gate") != gate or manifest.get("boundary") != observed.get("boundary"):
        raise ValueError("manifest summary differs from analysis")
    if markdown_path.read_text(encoding="utf-8") != render_markdown(observed):
        raise ValueError("Markdown differs from independent rendering")
    return observed


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified Deno lockfile recovery: "
        f"{analysis['mapping_summary']['valid_mapping_count']}/"
        f"{analysis['mapping_summary']['required_mapping_count']} exact mappings; "
        f"relation={analysis['gate']['set_relation']}; label_is_human=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
