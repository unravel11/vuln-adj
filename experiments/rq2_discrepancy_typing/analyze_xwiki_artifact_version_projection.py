#!/usr/bin/env python3
"""Audit whether the unresolved XWiki row is safe to project into one version domain."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

import build_rq2_typing_contract_calibration as calibration
import build_rq2_typing_contract_evidence_secondary as secondary


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "xwiki_artifact_version_projection_v1"
ARTIFACT_TYPE = "xwiki_artifact_version_projection_v1_manifest"
DEFAULT_SOURCE = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/source_rows.jsonl"
)
DEFAULT_SECONDARY_MANIFEST = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "evidence_secondary_v1/manifest.sealed.json"
)
DEFAULT_SECONDARY_SUMMARY = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "evidence_secondary_v1/summary.json"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/xwiki_artifact_version_projection_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_version_projection_v1"
)
FIX_COMMIT = "fe65bc35d5672dd2505b7ac4ec42aec57d500fbb"
MODULE_PATH = (
    "xwiki-platform-core/xwiki-platform-skin/"
    "xwiki-platform-skin-skinx/pom.xml"
)
CURRENT_COORDINATE = "org.xwiki.platform:xwiki-platform-skin-skinx"
LEGACY_COORDINATE = "com.xpn.xwiki.platform.plugins:xwiki-plugin-skinx"
MAVEN_BASE = (
    "https://maven.xwiki.org/releases/org/xwiki/platform/"
    "xwiki-platform-skin-skinx"
)
MAX_RESPONSE_BYTES = 2_000_000


@dataclass(frozen=True)
class EvidenceSource:
    key: str
    url: str
    expected_status: int = 200


def contents_url(ref: str) -> str:
    return (
        "https://api.github.com/repos/xwiki/xwiki-platform/contents/"
        f"{MODULE_PATH}?ref={quote(ref, safe='')}"
    )


EVIDENCE_SOURCES = (
    EvidenceSource(
        "platform_readme_at_fix",
        f"https://raw.githubusercontent.com/xwiki/xwiki-platform/{FIX_COMMIT}/README.md",
    ),
    EvidenceSource("current_maven_metadata", f"{MAVEN_BASE}/maven-metadata.xml"),
    EvidenceSource(
        "current_pom_3_1_milestone_1",
        f"{MAVEN_BASE}/3.1-milestone-1/"
        "xwiki-platform-skin-skinx-3.1-milestone-1.pom",
    ),
    EvidenceSource(
        "current_pom_14_8",
        f"{MAVEN_BASE}/14.8/xwiki-platform-skin-skinx-14.8.pom",
    ),
    EvidenceSource(
        "current_pom_14_9_rc_1",
        f"{MAVEN_BASE}/14.9-rc-1/xwiki-platform-skin-skinx-14.9-rc-1.pom",
    ),
    EvidenceSource(
        "module_path_at_xwiki_web_3_0_milestone_1",
        contents_url("xwiki-web-3.0-milestone-1"),
        404,
    ),
    EvidenceSource(
        "module_path_at_xwiki_web_3_0",
        contents_url("xwiki-web-3.0"),
        404,
    ),
    EvidenceSource(
        "legacy_skinx_pom_1_13_1",
        "https://raw.githubusercontent.com/xwiki/xwiki-platform/"
        "xwiki-plugin-skinx-1.13.1/xwiki-platform-skinx/pom.xml",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--secondary-manifest", default=DEFAULT_SECONDARY_MANIFEST)
    parser.add_argument("--secondary-summary", default=DEFAULT_SECONDARY_SUMMARY)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def response_paths(cache_dir: Path, source: EvidenceSource) -> tuple[Path, Path]:
    return (
        cache_dir / f"{source.key}.response",
        cache_dir / f"{source.key}.fetch.json",
    )


def fetch_or_load(
    source: EvidenceSource,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[bytes, dict, tuple[Path, Path]]:
    response_path, metadata_path = response_paths(cache_dir, source)
    if response_path.exists() and metadata_path.exists() and not refresh:
        body = response_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != source.url:
            raise ValueError(f"cached URL drift for {source.key}")
        if metadata.get("response_sha256") != bytes_sha256(body):
            raise ValueError(f"cached response hash mismatch for {source.key}")
    else:
        request = Request(
            source.url,
            headers={
                "Accept": "application/vnd.github+json, application/json, application/xml, text/plain",
                "User-Agent": "vuln-adj-xwiki-projection-audit/1.0",
            },
        )
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                status = response.status
                content_type = response.headers.get("Content-Type")
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            status = exc.code
            content_type = exc.headers.get("Content-Type") if exc.headers else None
            body = exc.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError(f"response exceeds byte limit for {source.key}")
        metadata = {
            "schema_version": SCHEMA_VERSION,
            "url": source.url,
            "http_status": status,
            "content_type": content_type,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "response_sha256": bytes_sha256(body),
            "response_bytes": len(body),
        }
        response_path.write_bytes(body)
        metadata_path.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if metadata.get("http_status") != source.expected_status:
        raise ValueError(
            f"{source.key}: expected HTTP {source.expected_status}, "
            f"got {metadata.get('http_status')}"
        )
    return body, metadata, (response_path, metadata_path)


def xml_text(root: ET.Element, path: str) -> str | None:
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    return root.findtext(path, namespaces=namespace)


def pom_identity(body: bytes) -> dict:
    root = ET.fromstring(body)
    group = xml_text(root, "m:groupId") or xml_text(root, "m:parent/m:groupId")
    artifact = xml_text(root, "m:artifactId")
    version = xml_text(root, "m:version") or xml_text(root, "m:parent/m:version")
    return {
        "group_id": group,
        "artifact_id": artifact,
        "version": version,
        "coordinate": f"{group}:{artifact}" if group and artifact else None,
    }


def metadata_versions(body: bytes) -> list[str]:
    root = ET.fromstring(body)
    return [
        str(item.text)
        for item in root.findall("./versioning/versions/version")
        if item.text
    ]


def normalize_cpe_release(record: dict) -> str | None:
    criteria = str(record.get("criteria") or "")
    parts = criteria.split(":")
    if len(parts) < 7:
        return None
    version, update = parts[5], parts[6]
    if version in {"", "*", "-"}:
        return None
    if update in {"", "*", "-"}:
        return version
    token = update.lower().replace("_", "-")
    match = re.fullmatch(r"milestone-?(\d+)", token)
    if match:
        token = f"milestone-{match.group(1)}"
    match = re.fullmatch(r"rc-?(\d+)", token)
    if match:
        token = f"rc-{match.group(1)}"
    return f"{version}-{token}"


def projection_gate(checks: dict[str, bool]) -> dict:
    required = (
        "component_membership_bound",
        "same_version_release_policy_bound",
        "current_lineage_poms_match_release_versions",
        "ghsa_lower_bound_exists_in_current_lineage",
        "nvd_explicit_versions_exist_in_current_lineage",
        "legacy_to_current_lineage_mapping_bound",
        "upper_bound_versions_exist_in_current_lineage",
    )
    missing = [name for name in required if not checks.get(name, False)]
    return {
        "status": (
            "artifact_version_projection_allowed"
            if not missing
            else "abstain_artifact_version_projection_unresolved"
        ),
        "passed": not missing,
        "required_checks": list(required),
        "failed_checks": missing,
        "typing_disposition": "compare_sets" if not missing else "uncertain",
    }


def find_target(path: Path) -> dict:
    matches = [
        row
        for row in calibration.iter_jsonl(path)
        if row.get("sample_id") == secondary.TARGET_SAMPLE_ID
    ]
    if len(matches) != 1:
        raise ValueError("target XWiki row must occur exactly once")
    return matches[0]


def validate_secondary(manifest_path: Path, summary_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != secondary.ARTIFACT_TYPE:
        raise ValueError("unexpected evidence-secondary manifest")
    if summary.get("gate", {}).get("status") != "no_go_ai_contract_v2_evidence_secondary_unresolved":
        raise ValueError("projection audit requires the unresolved secondary result")
    if summary.get("source_manifest", {}).get("sha256") != calibration.sha256(manifest_path):
        raise ValueError("secondary summary does not bind its sealed manifest")
    for item in manifest.get("evidence_cache", {}).values():
        path = Path(item["path"])
        if not path.is_file() or calibration.sha256(path) != item["sha256"]:
            raise ValueError(f"secondary evidence cache hash mismatch: {path}")
    return manifest


def analyze(
    row: dict,
    prior_manifest: dict,
    bodies: dict[str, bytes],
    metadata: dict[str, dict],
) -> dict:
    prior_cache = prior_manifest["evidence_cache"]
    ghsa = json.loads(
        Path(prior_cache["ghsa_advisory.response.json"]["path"]).read_text(
            encoding="utf-8"
        )
    )
    commit = json.loads(
        Path(prior_cache["fixing_commit.response.json"]["path"]).read_text(
            encoding="utf-8"
        )
    )
    versions = metadata_versions(bodies["current_maven_metadata"])
    version_set = set(versions)
    current_poms = {
        "3.1-milestone-1": pom_identity(bodies["current_pom_3_1_milestone_1"]),
        "14.8": pom_identity(bodies["current_pom_14_8"]),
        "14.9-rc-1": pom_identity(bodies["current_pom_14_9_rc_1"]),
    }
    legacy_pom = pom_identity(bodies["legacy_skinx_pom_1_13_1"])
    ghsa_range = row["ghsa_value"][0]
    ghsa_start = ghsa_range["version_start_including"]
    ghsa_end = ghsa_range["version_end_excluding"]
    nvd_explicit = sorted(
        {
            value
            for value in (normalize_cpe_release(item) for item in row["nvd_value"])
            if value
        }
    )
    readme = bodies["platform_readme_at_fix"].decode("utf-8", errors="replace")
    current_pom_text = "\n".join(
        bodies[key].decode("utf-8", errors="replace")
        for key in (
            "current_pom_3_1_milestone_1",
            "current_pom_14_8",
            "current_pom_14_9_rc_1",
        )
    )
    ghsa_packages = {
        (item.get("package") or {}).get("name")
        for item in ghsa.get("vulnerabilities") or []
    }
    commit_files = [item.get("filename") for item in commit.get("files") or []]
    explicit_lineage_mapping = (
        LEGACY_COORDINATE in current_pom_text
        or "xwiki-plugin-skinx" in current_pom_text
        or "xwiki.extension.previousIds" in current_pom_text
    )
    checks = {
        "component_membership_bound": (
            CURRENT_COORDINATE in ghsa_packages
            and any("xwiki-platform-skin-skinx/" in str(path) for path in commit_files)
        ),
        "same_version_release_policy_bound": (
            "They are released together and share the same version." in readme
        ),
        "current_lineage_poms_match_release_versions": all(
            identity["coordinate"] == CURRENT_COORDINATE
            and identity["version"] == version
            for version, identity in current_poms.items()
        ),
        "ghsa_lower_bound_exists_in_current_lineage": ghsa_start in version_set,
        "nvd_explicit_versions_exist_in_current_lineage": all(
            version in version_set for version in nvd_explicit
        ),
        "legacy_to_current_lineage_mapping_bound": explicit_lineage_mapping,
        "upper_bound_versions_exist_in_current_lineage": (
            "14.8" in version_set and ghsa_end in version_set
        ),
    }
    gate = projection_gate(checks)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "xwiki_artifact_version_projection_v1_analysis",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "current_coordinate": CURRENT_COORDINATE,
        "legacy_coordinate_observed": legacy_pom["coordinate"],
        "legacy_version_observed": legacy_pom["version"],
        "current_release_catalog": {
            "source": next(
                source.url
                for source in EVIDENCE_SOURCES
                if source.key == "current_maven_metadata"
            ),
            "release_count": len(versions),
            "first_release": versions[0] if versions else None,
            "ghsa_start": ghsa_start,
            "ghsa_start_present": ghsa_start in version_set,
            "ghsa_end_excluding": ghsa_end,
            "ghsa_end_present": ghsa_end in version_set,
            "nvd_explicit_releases": nvd_explicit,
            "nvd_explicit_present": {
                version: version in version_set for version in nvd_explicit
            },
        },
        "source_path_probe": {
            "xwiki_web_3_0_milestone_1_http_status": metadata[
                "module_path_at_xwiki_web_3_0_milestone_1"
            ]["http_status"],
            "xwiki_web_3_0_http_status": metadata[
                "module_path_at_xwiki_web_3_0"
            ]["http_status"],
            "current_module_first_catalog_release": "3.1-milestone-1",
        },
        "checks": checks,
        "gate": gate,
        "interpretation": {
            "supported": (
                "The vulnerability is bound to the current Skinx component, and "
                "the current XWiki Platform lineage releases together with shared versions."
            ),
            "not_supported": (
                "The frozen evidence does not bind GHSA's 3.0-milestone-1 lower "
                "bound or NVD's explicit 3.0 prereleases to the current Maven "
                "coordinate; a differently versioned legacy Skinx artifact is observed."
            ),
            "consequence": (
                "Do not infer strict set containment across the product CPE and "
                "current component package. The evidence-bound typing disposition "
                "remains uncertain until an explicit legacy-to-current lineage map is frozen."
            ),
        },
    }


def render_markdown(analysis: dict) -> str:
    catalog = analysis["current_release_catalog"]
    lines = [
        "# XWiki Artifact-Version Projection Audit v1",
        "",
        "> Evidence-bound, non-human development diagnostic; not a gold label.",
        "",
        f"- Sample: `{analysis['sample_id']}`",
        f"- Current coordinate: `{analysis['current_coordinate']}`",
        f"- Observed legacy coordinate: `{analysis['legacy_coordinate_observed']}`",
        f"- Current catalog first release: `{catalog['first_release']}`",
        f"- GHSA lower bound present in current catalog: `{catalog['ghsa_start_present']}`",
        f"- Projection gate: `{analysis['gate']['status']}`",
        "",
        "| Check | Passed |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {name} | {str(passed).lower()} |"
        for name, passed in analysis["checks"].items()
    )
    lines.extend(
        [
            "",
            analysis["interpretation"]["consequence"],
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.timeout_seconds < 1:
        raise ValueError("--timeout-seconds must be positive")
    source_path = resolve(args.source)
    secondary_manifest_path = resolve(args.secondary_manifest)
    secondary_summary_path = resolve(args.secondary_summary)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite projection audit: {output_dir}")
    row = find_target(source_path)
    prior_manifest = validate_secondary(
        secondary_manifest_path, secondary_summary_path
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    bodies = {}
    metadata = {}
    cache_paths = []
    for source in EVIDENCE_SOURCES:
        body, record, paths = fetch_or_load(
            source,
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        bodies[source.key] = body
        metadata[source.key] = record
        cache_paths.extend(paths)
    analysis = analyze(row, prior_manifest, bodies, metadata)

    output_dir.mkdir(parents=True, exist_ok=False)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "analysis.md"
    manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "inputs": {
            "source": {"path": str(source_path), "sha256": calibration.sha256(source_path)},
            "secondary_manifest": {
                "path": str(secondary_manifest_path),
                "sha256": calibration.sha256(secondary_manifest_path),
            },
            "secondary_summary": {
                "path": str(secondary_summary_path),
                "sha256": calibration.sha256(secondary_summary_path),
            },
            "code": {"path": str(Path(__file__)), "sha256": calibration.sha256(Path(__file__))},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": calibration.sha256(path)}
            for path in sorted(cache_paths)
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": calibration.sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": calibration.sha256(markdown_path)},
        },
        "gate": analysis["gate"],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {analysis_path}")
    print(f"Gate: {analysis['gate']['status']}")
    print("Boundary: non-human development projection audit; no gold label.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
