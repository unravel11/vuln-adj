#!/usr/bin/env python3
"""Build a lineage-aware XWiki product-to-Skinx release-set projection."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import analyze_xwiki_artifact_version_projection as v1
import build_rq2_typing_contract_calibration as calibration
import verify_xwiki_artifact_version_projection as v1_verify


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "xwiki_artifact_version_projection_v2"
ARTIFACT_TYPE = "xwiki_artifact_version_projection_v2_manifest"
DEFAULT_SOURCE = v1.DEFAULT_SOURCE
DEFAULT_V1_DIR = v1.DEFAULT_OUTPUT_DIR
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/xwiki_artifact_version_projection_v2"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_version_projection_v2"
)
PRODUCT_RELEASES = (
    "3.0-milestone-1",
    "3.0-milestone-2",
    "3.0-milestone-3",
    "3.0-rc-1",
    "3.0",
)
EXPECTED_PRODUCT_TO_LEGACY = {
    "3.0-milestone-1": "1.20",
    "3.0-milestone-2": "1.21",
    "3.0-milestone-3": "1.22",
    "3.0-rc-1": "1.22",
    "3.0": "1.22",
}
LEGACY_VERSIONS = ("1.20", "1.21", "1.22")
LEGACY_TAG_COMMITS = {
    "1.20": "427ff008cd633453e48c3dd6402dee6e1c9c40c8",
    "1.21": "c6931f911dcdf4c8916c69a7703562c7de306753",
    "1.22": "d8e4a4f7150504c41671fc377b87618f2c2604bb",
}
CURRENT_3_1_M1_COMMIT = "0ccb476875da6a9cf07b37cc0f5ca7a59f26f667"
RELEVANT_CLASSES = (
    "AbstractDocumentSkinExtensionPlugin.java",
    "JsExtension.java",
    "CssExtension.java",
    "JsxAction.java",
    "SsxAction.java",
)
CLASS_PATHS = {
    "AbstractDocumentSkinExtensionPlugin.java": (
        "com/xpn/xwiki/plugin/skinx/AbstractDocumentSkinExtensionPlugin.java"
    ),
    "JsExtension.java": "com/xpn/xwiki/web/sx/JsExtension.java",
    "CssExtension.java": "com/xpn/xwiki/web/sx/CssExtension.java",
    "JsxAction.java": "com/xpn/xwiki/web/JsxAction.java",
    "SsxAction.java": "com/xpn/xwiki/web/SsxAction.java",
}


def parent_pom_url(version: str) -> str:
    return (
        "https://maven.xwiki.org/releases/org/xwiki/enterprise/"
        f"xwiki-enterprise-parent/{version}/xwiki-enterprise-parent-{version}.pom"
    )


def web_pom_url(version: str) -> str:
    return (
        "https://maven.xwiki.org/releases/org/xwiki/enterprise/"
        f"xwiki-enterprise-web/{version}/xwiki-enterprise-web-{version}.pom"
    )


def legacy_pom_url(version: str) -> str:
    return (
        "https://maven.xwiki.org/releases/com/xpn/xwiki/platform/plugins/"
        f"xwiki-plugin-skinx/{version}/xwiki-plugin-skinx-{version}.pom"
    )


def legacy_source_url(version: str, relative_path: str) -> str:
    return (
        "https://raw.githubusercontent.com/xwiki/xwiki-platform/"
        f"{LEGACY_TAG_COMMITS[version]}/xwiki-platform-skinx/src/main/java/"
        f"{relative_path}"
    )


def current_source_url(relative_path: str) -> str:
    return (
        "https://raw.githubusercontent.com/xwiki/xwiki-platform/"
        f"{CURRENT_3_1_M1_COMMIT}/xwiki-platform-core/xwiki-platform-skin/"
        "xwiki-platform-skin-skinx/src/main/java/"
        f"{relative_path}"
    )


def slug(value: str) -> str:
    return value.replace(".", "_").replace("-", "_")


EVIDENCE_SOURCES = (
    *(
        v1.EvidenceSource(f"enterprise_parent_{slug(version)}", parent_pom_url(version))
        for version in PRODUCT_RELEASES
    ),
    *(
        v1.EvidenceSource(f"enterprise_web_{slug(version)}", web_pom_url(version))
        for version in PRODUCT_RELEASES
    ),
    *(
        v1.EvidenceSource(f"legacy_skinx_pom_{slug(version)}", legacy_pom_url(version))
        for version in LEGACY_VERSIONS
    ),
    *(
        v1.EvidenceSource(
            f"legacy_source_{slug(version)}_{slug(class_name.removesuffix('.java'))}",
            legacy_source_url(version, relative_path),
        )
        for version in LEGACY_VERSIONS
        for class_name, relative_path in CLASS_PATHS.items()
    ),
    *(
        v1.EvidenceSource(
            f"current_source_3_1_milestone_1_{slug(class_name.removesuffix('.java'))}",
            current_source_url(relative_path),
        )
        for class_name, relative_path in CLASS_PATHS.items()
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--v1-dir", default=DEFAULT_V1_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def pom_property(body: bytes, name: str) -> str | None:
    root = ET.fromstring(body)
    return v1.xml_text(root, f"m:properties/m:{name}")


def skinx_dependency(body: bytes) -> dict | None:
    root = ET.fromstring(body)
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    for dependency in root.findall(".//m:dependency", namespace):
        artifact = dependency.findtext("m:artifactId", namespaces=namespace)
        if artifact != "xwiki-plugin-skinx":
            continue
        group = dependency.findtext("m:groupId", namespaces=namespace)
        return {
            "coordinate": f"{group}:{artifact}",
            "version_expression": dependency.findtext(
                "m:version", namespaces=namespace
            ),
        }
    return None


def source_hashes(bodies: dict[str, bytes], version: str) -> dict[str, str]:
    prefix = (
        f"legacy_source_{slug(version)}_"
        if version in LEGACY_VERSIONS
        else "current_source_3_1_milestone_1_"
    )
    return {
        class_name: v1.bytes_sha256(
            bodies[f"{prefix}{slug(class_name.removesuffix('.java'))}"]
        )
        for class_name in RELEVANT_CLASSES
    }


def xwiki_version_key(value: str) -> tuple[int, int, int, int, int] | None:
    match = re.fullmatch(
        r"(\d+)\.(\d+)(?:\.(\d+))?(?:-(milestone|rc)-(\d+))?",
        value,
    )
    if not match:
        return None
    major, minor, patch, qualifier, qualifier_number = match.groups()
    qualifier_rank = {"milestone": 0, "rc": 1, None: 2}[qualifier]
    return (
        int(major),
        int(minor),
        int(patch or 0),
        qualifier_rank,
        int(qualifier_number or 0),
    )


def set_relation(left: set[str], right: set[str]) -> str:
    if left == right:
        return "equal"
    if left < right:
        return "strict_subset"
    if right < left:
        return "strict_superset"
    if left & right:
        return "overlap_without_containment"
    return "disjoint"


def build_release_sets(
    current_versions: list[str],
    nvd_explicit: list[str],
) -> dict:
    domain = set(PRODUCT_RELEASES)
    domain.update(version for version in current_versions if xwiki_version_key(version))
    start = xwiki_version_key("3.0-milestone-1")
    final_3_0 = xwiki_version_key("3.0")
    end_nvd = xwiki_version_key("14.8")
    end_ghsa = xwiki_version_key("14.9-rc-1")
    assert start and final_3_0 and end_nvd and end_ghsa
    ghsa = {
        version
        for version in domain
        if start <= xwiki_version_key(version) < end_ghsa
    }
    nvd = set(nvd_explicit) | {
        version
        for version in domain
        if final_3_0 < xwiki_version_key(version) <= end_nvd
    }
    return {
        "domain": domain,
        "nvd": nvd,
        "ghsa": ghsa,
        "relation": set_relation(nvd, ghsa),
        "nvd_only": sorted(nvd - ghsa, key=xwiki_version_key),
        "ghsa_only": sorted(ghsa - nvd, key=xwiki_version_key),
    }


def projection_gate(checks: dict[str, bool], relation: str) -> dict:
    required = (
        "all_product_dependency_edges_bound",
        "all_legacy_poms_bound",
        "legacy_release_classes_present",
        "legacy_to_current_source_continuity_bound",
        "unified_release_domain_bound",
        "strict_subset_computed",
    )
    failed = [name for name in required if not checks.get(name, False)]
    passed = not failed and relation == "strict_subset"
    return {
        "status": (
            "artifact_version_projection_allowed_development_only"
            if passed
            else "abstain_artifact_version_projection_v2_unresolved"
        ),
        "passed": passed,
        "required_checks": list(required),
        "failed_checks": failed,
        "development_typing_candidate": "incomplete" if passed else "uncertain",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def analyze(
    row: dict,
    v1_analysis: dict,
    v1_manifest: dict,
    bodies: dict[str, bytes],
) -> dict:
    product_edges = {}
    all_dependency_edges = True
    for product_version in PRODUCT_RELEASES:
        key = slug(product_version)
        parent_body = bodies[f"enterprise_parent_{key}"]
        web_body = bodies[f"enterprise_web_{key}"]
        skinx_version = pom_property(parent_body, "platform.plugin.skinx.version")
        core_version = pom_property(parent_body, "platform.core.version")
        dependency = skinx_dependency(web_body)
        edge_ok = (
            skinx_version == EXPECTED_PRODUCT_TO_LEGACY[product_version]
            and core_version == product_version
            and dependency is not None
            and dependency["coordinate"] == v1.LEGACY_COORDINATE
            and dependency["version_expression"] == "${platform.plugin.skinx.version}"
        )
        all_dependency_edges &= edge_ok
        product_edges[product_version] = {
            "legacy_coordinate": v1.LEGACY_COORDINATE,
            "legacy_version": skinx_version,
            "core_version": core_version,
            "web_dependency": dependency,
            "edge_bound": edge_ok,
        }

    legacy_poms = {
        version: v1.pom_identity(bodies[f"legacy_skinx_pom_{slug(version)}"])
        for version in LEGACY_VERSIONS
    }
    legacy_poms_bound = all(
        identity["coordinate"] == v1.LEGACY_COORDINATE
        and identity["version"] == version
        for version, identity in legacy_poms.items()
    )
    legacy_sources = {
        version: source_hashes(bodies, version)
        for version in LEGACY_VERSIONS
    }
    current_sources = source_hashes(bodies, "3.1-milestone-1")
    relevant_presence = {
        version: {name: bool(source_hash) for name, source_hash in hashes.items()}
        for version, hashes in {
            **legacy_sources,
            "3.1-milestone-1": current_sources,
        }.items()
    }
    relevant_classes_present = all(
        all(class_presence.values())
        for class_presence in relevant_presence.values()
    )
    legacy_1_22 = legacy_sources["1.22"]
    common_names = set(legacy_1_22) & set(current_sources)
    identical_names = {
        name
        for name in common_names
        if legacy_1_22[name] == current_sources[name]
    }
    source_continuity = (
        common_names == set(RELEVANT_CLASSES)
        and identical_names == common_names
        and relevant_classes_present
    )

    metadata_path = Path(
        v1_manifest["evidence_cache"]["current_maven_metadata.response"]["path"]
    )
    current_versions = v1.metadata_versions(metadata_path.read_bytes())
    nvd_explicit = sorted(
        {
            value
            for value in (
                v1.normalize_cpe_release(item) for item in row["nvd_value"]
            )
            if value
        },
        key=xwiki_version_key,
    )
    release_sets = build_release_sets(current_versions, nvd_explicit)
    checks = {
        "all_product_dependency_edges_bound": all_dependency_edges,
        "all_legacy_poms_bound": legacy_poms_bound,
        "legacy_release_classes_present": relevant_classes_present,
        "legacy_to_current_source_continuity_bound": source_continuity,
        "unified_release_domain_bound": (
            all(version in release_sets["domain"] for version in PRODUCT_RELEASES)
            and "3.1-milestone-1" in release_sets["domain"]
            and "14.8" in release_sets["domain"]
            and "14.9-rc-1" in release_sets["domain"]
        ),
        "strict_subset_computed": release_sets["relation"] == "strict_subset",
    }
    gate = projection_gate(checks, release_sets["relation"])
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "xwiki_artifact_version_projection_v2_analysis",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing_conditional_analysis": True,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "product_to_legacy_edges": product_edges,
        "legacy_poms": legacy_poms,
        "source_lineage": {
            "legacy_versions": list(LEGACY_VERSIONS),
            "current_first_release": "3.1-milestone-1",
            "relevant_class_presence": relevant_presence,
            "relevant_files_checked": len(RELEVANT_CLASSES),
            "transition_common_relevant_files": len(common_names),
            "transition_identical_relevant_files": len(identical_names),
            "source_continuity_bound": source_continuity,
        },
        "release_set_projection": {
            "domain_release_count": len(release_sets["domain"]),
            "nvd_release_count": len(release_sets["nvd"]),
            "ghsa_release_count": len(release_sets["ghsa"]),
            "relation": release_sets["relation"],
            "nvd_only": release_sets["nvd_only"],
            "ghsa_only": release_sets["ghsa_only"],
        },
        "checks": checks,
        "gate": gate,
        "interpretation": {
            "supported": (
                "The XWiki 3.0 product POMs bind each product prerelease to a "
                "legacy Skinx artifact release, and the legacy 1.22 to current "
                "3.1-milestone-1 transition preserves all common Java blobs."
            ),
            "set_relation": (
                "After projecting both claims into the evidence-bound XWiki product "
                "release domain, the NVD set is a strict subset of the GHSA set; "
                "the only GHSA-only release is 3.0-milestone-1."
            ),
            "boundary": (
                "This yields a post-unsealing non-human development candidate of "
                "incomplete. It does not revise the sealed reviewer result, create "
                "human gold, or authorize production switching."
            ),
        },
    }


def render_markdown(analysis: dict) -> str:
    projection = analysis["release_set_projection"]
    lineage = analysis["source_lineage"]
    lines = [
        "# XWiki Artifact-Version Projection Audit v2",
        "",
        "> Post-unsealing, non-human development diagnostic; not a gold label.",
        "",
        f"- Sample: `{analysis['sample_id']}`",
        f"- Product dependency edges: `{len(analysis['product_to_legacy_edges'])}`",
        f"- Legacy/current identical relevant source files: `{lineage['transition_identical_relevant_files']}/{lineage['transition_common_relevant_files']}`",
        f"- Release-set relation: `{projection['relation']}`",
        f"- GHSA-only releases: `{projection['ghsa_only']}`",
        f"- Gate: `{analysis['gate']['status']}`",
        f"- Development typing candidate: `{analysis['gate']['development_typing_candidate']}`",
        "",
        "| Check | Passed |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {name} | {str(passed).lower()} |"
        for name, passed in analysis["checks"].items()
    )
    lines.extend(["", analysis["interpretation"]["boundary"], ""])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.timeout_seconds < 1:
        raise ValueError("--timeout-seconds must be positive")
    source_path = resolve(args.source)
    v1_dir = resolve(args.v1_dir)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite v2 projection audit: {output_dir}")
    v1_manifest_path = v1_dir / "manifest.json"
    v1_manifest = json.loads(v1_manifest_path.read_text(encoding="utf-8"))
    v1_analysis = v1_verify.validate_manifest(v1_manifest, v1_manifest_path)
    row = v1.find_target(source_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    bodies = {}
    cache_paths = []
    for source in EVIDENCE_SOURCES:
        body, _metadata, paths = v1.fetch_or_load(
            source,
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        bodies[source.key] = body
        cache_paths.extend(paths)
    analysis = analyze(row, v1_analysis, v1_manifest, bodies)

    output_dir.mkdir(parents=True, exist_ok=False)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "analysis.md"
    manifest_path = output_dir / "manifest.json"
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing_conditional_analysis": True,
        "inputs": {
            "source": {"path": str(source_path), "sha256": calibration.sha256(source_path)},
            "v1_manifest": {"path": str(v1_manifest_path), "sha256": calibration.sha256(v1_manifest_path)},
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
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {analysis_path}")
    print(f"Gate: {analysis['gate']['status']}")
    print(
        "Boundary: post-unsealing non-human development candidate; no gold label."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
