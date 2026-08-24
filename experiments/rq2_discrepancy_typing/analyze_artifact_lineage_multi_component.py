#!/usr/bin/env python3
"""Evaluate a product claim against multiple bound component-package claims."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from packaging.version import Version

import analyze_artifact_lineage_cross_case as graph
import analyze_artifact_lineage_non_equal as lineage


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_multi_component_v1"
DEFAULT_COHORT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_multi_component_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "affected_versions_snapshot_extensional_codex_candidate_v1.md"
)
DEFAULT_REVIEWER_A = graph.DEFAULT_REVIEWER_A
DEFAULT_REVIEWER_B = graph.DEFAULT_REVIEWER_B
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/artifact_lineage_multi_component_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_multi_component_v1"
)
FIXED_SAMPLE_ID = "rq2_typing_holdout_v1:548"
ANCHOR_VERSIONS = ("1.4.0", "1.5.0", "1.6.0")
EXPECTED_PARENT = "org.apache.inlong:inlong-manager"


def catalog_source(coordinate: str) -> graph.EvidenceSource:
    group, artifact = coordinate.split(":", 1)
    group_path = group.replace(".", "/")
    return lineage.source(
        f"inlong_{artifact.replace('-', '_')}_maven_catalog",
        FIXED_SAMPLE_ID,
        f"https://repo.maven.apache.org/maven2/{group_path}/{artifact}/maven-metadata.xml",
        "maven_catalog",
        coordinate,
    )


def component_spec(coordinate: str) -> dict:
    artifact = coordinate.split(":", 1)[1]
    return {
        "coordinate": coordinate,
        "catalog": catalog_source(coordinate),
        "anchors": graph.maven_sources(
            FIXED_SAMPLE_ID,
            coordinate,
            list(ANCHOR_VERSIONS),
            prefix=f"inlong_{artifact.replace('-', '_')}",
        ),
        "expected_parent": EXPECTED_PARENT,
        "required_project_prefix": "Apache InLong - Manager",
    }


CASE_SPEC = {
    "sample_id": FIXED_SAMPLE_ID,
    "cve_id": "CVE-2023-30465",
    "ecosystem": "Maven",
    "nvd_subject": "inlong",
    "edge_type": "product_contains_artifact",
    "authority_class": "ecosystem_registry_component_pom_parent",
    "components": {
        coordinate: component_spec(coordinate)
        for coordinate in (
            "org.apache.inlong:manager-pojo",
            "org.apache.inlong:manager-service",
        )
    },
}
EVIDENCE_SOURCES = tuple(
    evidence
    for coordinate in sorted(CASE_SPEC["components"])
    for evidence in (
        CASE_SPEC["components"][coordinate]["catalog"],
        *CASE_SPEC["components"][coordinate]["anchors"],
    )
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", default=DEFAULT_COHORT_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--reviewer-a", default=DEFAULT_REVIEWER_A)
    parser.add_argument("--reviewer-b", default=DEFAULT_REVIEWER_B)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def extract_component_anchor(
    source: graph.EvidenceSource,
    body: bytes,
    *,
    expected_parent: str,
    required_project_prefix: str,
) -> dict:
    extracted = graph.extract_evidence(source, body)
    root = ET.fromstring(body)
    parent_group = graph.xml_text(root, "m:parent/m:groupId")
    parent_artifact = graph.xml_text(root, "m:parent/m:artifactId")
    parent_version = graph.xml_text(root, "m:parent/m:version")
    parent_identity = (
        f"{parent_group}:{parent_artifact}"
        if parent_group and parent_artifact
        else None
    )
    product_edge_bound = (
        extracted["passed"]
        and parent_identity == expected_parent
        and parent_version == source.version
        and str(extracted.get("project_name") or "").startswith(
            required_project_prefix
        )
    )
    extracted.update(
        parent_identity=parent_identity,
        parent_version=parent_version,
        expected_parent_identity=expected_parent,
        product_edge_bound=product_edge_bound,
        passed=product_edge_bound,
    )
    return extracted


def component_records(row: dict, coordinate: str) -> list[dict]:
    return [
        record
        for record in row["ghsa_value"]
        if (record.get("package_name") or record.get("product")) == coordinate
    ]


def sorted_versions(values: set[str]) -> list[str]:
    return sorted(values, key=Version)


def analyze_case(row: dict, bodies: dict[str, bytes]) -> dict:
    component_results = []
    catalog_domains: list[set[str]] = []
    anchor_domains: list[set[str]] = []
    component_sets: list[set[str]] = []

    for coordinate, spec in sorted(CASE_SPEC["components"].items()):
        catalog = lineage.parse_catalog(spec["catalog"], bodies[spec["catalog"].key])
        anchors = [
            extract_component_anchor(
                source,
                bodies[source.key],
                expected_parent=spec["expected_parent"],
                required_project_prefix=spec["required_project_prefix"],
            )
            for source in spec["anchors"]
        ]
        catalog_domain = set(catalog["canonical_to_raw"])
        anchor_domain = {
            str(lineage.normalized_version(item["expected_version"]))
            for item in anchors
            if item["passed"] and lineage.normalized_version(item["expected_version"])
        }
        records = component_records(row, coordinate)
        affected = lineage.affected_set(records, catalog)
        catalog_domains.append(catalog_domain)
        anchor_domains.append(anchor_domain)
        component_sets.append(affected)
        component_results.append(
            {
                "coordinate": coordinate,
                "identity_edge": {
                    "from": row["nvd_subject"],
                    "to": coordinate,
                    "edge_type": CASE_SPEC["edge_type"],
                    "authority_class": CASE_SPEC["authority_class"],
                    "bound": catalog["identity_bound"]
                    and bool(anchors)
                    and all(item["passed"] for item in anchors),
                },
                "catalog": {
                    key: value
                    for key, value in catalog.items()
                    if key != "canonical_to_raw"
                },
                "anchors": anchors,
                "claim_record_count": len(records),
                "affected_versions": sorted_versions(affected),
                "affected_version_count": len(affected),
            }
        )

    endpoints = lineage.endpoint_values(row)
    normalized_endpoints = {lineage.normalized_version(value) for value in endpoints}
    endpoints_parse = None not in normalized_endpoints
    endpoint_domain = {str(value) for value in normalized_endpoints if value is not None}
    catalog_intersection = set.intersection(*catalog_domains)
    anchor_intersection = set.intersection(*anchor_domains)
    coordinated_domain = catalog_intersection & anchor_intersection
    ghsa_union = set().union(*component_sets)
    pseudo_catalog = {
        "canonical_to_raw": {version: version for version in coordinated_domain}
    }
    nvd_set = lineage.affected_set(row["nvd_value"], pseudo_catalog)

    expected_components = set(CASE_SPEC["components"])
    subject_match = (
        row["sample_id"] == CASE_SPEC["sample_id"]
        and row["cve_id"] == CASE_SPEC["cve_id"]
        and row["nvd_subject"] == CASE_SPEC["nvd_subject"]
        and set(row["ghsa_subjects"]) == expected_components
        and CASE_SPEC["edge_type"] in graph.ALLOWED_EDGE_TYPES
    )
    component_catalogs_bound = all(
        item["catalog"]["identity_bound"] for item in component_results
    )
    component_product_edges_bound = all(
        item["identity_edge"]["bound"] for item in component_results
    )
    all_components_have_claims = all(
        item["claim_record_count"] > 0 for item in component_results
    )
    boundaries_bound = (
        endpoints_parse
        and endpoint_domain <= catalog_intersection
        and endpoint_domain <= anchor_intersection
    )
    affected_releases_coordinated = (
        bool(ghsa_union)
        and ghsa_union <= coordinated_domain
        and bool(nvd_set)
    )
    prechecks = {
        "claim_subjects_bound": subject_match and all_components_have_claims,
        "component_catalog_identities_bound": component_catalogs_bound,
        "component_product_edges_bound": component_product_edges_bound,
        "boundary_releases_bound": boundaries_bound,
        "ordering_supported": endpoints_parse and bool(coordinated_domain),
        "affected_releases_product_coordinated": affected_releases_coordinated,
        "shared_release_domain_bound": (
            component_catalogs_bound
            and component_product_edges_bound
            and boundaries_bound
            and affected_releases_coordinated
        ),
    }
    relation = (
        lineage.set_relation(nvd_set, ghsa_union)
        if all(prechecks.values())
        else None
    )
    checks = {**prechecks, "set_relation_computed": relation is not None}
    failed = [name for name, passed in checks.items() if not passed]
    gate_passed = not failed
    candidate = lineage.relation_candidate(relation if gate_passed else None)
    unique_component_sets = {tuple(sorted_versions(values)) for values in component_sets}

    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "ecosystem": CASE_SPEC["ecosystem"],
        "product_subject": row["nvd_subject"],
        "components": component_results,
        "release_domain": {
            "scope": "stable_parseable_frozen_maven_releases",
            "catalog_intersection_count": len(catalog_intersection),
            "anchored_product_versions": sorted_versions(coordinated_domain),
            "boundary_versions": sorted_versions(endpoint_domain),
        },
        "release_sets": {
            "nvd_product_versions": sorted_versions(nvd_set),
            "ghsa_component_union_versions": sorted_versions(ghsa_union),
            "nvd_count": len(nvd_set),
            "ghsa_union_count": len(ghsa_union),
            "relation": relation,
            "nvd_only": sorted_versions(nvd_set - ghsa_union),
            "ghsa_only": sorted_versions(ghsa_union - nvd_set),
            "component_heterogeneity": len(unique_component_sets) > 1,
        },
        "checks": checks,
        "gate": {
            "status": (
                "codex_snapshot_extensional_projection_allowed_development_only"
                if gate_passed
                else "abstain_multi_component_projection_unresolved"
            ),
            "passed": gate_passed,
            "failed_checks": failed,
            "development_typing_candidate": candidate,
            "contract_status": "codex_expert_contract_candidate",
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        },
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
    }


def build_summary(cases: list[dict], reviewer_a: dict, reviewer_b: dict) -> dict:
    comparisons = []
    for case in cases:
        candidate = case["gate"]["development_typing_candidate"]
        a_label = reviewer_a.get(case["sample_id"])
        b_label = reviewer_b.get(case["sample_id"])
        comparisons.append(
            {
                "sample_id": case["sample_id"],
                "candidate": candidate,
                "reviewer_a": a_label,
                "reviewer_b": b_label,
                "matches_both": candidate == a_label == b_label,
            }
        )
    projection_supported = all(case["gate"]["passed"] for case in cases)
    reviewer_match = all(item["matches_both"] for item in comparisons)
    diagnostic = {
        "status": (
            "snapshot_extensional_projection_supported_human_resolution_required"
            if projection_supported and not reviewer_match
            else "multi_component_contract_diagnostic_inconclusive"
        ),
        "technical_projection_supported": projection_supported,
        "matches_both_sealed_ai_reviewers": reviewer_match,
        "human_resolution_required": True,
        "production_switch_allowed": False,
        "accuracy_claim_allowed": False,
        "human_gold_claim_allowed": False,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_multi_component_analysis",
        "row_count": len(cases),
        "projection_gate_passed": sum(case["gate"]["passed"] for case in cases),
        "component_count": sum(len(case["components"]) for case in cases),
        "component_heterogeneity_count": sum(
            case["release_sets"]["component_heterogeneity"] for case in cases
        ),
        "candidate_counts": {
            label: sum(
                case["gate"]["development_typing_candidate"] == label
                for case in cases
            )
            for label in sorted(
                {case["gate"]["development_typing_candidate"] for case in cases}
            )
        },
        "non_human_consistency_only": {
            "rows_matching_both_sealed_ai_reviewers": sum(
                item["matches_both"] for item in comparisons
            ),
            "row_count": len(comparisons),
            "cases": comparisons,
            "accuracy_claim_allowed": False,
            "human_gold_claim_allowed": False,
        },
        "contract_diagnostic": diagnostic,
        "cases": cases,
        "boundary": {
            "selection_uses_reviewer_labels": False,
            "upstream_source_conditioned_on_non_human_consensus": True,
            "post_unsealing": True,
            "development_diagnostic_only": True,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    case = analysis["cases"][0]
    comparison = analysis["non_human_consistency_only"]["cases"][0]
    lines = [
        "# Multi-Component Artifact-Lineage Audit v1",
        "",
        "> Post-unsealing Codex expert-contract diagnostic; not human gold or an accuracy result.",
        "",
        f"- Sample: `{case['sample_id']}` (`{case['cve_id']}`)",
        f"- Bound components: `{len(case['components'])}`",
        f"- Projection gate: `{case['gate']['status']}`",
        f"- Frozen-set relation: `{case['release_sets']['relation']}`",
        f"- Codex candidate: `{case['gate']['development_typing_candidate']}`",
        f"- Sealed AI reviewers: `{comparison['reviewer_a']} / {comparison['reviewer_b']}`",
        f"- Contract diagnostic: `{analysis['contract_diagnostic']['status']}`",
        "",
        "| Component | Affected published releases | Product edge |",
        "|---|---|---|",
    ]
    for component in case["components"]:
        versions = ", ".join(component["affected_versions"])
        lines.append(
            f"| {component['coordinate']} | {versions} | "
            f"{component['identity_edge']['bound']} |"
        )
    lines.extend(
        [
            "",
            "Both component sets project to the same frozen InLong releases, and their union equals the NVD point set. The resulting representation-discrepancy candidate conflicts with both sealed AI reviewers, so real-person semantic resolution remains required.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    cohort_dir = resolve(args.cohort_dir)
    cohort_path = cohort_dir / "cohort.jsonl"
    cohort_manifest_path = cohort_dir / "manifest.sealed.json"
    contract_path = resolve(args.contract)
    reviewer_a_path = resolve(args.reviewer_a)
    reviewer_b_path = resolve(args.reviewer_b)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite multi-component audit: {output_dir}")
    cohort_manifest = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != graph.file_sha256(cohort_path):
        raise ValueError("cohort seal mismatch")
    cohort = graph.load_jsonl(cohort_path)
    if [row["sample_id"] for row in cohort] != [FIXED_SAMPLE_ID]:
        raise ValueError("cohort differs from fixed multi-component sample")

    cache_dir.mkdir(parents=True, exist_ok=True)
    bodies = {}
    cache_paths = []
    for evidence in EVIDENCE_SOURCES:
        body, paths = graph.fetch_or_load(
            evidence,
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        bodies[evidence.key] = body
        cache_paths.extend(paths)

    cases = [analyze_case(row, bodies) for row in cohort]
    analysis = build_summary(
        cases,
        graph.reviewer_labels(reviewer_a_path),
        graph.reviewer_labels(reviewer_b_path),
    )
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
        "artifact_type": "artifact_lineage_multi_component_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": graph.file_sha256(cohort_path)},
            "cohort_manifest": {
                "path": str(cohort_manifest_path),
                "sha256": graph.file_sha256(cohort_manifest_path),
            },
            "contract": {"path": str(contract_path), "sha256": graph.file_sha256(contract_path)},
            "reviewer_a_diagnostic_only": {
                "path": str(reviewer_a_path),
                "sha256": graph.file_sha256(reviewer_a_path),
            },
            "reviewer_b_diagnostic_only": {
                "path": str(reviewer_b_path),
                "sha256": graph.file_sha256(reviewer_b_path),
            },
            "code": {
                "path": str(Path(__file__).resolve()),
                "sha256": graph.file_sha256(Path(__file__).resolve()),
            },
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": graph.file_sha256(path)}
            for path in sorted(cache_paths)
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": graph.file_sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": graph.file_sha256(markdown_path)},
        },
        "summary": {
            "row_count": analysis["row_count"],
            "projection_gate_passed": analysis["projection_gate_passed"],
            "component_count": analysis["component_count"],
        },
        "contract_diagnostic": analysis["contract_diagnostic"],
        "boundary": analysis["boundary"],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {analysis_path}")
    print(
        "Projection: "
        f"{analysis['projection_gate_passed']}/{analysis['row_count']}; "
        f"diagnostic={analysis['contract_diagnostic']['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
