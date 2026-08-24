#!/usr/bin/env python3
"""Audit heterogeneous multi-package claims in three unseen ecosystems."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from packaging.version import Version

import analyze_artifact_lineage_cross_case as graph
import analyze_artifact_lineage_non_equal as lineage


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_unseen_ecosystem_v1"
DEFAULT_COHORT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_unseen_ecosystem_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/affected_versions_unseen_ecosystem_graph_contract_v1.md"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/artifact_lineage_unseen_ecosystem_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_unseen_ecosystem_v1"
)
MIN_PROJECTION_COVERAGE = 2 / 3
MIN_PASSING_ECOSYSTEMS = 2


def evidence(
    key: str,
    sample_id: str,
    url: str,
    parser: str,
    identity: str | None = None,
    version: str | None = None,
) -> graph.EvidenceSource:
    return graph.EvidenceSource(
        key=key,
        sample_id=sample_id,
        version=version,
        url=url,
        parser=parser,
        expected_identity=identity,
    )


NUGET_SAMPLE = "artifact_lineage_unseen_ecosystem_v1:nuget"
PYPI_SAMPLE = "artifact_lineage_unseen_ecosystem_v1:pypi"
CRATES_SAMPLE = "artifact_lineage_unseen_ecosystem_v1:cratesio"

CASE_SPECS = {
    NUGET_SAMPLE: {
        "cve_id": "CVE-2023-21893",
        "ecosystem": "NuGet",
        "nvd_subject": "database_server",
        "components": {
            "Oracle.ManagedDataAccess": {
                "catalog": evidence(
                    "oracle_manageddataaccess_catalog",
                    NUGET_SAMPLE,
                    "https://api.nuget.org/v3-flatcontainer/oracle.manageddataaccess/index.json",
                    "nuget_catalog",
                    "Oracle.ManagedDataAccess",
                ),
                "metadata": evidence(
                    "oracle_manageddataaccess_21_9_0_nuspec",
                    NUGET_SAMPLE,
                    "https://api.nuget.org/v3-flatcontainer/oracle.manageddataaccess/21.9.0/oracle.manageddataaccess.nuspec",
                    "nuget_nuspec",
                    "Oracle.ManagedDataAccess",
                    "21.9.0",
                ),
            },
            "Oracle.ManagedDataAccess.Core": {
                "catalog": evidence(
                    "oracle_manageddataaccess_core_catalog",
                    NUGET_SAMPLE,
                    "https://api.nuget.org/v3-flatcontainer/oracle.manageddataaccess.core/index.json",
                    "nuget_catalog",
                    "Oracle.ManagedDataAccess.Core",
                ),
                "metadata": evidence(
                    "oracle_manageddataaccess_core_3_21_90_nuspec",
                    NUGET_SAMPLE,
                    "https://api.nuget.org/v3-flatcontainer/oracle.manageddataaccess.core/3.21.90/oracle.manageddataaccess.core.nuspec",
                    "nuget_nuspec",
                    "Oracle.ManagedDataAccess.Core",
                    "3.21.90",
                ),
            },
        },
        "extra_sources": (
            evidence(
                "oracle_cpu_january_2023",
                NUGET_SAMPLE,
                "https://www.oracle.com/security-alerts/cpujan2023.html",
                "oracle_advisory",
            ),
        ),
    },
    PYPI_SAMPLE: {
        "cve_id": "CVE-2023-39631",
        "ecosystem": "PyPI",
        "nvd_subject": "langchain",
        "components": {
            "langchain": {
                "catalog": evidence(
                    "langchain_pypi_catalog",
                    PYPI_SAMPLE,
                    "https://pypi.org/pypi/langchain/json",
                    "pypi_catalog",
                    "langchain",
                ),
            },
            "numexpr": {
                "catalog": evidence(
                    "numexpr_pypi_catalog",
                    PYPI_SAMPLE,
                    "https://pypi.org/pypi/numexpr/json",
                    "pypi_catalog",
                    "numexpr",
                ),
            },
        },
        "extra_sources": (
            evidence(
                "langchain_0_0_245_release",
                PYPI_SAMPLE,
                "https://pypi.org/pypi/langchain/0.0.245/json",
                "pypi_release",
                "langchain",
                "0.0.245",
            ),
        ),
        "product_component": "langchain",
    },
    CRATES_SAMPLE: {
        "cve_id": "CVE-2025-48888",
        "ecosystem": "crates.io",
        "nvd_subject": "deno",
        "components": {
            "deno": {
                "catalog": evidence(
                    "deno_crates_catalog",
                    CRATES_SAMPLE,
                    "https://crates.io/api/v1/crates/deno",
                    "crates_catalog",
                    "deno",
                ),
            },
            "deno_runtime": {
                "catalog": evidence(
                    "deno_runtime_crates_catalog",
                    CRATES_SAMPLE,
                    "https://crates.io/api/v1/crates/deno_runtime",
                    "crates_catalog",
                    "deno_runtime",
                ),
            },
        },
        "extra_sources": tuple(
            evidence(
                f"deno_{version.replace('.', '_')}_dependencies",
                CRATES_SAMPLE,
                f"https://crates.io/api/v1/crates/deno/{version}/dependencies",
                "crates_dependencies",
                "deno",
                version,
            )
            for version in ("1.41.3", "2.2.0", "2.3.0", "2.3.2")
        ),
        "product_component": "deno",
    },
}
EVIDENCE_SOURCES = tuple(
    source
    for sample_id in (NUGET_SAMPLE, PYPI_SAMPLE, CRATES_SAMPLE)
    for source in (
        *tuple(
            item
            for component in CASE_SPECS[sample_id]["components"].values()
            for item in component.values()
        ),
        *CASE_SPECS[sample_id]["extra_sources"],
    )
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", default=DEFAULT_COHORT_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def canonical_catalog(identity: str | None, expected: str, versions: list[str], **extra) -> dict:
    canonical_to_raw = {}
    rejected = []
    for raw in versions:
        parsed = lineage.normalized_version(str(raw))
        if parsed is None:
            rejected.append(str(raw))
        else:
            canonical_to_raw[str(parsed)] = str(raw)
    return {
        "identity": identity,
        "expected_identity": expected,
        "identity_bound": identity is not None and identity.lower() == expected.lower(),
        "raw_version_count": len(versions),
        "parseable_version_count": len(canonical_to_raw),
        "rejected_version_count": len(rejected),
        "rejected_versions": sorted(rejected)[:30],
        "canonical_to_raw": canonical_to_raw,
        **extra,
    }


def parse_catalog(source: graph.EvidenceSource, body: bytes) -> dict:
    document = json.loads(body)
    expected = str(source.expected_identity)
    if source.parser == "nuget_catalog":
        return canonical_catalog(expected, expected, document.get("versions") or [])
    if source.parser == "pypi_catalog":
        info = document.get("info") or {}
        return canonical_catalog(
            info.get("name"),
            expected,
            list((document.get("releases") or {}).keys()),
            repositories=sorted((info.get("project_urls") or {}).values()),
        )
    if source.parser == "crates_catalog":
        crate = document.get("crate") or {}
        return canonical_catalog(
            crate.get("id") or crate.get("name"),
            expected,
            [str(item.get("num")) for item in document.get("versions") or [] if item.get("num")],
            repositories=[str(crate.get("repository") or "")],
        )
    raise ValueError(f"unsupported catalog parser: {source.parser}")


def xml_value(metadata: ET.Element, name: str) -> str | None:
    for child in metadata:
        if child.tag.rsplit("}", 1)[-1] == name:
            return child.text
    return None


def parse_nuspec(source: graph.EvidenceSource, body: bytes) -> dict:
    root = ET.fromstring(body)
    metadata = next(
        item for item in root.iter() if item.tag.rsplit("}", 1)[-1] == "metadata"
    )
    identity = xml_value(metadata, "id")
    version = xml_value(metadata, "version")
    authors = xml_value(metadata, "authors")
    description = xml_value(metadata, "description") or ""
    passed = (
        identity == source.expected_identity
        and version == source.version
        and authors == "Oracle"
        and "Oracle" in description
    )
    return {
        "key": source.key,
        "url": source.url,
        "identity": identity,
        "expected_identity": source.expected_identity,
        "version": version,
        "expected_version": source.version,
        "authors": authors,
        "description": description,
        "passed": passed,
    }


def parse_pypi_release(source: graph.EvidenceSource, body: bytes) -> dict:
    document = json.loads(body)
    info = document.get("info") or {}
    requirements = [str(item) for item in info.get("requires_dist") or []]
    numexpr = [item for item in requirements if re.match(r"(?i)^numexpr(?:\s|\(|$)", item)]
    exact = any(re.search(r"==\s*[^,;)]+", item) for item in numexpr)
    return {
        "key": source.key,
        "url": source.url,
        "identity": info.get("name"),
        "expected_identity": source.expected_identity,
        "version": info.get("version"),
        "expected_version": source.version,
        "numexpr_requirements": numexpr,
        "dependency_present": bool(numexpr),
        "dependency_exactly_resolved": bool(numexpr) and exact,
        "passed": (
            str(info.get("name") or "").lower()
            == str(source.expected_identity).lower()
            and info.get("version") == source.version
            and bool(numexpr)
        ),
    }


def parse_crates_dependencies(source: graph.EvidenceSource, body: bytes) -> dict:
    document = json.loads(body)
    dependencies = [
        item
        for item in document.get("dependencies") or []
        if item.get("crate_id") == "deno_runtime"
        and item.get("kind") in {"normal", "build"}
        and item.get("optional") is False
    ]
    requirements = sorted({str(item.get("req") or "") for item in dependencies})
    exact = bool(requirements) and all(req.startswith("=") for req in requirements)
    return {
        "key": source.key,
        "url": source.url,
        "product_version": source.version,
        "dependency": "deno_runtime",
        "requirements": requirements,
        "required_dependency_present": bool(dependencies),
        "dependency_exactly_resolved": exact,
        "passed": bool(dependencies),
    }


def parse_oracle_advisory(source: graph.EvidenceSource, body: bytes) -> dict:
    text = body.decode("utf-8", errors="replace")
    counts = {
        term: text.lower().count(term.lower())
        for term in (
            "Oracle Database Server",
            "19c",
            "21c",
            "ManagedDataAccess",
            "21.9.0",
            "3.21.90",
        )
    }
    return {
        "key": source.key,
        "url": source.url,
        "term_counts": counts,
        "product_versions_present": counts["19c"] > 0 and counts["21c"] > 0,
        "package_versions_present": (
            counts["ManagedDataAccess"] > 0
            and counts["21.9.0"] > 0
            and counts["3.21.90"] > 0
        ),
    }


def component_records(row: dict, component: str) -> list[dict]:
    return [
        record
        for record in row["ghsa_value"]
        if str(record.get("package_name") or record.get("product") or "") == component
    ]


def signature_boundaries(signature: list[dict]) -> set[str]:
    return {
        str(value)
        for span in signature
        for value in (span.get("start"), span.get("end"))
        if value and value != "0"
    }


def boundaries_in_catalog(signature: list[dict], catalog: dict) -> tuple[bool, list[str]]:
    domain = {Version(value) for value in catalog["canonical_to_raw"]}
    missing = []
    for raw in signature_boundaries(signature):
        parsed = lineage.normalized_version(raw)
        if parsed is None or parsed not in domain:
            missing.append(raw)
    return not missing, sorted(missing)


def sorted_versions(values: set[str]) -> list[str]:
    return sorted(values, key=Version)


def analyze_case(row: dict, bodies: dict[str, bytes]) -> dict:
    spec = CASE_SPECS[row["sample_id"]]
    components = []
    catalogs = {}
    component_boundaries_ok = True
    for name, component_spec in sorted(spec["components"].items()):
        catalog_source = component_spec["catalog"]
        catalog = parse_catalog(catalog_source, bodies[catalog_source.key])
        catalogs[name] = catalog
        records = component_records(row, name)
        affected = lineage.affected_set(records, catalog)
        signature = row["ghsa_component_range_signatures"][name]
        boundary_ok, missing = boundaries_in_catalog(signature, catalog)
        component_boundaries_ok = component_boundaries_ok and boundary_ok
        components.append(
            {
                "coordinate": name,
                "catalog": {
                    key: value for key, value in catalog.items() if key != "canonical_to_raw"
                },
                "range_signature": signature,
                "missing_boundary_versions": missing,
                "affected_versions": sorted_versions(affected),
                "affected_version_count": len(affected),
            }
        )

    extras = []
    edge_classes = {}
    product_edges_bound = False
    deterministic_mapping = False
    product_component = spec.get("product_component")
    if row["sample_id"] == NUGET_SAMPLE:
        metadata = []
        for name, component_spec in sorted(spec["components"].items()):
            item = parse_nuspec(component_spec["metadata"], bodies[component_spec["metadata"].key])
            metadata.append(item)
            edge_classes[name] = "parallel_distribution"
        advisory = parse_oracle_advisory(spec["extra_sources"][0], bodies[spec["extra_sources"][0].key])
        extras = [*metadata, advisory]
        product_edges_bound = all(item["passed"] for item in metadata) and advisory["product_versions_present"]
        deterministic_mapping = advisory["package_versions_present"]
    elif row["sample_id"] == PYPI_SAMPLE:
        release = parse_pypi_release(spec["extra_sources"][0], bodies[spec["extra_sources"][0].key])
        extras = [release]
        edge_classes = {
            "langchain": "coordinated_product_component",
            "numexpr": "dependency_constraint_only",
        }
        repos = {
            name: set(catalogs[name].get("repositories") or [])
            for name in catalogs
        }
        product_edges_bound = (
            release["passed"]
            and any("langchain-ai/langchain" in url for url in repos["langchain"])
            and any("pydata/numexpr" in url for url in repos["numexpr"])
        )
        deterministic_mapping = release["dependency_exactly_resolved"]
    else:
        dependencies = [
            parse_crates_dependencies(source, bodies[source.key])
            for source in spec["extra_sources"]
        ]
        extras = dependencies
        edge_classes = {
            "deno": "coordinated_product_component",
            "deno_runtime": "dependency_constraint_only",
        }
        repositories = {
            name: set(catalogs[name].get("repositories") or [])
            for name in catalogs
        }
        product_edges_bound = (
            repositories["deno"] == {"https://github.com/denoland/deno"}
            and repositories["deno_runtime"] == {"https://github.com/denoland/deno"}
            and all(item["passed"] for item in dependencies)
        )
        deterministic_mapping = all(
            item["dependency_exactly_resolved"] for item in dependencies
        )

    registry_identities_bound = all(
        catalog["identity_bound"] for catalog in catalogs.values()
    )
    nvd_domain_bound = False
    nvd_missing = sorted(signature_boundaries(row["nvd_range_signature"]))
    partial_nvd_set: set[str] = set()
    partial_direct_set: set[str] = set()
    if product_component:
        product_catalog = catalogs[product_component]
        nvd_domain_bound, nvd_missing = boundaries_in_catalog(
            row["nvd_range_signature"], product_catalog
        )
        partial_nvd_set = lineage.affected_set(row["nvd_value"], product_catalog)
        partial_direct_set = lineage.affected_set(
            component_records(row, product_component), product_catalog
        )

    subject_match = (
        row["cve_id"] == spec["cve_id"]
        and row["ecosystem"] == spec["ecosystem"]
        and row["nvd_subject"] == spec["nvd_subject"]
        and set(row["ghsa_subjects"]) == set(spec["components"])
    )
    component_union_mappable = (
        product_edges_bound
        and deterministic_mapping
        and component_boundaries_ok
        and nvd_domain_bound
    )
    prechecks = {
        "claim_subjects_bound": subject_match,
        "registry_package_identities_bound": registry_identities_bound,
        "component_boundaries_in_registry_catalogs": component_boundaries_ok,
        "product_component_edges_bound": product_edges_bound,
        "nvd_product_release_domain_bound": nvd_domain_bound,
        "deterministic_component_to_product_release_mapping": deterministic_mapping,
        "affected_component_union_mappable": component_union_mappable,
        "shared_product_release_domain_bound": component_union_mappable,
    }
    relation = None
    checks = {**prechecks, "set_relation_computed": relation is not None}
    failed = [name for name, passed in checks.items() if not passed]
    gate_passed = not failed
    unique_sets = {
        tuple(component["affected_versions"]) for component in components
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "ecosystem": row["ecosystem"],
        "product_subject": row["nvd_subject"],
        "components": components,
        "edge_classes": edge_classes,
        "extra_evidence": extras,
        "partial_product_view_not_a_relation": {
            "nvd_versions": sorted_versions(partial_nvd_set),
            "direct_component_versions": sorted_versions(partial_direct_set),
            "nvd_missing_boundary_versions": nvd_missing,
        },
        "release_sets": {
            "relation": relation,
            "component_heterogeneity": len(unique_sets) > 1,
            "product_union_computed": False,
        },
        "checks": checks,
        "gate": {
            "status": (
                "unseen_ecosystem_projection_allowed_development_only"
                if gate_passed
                else "abstain_unseen_ecosystem_projection_unresolved"
            ),
            "passed": gate_passed,
            "failed_checks": failed,
            "development_typing_candidate": lineage.relation_candidate(relation),
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        },
        "selection_uses_reviewer_labels": False,
        "upstream_source_conditioned_on_non_human_consensus": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
    }


def advancement_gate(cases: list[dict]) -> dict:
    row_count = len(cases)
    passed = [case for case in cases if case["gate"]["passed"]]
    coverage = len(passed) / row_count
    passing_ecosystems = sorted({case["ecosystem"] for case in passed})
    checks = {
        "minimum_projection_coverage": coverage >= MIN_PROJECTION_COVERAGE,
        "minimum_passing_ecosystems": len(passing_ecosystems) >= MIN_PASSING_ECOSYSTEMS,
        "non_human_boundary_preserved": all(
            case["label_is_human"] is False
            and case["eligible_for_human_gold_claim"] is False
            for case in cases
        ),
        "label_independent_source_preserved": all(
            case["selection_uses_reviewer_labels"] is False
            and case["upstream_source_conditioned_on_non_human_consensus"] is False
            for case in cases
        ),
    }
    failed = [name for name, passed_check in checks.items() if not passed_check]
    return {
        "status": (
            "advance_unseen_ecosystem_graph_candidate"
            if not failed
            else "no_go_unseen_ecosystem_graph_unstable"
        ),
        "passed": not failed,
        "thresholds_fixed_before_evidence_fetch": True,
        "minimum_projection_coverage": MIN_PROJECTION_COVERAGE,
        "minimum_passing_ecosystems": MIN_PASSING_ECOSYSTEMS,
        "observed_projection_coverage": coverage,
        "observed_passing_ecosystems": passing_ecosystems,
        "checks": checks,
        "failed_checks": failed,
        "production_switch_allowed": False,
        "human_gold_claim_allowed": False,
    }


def build_summary(cases: list[dict]) -> dict:
    gate = advancement_gate(cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_unseen_ecosystem_analysis",
        "row_count": len(cases),
        "projection_gate_passed": sum(case["gate"]["passed"] for case in cases),
        "component_heterogeneity_count": sum(
            case["release_sets"]["component_heterogeneity"] for case in cases
        ),
        "candidate_counts": {
            label: sum(case["gate"]["development_typing_candidate"] == label for case in cases)
            for label in sorted({case["gate"]["development_typing_candidate"] for case in cases})
        },
        "advancement_gate": gate,
        "cases": cases,
        "boundary": {
            "selection_uses_reviewer_labels": False,
            "upstream_source_conditioned_on_non_human_consensus": False,
            "post_unsealing": True,
            "development_diagnostic_only": True,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    lines = [
        "# Unseen-Ecosystem Heterogeneous Multi-Package Audit v1",
        "",
        "> Label-independent full-aligned-data development diagnostic; not human gold or accuracy.",
        "",
        f"- Rows: `{analysis['row_count']}`",
        f"- Projection gates passed: `{analysis['projection_gate_passed']}/{analysis['row_count']}`",
        f"- Advancement gate: `{analysis['advancement_gate']['status']}`",
        "",
        "| Ecosystem | CVE | Edge classes | Missing product boundaries | Candidate |",
        "|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        edges = ", ".join(
            f"{name}:{edge}" for name, edge in sorted(case["edge_classes"].items())
        )
        missing = ", ".join(
            case["partial_product_view_not_a_relation"]["nvd_missing_boundary_versions"]
        ) or "none"
        lines.append(
            f"| {case['ecosystem']} | {case['cve_id']} | {edges} | {missing} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend(
        [
            "",
            "All rows retain their component-level release sets, but no row has a deterministic total mapping from every affected package release into one NVD product-release domain. The fixed cross-ecosystem advancement gate therefore remains no-go.",
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
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite unseen-ecosystem audit: {output_dir}")
    cohort_manifest = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != graph.file_sha256(cohort_path):
        raise ValueError("cohort seal mismatch")
    cohort = graph.load_jsonl(cohort_path)
    if {row["sample_id"] for row in cohort} != set(CASE_SPECS):
        raise ValueError("cohort differs from fixed unseen-ecosystem case specification")

    cache_dir.mkdir(parents=True, exist_ok=True)
    bodies = {}
    cache_paths = []
    for source in EVIDENCE_SOURCES:
        body, paths = graph.fetch_or_load(
            source,
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        bodies[source.key] = body
        cache_paths.extend(paths)
    cases = [analyze_case(row, bodies) for row in cohort]
    analysis = build_summary(cases)
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
        "artifact_type": "artifact_lineage_unseen_ecosystem_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": graph.file_sha256(cohort_path)},
            "cohort_manifest": {
                "path": str(cohort_manifest_path),
                "sha256": graph.file_sha256(cohort_manifest_path),
            },
            "contract": {"path": str(contract_path), "sha256": graph.file_sha256(contract_path)},
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
        "advancement_gate": analysis["advancement_gate"],
        "boundary": analysis["boundary"],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {analysis_path}")
    print(f"Projection coverage: {analysis['projection_gate_passed']}/{analysis['row_count']}")
    print(f"Advancement gate: {analysis['advancement_gate']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
