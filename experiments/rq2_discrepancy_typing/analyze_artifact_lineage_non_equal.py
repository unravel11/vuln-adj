#!/usr/bin/env python3
"""Evaluate non-equal artifact claims over frozen ecosystem release catalogs."""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from packaging.version import InvalidVersion, Version

import analyze_artifact_lineage_cross_case as graph
import build_artifact_lineage_development_cohort as cohort_util


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_non_equal_v1"
DEFAULT_COHORT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_non_equal_v1"
)
DEFAULT_CONTRACT = graph.DEFAULT_CONTRACT
DEFAULT_REVIEWER_A = graph.DEFAULT_REVIEWER_A
DEFAULT_REVIEWER_B = graph.DEFAULT_REVIEWER_B
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/artifact_lineage_non_equal_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_non_equal_v1"
)
MIN_PROJECTION_COVERAGE = 0.8
MIN_BOTH_REVIEWER_CONSISTENCY = 0.8


def source(
    key: str,
    sample_id: str,
    url: str,
    parser: str,
    identity: str,
) -> graph.EvidenceSource:
    return graph.EvidenceSource(
        key=key,
        sample_id=sample_id,
        version=None,
        url=url,
        parser=parser,
        expected_identity=identity,
    )


CASE_SPECS = {
    "rq2_typing_holdout_v1:016": {
        "cve_id": "CVE-2024-29900",
        "ecosystem": "npm",
        "nvd_subject": "packager",
        "ghsa_subject": "@electron/packager",
        "edge_type": "package_identity",
        "authority_class": "ecosystem_registry_catalog",
        "expected_repository": "electron/packager",
        "catalog": source(
            "electron_packager_npm_catalog",
            "rq2_typing_holdout_v1:016",
            "https://registry.npmjs.org/%40electron%2Fpackager",
            "npm_catalog",
            "@electron/packager",
        ),
        "anchors": (),
    },
    "rq2_typing_holdout_v1:026": {
        "cve_id": "CVE-2023-3469",
        "ecosystem": "Packagist",
        "nvd_subject": "phpmyfaq",
        "ghsa_subject": "thorsten/phpmyfaq",
        "edge_type": "package_identity",
        "authority_class": "ecosystem_registry_catalog",
        "expected_repository": "thorsten/phpmyfaq",
        "catalog": source(
            "phpmyfaq_packagist_catalog",
            "rq2_typing_holdout_v1:026",
            "https://repo.packagist.org/p2/thorsten/phpmyfaq.json",
            "packagist_catalog",
            "thorsten/phpmyfaq",
        ),
        "anchors": (),
    },
    "rq2_typing_holdout_v1:086": {
        "cve_id": "CVE-2025-53106",
        "ecosystem": "Maven",
        "nvd_subject": "graylog",
        "ghsa_subject": "org.graylog2:graylog2-server",
        "edge_type": "product_contains_artifact",
        "authority_class": "ecosystem_registry_component_pom",
        "required_project_text": "Graylog",
        "catalog": source(
            "graylog_maven_catalog",
            "rq2_typing_holdout_v1:086",
            "https://repo.maven.apache.org/maven2/org/graylog2/graylog2-server/maven-metadata.xml",
            "maven_catalog",
            "org.graylog2:graylog2-server",
        ),
        "anchors": (
            graph.EvidenceSource(
                key="graylog_6_3_0_pom",
                sample_id="rq2_typing_holdout_v1:086",
                version="6.3.0",
                url=(
                    "https://repo.maven.apache.org/maven2/org/graylog2/"
                    "graylog2-server/6.3.0/graylog2-server-6.3.0.pom"
                ),
                parser="maven_pom",
                expected_identity="org.graylog2:graylog2-server",
            ),
        ),
    },
    "rq2_typing_holdout_v1:737": {
        "cve_id": "CVE-2023-25240",
        "ecosystem": "Packagist",
        "nvd_subject": "pimcore",
        "ghsa_subject": "pimcore/pimcore",
        "edge_type": "package_identity",
        "authority_class": "ecosystem_registry_catalog",
        "expected_repository": "pimcore/pimcore",
        "catalog": source(
            "pimcore_packagist_catalog",
            "rq2_typing_holdout_v1:737",
            "https://repo.packagist.org/p2/pimcore/pimcore.json",
            "packagist_catalog",
            "pimcore/pimcore",
        ),
        "anchors": (),
    },
    "rq2_typing_holdout_v1:864": {
        "cve_id": "CVE-2023-46658",
        "ecosystem": "Maven",
        "nvd_subject": "msteams_webhook_trigger",
        "ghsa_subject": "io.jenkins.plugins:teams-webhook-trigger",
        "edge_type": "product_contains_artifact",
        "authority_class": "ecosystem_registry_component_pom",
        "required_project_text": "MSTeams Webhook Trigger Plugin",
        "catalog": source(
            "jenkins_teams_webhook_maven_catalog",
            "rq2_typing_holdout_v1:864",
            "https://repo.jenkins-ci.org/releases/io/jenkins/plugins/teams-webhook-trigger/maven-metadata.xml",
            "maven_catalog",
            "io.jenkins.plugins:teams-webhook-trigger",
        ),
        "anchors": (
            graph.EvidenceSource(
                key="jenkins_teams_webhook_0_1_1_pom",
                sample_id="rq2_typing_holdout_v1:864",
                version="0.1.1",
                url=(
                    "https://repo.jenkins-ci.org/releases/io/jenkins/plugins/"
                    "teams-webhook-trigger/0.1.1/teams-webhook-trigger-0.1.1.pom"
                ),
                parser="maven_pom",
                expected_identity="io.jenkins.plugins:teams-webhook-trigger",
            ),
        ),
    },
}
EVIDENCE_SOURCES = tuple(
    evidence
    for sample_id in sorted(CASE_SPECS)
    for evidence in (
        CASE_SPECS[sample_id]["catalog"],
        *CASE_SPECS[sample_id]["anchors"],
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


def normalized_version(value: str) -> Version | None:
    text = value.strip()
    if not text or text == "0":
        return None
    text = re.sub(
        r"-(alpha|beta|rc|milestone)[.-]?(\d*)$",
        lambda match: f"{match.group(1)}{match.group(2) or '0'}",
        text,
        flags=re.IGNORECASE,
    )
    try:
        return Version(text)
    except InvalidVersion:
        return None


def parse_catalog(source_spec: graph.EvidenceSource, body: bytes) -> dict:
    expected = source_spec.expected_identity
    if source_spec.parser == "maven_catalog":
        root = ET.fromstring(body)
        identity = f"{root.findtext('groupId')}:{root.findtext('artifactId')}"
        versions = [item.text for item in root.findall("./versioning/versions/version") if item.text]
        repositories = []
    elif source_spec.parser == "packagist_catalog":
        document = json.loads(body)
        rows = document.get("packages", {}).get(expected, [])
        # Composer 2 minified metadata omits repeated package-level keys after
        # the first version. Every name that is present must still match.
        observed_names = {row.get("name") for row in rows if row.get("name")}
        identity = expected if rows and observed_names == {expected} else None
        versions = [str(row.get("version")) for row in rows if row.get("version")]
        repositories = sorted(
            {
                str((row.get("source") or {}).get("url") or "")
                for row in rows
                if (row.get("source") or {}).get("url")
            }
        )
    elif source_spec.parser == "npm_catalog":
        document = json.loads(body)
        identity = document.get("name")
        versions = list((document.get("versions") or {}).keys())
        repository = document.get("repository") or {}
        repository_url = repository if isinstance(repository, str) else repository.get("url")
        repositories = [str(repository_url or "")]
    else:
        raise ValueError(f"unsupported catalog parser: {source_spec.parser}")
    parseable = {}
    rejected = []
    for raw in versions:
        parsed = normalized_version(raw)
        if parsed is None:
            rejected.append(raw)
        else:
            parseable[str(parsed)] = raw
    return {
        "identity": identity,
        "expected_identity": expected,
        "identity_bound": identity == expected,
        "raw_version_count": len(versions),
        "parseable_version_count": len(parseable),
        "rejected_version_count": len(rejected),
        "rejected_versions": sorted(rejected)[:30],
        "canonical_to_raw": parseable,
        "repositories": repositories,
    }


def endpoint_values(row: dict) -> set[str]:
    endpoints = set()
    for signature_name in ("nvd_range_signature", "ghsa_range_signature"):
        for item in row[signature_name]:
            for value in (item.get("start"), item.get("end")):
                if value and value != "0":
                    endpoints.add(value)
    return endpoints


def record_contains(record: dict, version: Version) -> bool:
    point = cohort_util.cpe_release(record)
    has_range = any(
        record.get(key)
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
            "introduced",
            "fixed",
        )
    )
    if point and not has_range:
        parsed_point = normalized_version(point)
        return parsed_point is not None and version == parsed_point

    lower = record.get("version_start_including") or record.get("introduced")
    lower_inclusive = True
    if record.get("version_start_excluding"):
        lower = record["version_start_excluding"]
        lower_inclusive = False
    upper = record.get("version_end_excluding") or record.get("fixed")
    upper_inclusive = False
    if record.get("version_end_including"):
        upper = record["version_end_including"]
        upper_inclusive = True
    if lower and lower != "0":
        parsed_lower = normalized_version(str(lower))
        if parsed_lower is None:
            return False
        if version < parsed_lower or (version == parsed_lower and not lower_inclusive):
            return False
    if upper:
        parsed_upper = normalized_version(str(upper))
        if parsed_upper is None:
            return False
        if version > parsed_upper or (version == parsed_upper and not upper_inclusive):
            return False
    return bool(lower or upper or point)


def affected_set(records: list[dict], catalog: dict) -> set[str]:
    result = set()
    for canonical in catalog["canonical_to_raw"]:
        parsed = Version(canonical)
        if any(record_contains(record, parsed) for record in records):
            result.add(canonical)
    return result


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


def relation_candidate(relation: str | None) -> str:
    if relation == "equal":
        return "representation_discrepancy"
    if relation in {"strict_subset", "strict_superset"}:
        return "incomplete"
    if relation in {"overlap_without_containment", "disjoint"}:
        return "factual_conflict"
    return "uncertain"


def analyze_case(row: dict, bodies: dict[str, bytes]) -> dict:
    spec = CASE_SPECS[row["sample_id"]]
    catalog_source = spec["catalog"]
    catalog = parse_catalog(catalog_source, bodies[catalog_source.key])
    anchors = [graph.extract_evidence(item, bodies[item.key]) for item in spec["anchors"]]
    repository_bound = True
    if spec.get("expected_repository"):
        expected = spec["expected_repository"].lower()
        repository_bound = any(expected in item.lower() for item in catalog["repositories"])
    project_anchor_bound = all(item["passed"] for item in anchors)
    if spec.get("required_project_text"):
        project_anchor_bound = project_anchor_bound and all(
            spec["required_project_text"] in str(item.get("project_name") or "")
            for item in anchors
        )
    subject_match = (
        row["cve_id"] == spec["cve_id"]
        and row["nvd_subject"] == spec["nvd_subject"]
        and row["ghsa_subject"] == spec["ghsa_subject"]
        and spec["edge_type"] in graph.ALLOWED_EDGE_TYPES
    )
    endpoints = endpoint_values(row)
    normalized_endpoints = {normalized_version(value) for value in endpoints}
    endpoints_parse = None not in normalized_endpoints
    catalog_versions = {Version(value) for value in catalog["canonical_to_raw"]}
    boundaries_bound = endpoints_parse and normalized_endpoints <= catalog_versions
    identity_bound = (
        subject_match
        and catalog["identity_bound"]
        and repository_bound
        and project_anchor_bound
    )
    relation = None
    nvd_set: set[str] = set()
    ghsa_set: set[str] = set()
    if identity_bound and boundaries_bound:
        nvd_set = affected_set(row["nvd_value"], catalog)
        ghsa_set = affected_set(row["ghsa_value"], catalog)
        relation = set_relation(nvd_set, ghsa_set)
    checks = {
        "claim_subjects_bound": identity_bound,
        "boundary_releases_bound": boundaries_bound,
        "lineage_path_complete": identity_bound,
        "ordering_supported": endpoints_parse and bool(catalog_versions),
        "shared_release_domain_bound": identity_bound and boundaries_bound,
        "set_relation_computed": relation is not None,
    }
    failed = [name for name, passed in checks.items() if not passed]
    gate_passed = not failed
    candidate = relation_candidate(relation if gate_passed else None)
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "ecosystem": spec["ecosystem"],
        "identity_edge": {
            "from": row["nvd_subject"],
            "to": row["ghsa_subject"],
            "edge_type": spec["edge_type"],
            "authority_class": spec["authority_class"],
            "scope": "stable_parseable_registry_releases",
            "bound": identity_bound,
        },
        "catalog": {key: value for key, value in catalog.items() if key != "canonical_to_raw"},
        "boundary_versions": sorted(
            endpoints,
            key=lambda value: (normalized_version(value) or Version("0"), value),
        ),
        "anchors": anchors,
        "release_sets": {
            "nvd_count": len(nvd_set),
            "ghsa_count": len(ghsa_set),
            "relation": relation,
            "nvd_only": sorted(nvd_set - ghsa_set, key=Version),
            "ghsa_only": sorted(ghsa_set - nvd_set, key=Version),
        },
        "checks": checks,
        "gate": {
            "status": (
                "artifact_lineage_projection_allowed_development_only"
                if gate_passed
                else "abstain_artifact_lineage_projection_unresolved"
            ),
            "passed": gate_passed,
            "failed_checks": failed,
            "development_typing_candidate": candidate,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        },
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
    }


def advancement_gate(cases: list[dict], consistency: list[dict]) -> dict:
    row_count = len(cases)
    projection_coverage = sum(case["gate"]["passed"] for case in cases) / row_count
    both_consistency = sum(item["matches_both"] for item in consistency) / row_count
    checks = {
        "minimum_projection_coverage": projection_coverage >= MIN_PROJECTION_COVERAGE,
        "minimum_both_reviewer_consistency": (
            both_consistency >= MIN_BOTH_REVIEWER_CONSISTENCY
        ),
        "non_human_boundary_preserved": all(
            case["label_is_human"] is False
            and case["eligible_for_human_gold_claim"] is False
            for case in cases
        ),
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "status": "advance_non_equal_graph_candidate" if not failed else "no_go_non_equal_graph_unstable",
        "passed": not failed,
        "thresholds_fixed_before_run": True,
        "minimum_projection_coverage": MIN_PROJECTION_COVERAGE,
        "minimum_both_reviewer_consistency": MIN_BOTH_REVIEWER_CONSISTENCY,
        "observed_projection_coverage": projection_coverage,
        "observed_both_reviewer_consistency": both_consistency,
        "checks": checks,
        "failed_checks": failed,
        "production_switch_allowed": False,
        "human_gold_claim_allowed": False,
    }


def build_summary(cases: list[dict], reviewer_a: dict, reviewer_b: dict) -> dict:
    consistency = []
    for case in cases:
        candidate = case["gate"]["development_typing_candidate"]
        a_label = reviewer_a.get(case["sample_id"])
        b_label = reviewer_b.get(case["sample_id"])
        consistency.append(
            {
                "sample_id": case["sample_id"],
                "candidate": candidate,
                "reviewer_a": a_label,
                "reviewer_b": b_label,
                "matches_both": candidate == a_label == b_label,
            }
        )
    gate = advancement_gate(cases, consistency)
    relation_labels = {
        case["release_sets"]["relation"] or "unresolved" for case in cases
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_non_equal_analysis",
        "row_count": len(cases),
        "projection_gate_passed": sum(case["gate"]["passed"] for case in cases),
        "relation_counts": {
            relation: sum(
                (case["release_sets"]["relation"] or "unresolved") == relation
                for case in cases
            )
            for relation in sorted(relation_labels)
        },
        "candidate_counts": {
            label: sum(case["gate"]["development_typing_candidate"] == label for case in cases)
            for label in sorted({case["gate"]["development_typing_candidate"] for case in cases})
        },
        "non_human_consistency_only": {
            "rows_matching_both_sealed_ai_reviewers": sum(item["matches_both"] for item in consistency),
            "row_count": len(consistency),
            "cases": consistency,
            "accuracy_claim_allowed": False,
            "human_gold_claim_allowed": False,
        },
        "advancement_gate": gate,
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
    gate = analysis["advancement_gate"]
    lines = [
        "# Non-Equal Artifact-Lineage Audit v1",
        "",
        "> Post-unsealing, non-human development diagnostic; not an accuracy result.",
        "",
        f"- Rows: `{analysis['row_count']}`",
        f"- Projection gates passed: `{analysis['projection_gate_passed']}/{analysis['row_count']}`",
        f"- Agreement with both sealed AI reviewers: `{analysis['non_human_consistency_only']['rows_matching_both_sealed_ai_reviewers']}/{analysis['row_count']}`",
        f"- Advancement gate: `{gate['status']}`",
        "",
        "| Sample | Relation | Candidate | Reviewer A/B | Projection gate |",
        "|---|---|---|---|---|",
    ]
    consistency = {
        item["sample_id"]: item for item in analysis["non_human_consistency_only"]["cases"]
    }
    for case in analysis["cases"]:
        item = consistency[case["sample_id"]]
        lines.append(
            f"| {case['sample_id']} | {case['release_sets']['relation']} | "
            f"{case['gate']['development_typing_candidate']} | "
            f"{item['reviewer_a']} / {item['reviewer_b']} | {case['gate']['status']} |"
        )
    lines.extend(
        [
            "",
            "The unchanged relation-to-taxonomy map does not meet the fixed cross-case consistency threshold. No production, accuracy, or human-gold claim is allowed.",
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
        raise FileExistsError(f"refusing to overwrite non-equal audit: {output_dir}")
    cohort_manifest = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != graph.file_sha256(cohort_path):
        raise ValueError("cohort seal mismatch")
    cohort = graph.load_jsonl(cohort_path)
    if {row["sample_id"] for row in cohort} != set(CASE_SPECS):
        raise ValueError("cohort and evidence specification sample IDs differ")
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
    analysis_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_non_equal_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": graph.file_sha256(cohort_path)},
            "cohort_manifest": {"path": str(cohort_manifest_path), "sha256": graph.file_sha256(cohort_manifest_path)},
            "contract": {"path": str(contract_path), "sha256": graph.file_sha256(contract_path)},
            "reviewer_a_diagnostic_only": {"path": str(reviewer_a_path), "sha256": graph.file_sha256(reviewer_a_path)},
            "reviewer_b_diagnostic_only": {"path": str(reviewer_b_path), "sha256": graph.file_sha256(reviewer_b_path)},
            "code": {"path": str(Path(__file__).resolve()), "sha256": graph.file_sha256(Path(__file__).resolve())},
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
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {analysis_path}")
    print(f"Projection coverage: {analysis['projection_gate_passed']}/{analysis['row_count']}")
    print(f"Advancement gate: {analysis['advancement_gate']['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
