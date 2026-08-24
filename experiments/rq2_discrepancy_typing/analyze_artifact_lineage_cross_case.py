#!/usr/bin/env python3
"""Run a fail-closed artifact-lineage audit on the cross-case cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "artifact_lineage_cross_case_v1"
DEFAULT_COHORT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_cross_case_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/affected_versions_lineage_graph_contract_v1.md"
)
DEFAULT_REVIEWER_A = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/reviewer_a.jsonl"
)
DEFAULT_REVIEWER_B = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/reviewer_b.jsonl"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/artifact_lineage_cross_case_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_cross_case_v1"
)
MAX_RESPONSE_BYTES = 2_000_000
ALLOWED_EDGE_TYPES = {
    "package_identity",
    "product_contains_artifact",
    "artifact_alias",
}


@dataclass(frozen=True)
class EvidenceSource:
    key: str
    sample_id: str
    version: str | None
    url: str
    parser: str
    expected_identity: str | None = None
    required_text: tuple[str, ...] = ()


def maven_sources(
    sample_id: str,
    coordinate: str,
    versions: list[str],
    *,
    prefix: str,
) -> tuple[EvidenceSource, ...]:
    group, artifact = coordinate.split(":", 1)
    group_path = group.replace(".", "/")
    return tuple(
        EvidenceSource(
            key=f"{prefix}_{version.replace('.', '_')}_pom",
            sample_id=sample_id,
            version=version,
            url=(
                f"https://repo.maven.apache.org/maven2/{group_path}/{artifact}/"
                f"{version}/{artifact}-{version}.pom"
            ),
            parser="maven_pom",
            expected_identity=coordinate,
        )
        for version in versions
    )


def composer_sources(
    sample_id: str,
    repository: str,
    package: str,
    versions: list[str],
    *,
    prefix: str,
) -> tuple[EvidenceSource, ...]:
    return tuple(
        EvidenceSource(
            key=f"{prefix}_{version.replace('.', '_')}_composer",
            sample_id=sample_id,
            version=version,
            url=f"https://raw.githubusercontent.com/{repository}/{version}/composer.json",
            parser="composer_manifest",
            expected_identity=package,
        )
        for version in versions
    )


def go_sources(
    sample_id: str,
    repository: str,
    module: str,
    versions: list[str],
    *,
    prefix: str,
    path: str = "go.mod",
) -> tuple[EvidenceSource, ...]:
    return tuple(
        EvidenceSource(
            key=f"{prefix}_{version.replace('.', '_')}_gomod",
            sample_id=sample_id,
            version=version,
            url=f"https://raw.githubusercontent.com/{repository}/v{version}/{path}",
            parser="go_module",
            expected_identity=module,
        )
        for version in versions
    )


CASE_SPECS = {
    "rq2_typing_holdout_v1:006": {
        "cve_id": "CVE-2025-25227",
        "ecosystem": "Packagist",
        "nvd_subject": "joomla\\!",
        "ghsa_subject": "joomla/joomla-cms",
        "edge_type": "package_identity",
        "authority_class": "official_root_manifest",
        "sources": composer_sources(
            "rq2_typing_holdout_v1:006",
            "joomla/joomla-cms",
            "joomla/joomla-cms",
            ["4.0.0", "4.4.13", "5.0.0", "5.2.6"],
            prefix="joomla",
        ),
    },
    "rq2_typing_holdout_v1:154": {
        "cve_id": "CVE-2023-50291",
        "ecosystem": "Maven",
        "nvd_subject": "solr",
        "ghsa_subject": "org.apache.solr:solr-core",
        "edge_type": "product_contains_artifact",
        "authority_class": "ecosystem_registry_component_pom",
        "required_project_text": "Apache Solr",
        "sources": maven_sources(
            "rq2_typing_holdout_v1:154",
            "org.apache.solr:solr-core",
            ["6.0.0", "8.11.3", "9.0.0", "9.3.0"],
            prefix="solr_core",
        ),
    },
    "rq2_typing_holdout_v1:212": {
        "cve_id": "CVE-2023-28841",
        "ecosystem": "Go",
        "nvd_subject": "moby",
        "ghsa_subject": "github.com/docker/docker",
        "edge_type": "artifact_alias",
        "authority_class": "official_project_plus_ecosystem_registry",
        "sources": (
            EvidenceSource(
                key="moby_project_readme_23_0_3",
                sample_id="rq2_typing_holdout_v1:212",
                version=None,
                url=(
                    "https://raw.githubusercontent.com/moby/moby/"
                    "v23.0.3/README.md"
                ),
                parser="project_text",
                required_text=("The Moby Project", "created by Docker"),
            ),
            *tuple(
                EvidenceSource(
                    key=f"docker_module_{version.replace('.', '_')}",
                    sample_id="rq2_typing_holdout_v1:212",
                    version=version,
                    url=(
                        "https://proxy.golang.org/github.com/docker/docker/@v/"
                        f"v{version}{'' if version == '1.12.0' else '+incompatible'}.mod"
                    ),
                    parser="go_module",
                    expected_identity="github.com/docker/docker",
                )
                for version in ["1.12.0", "20.10.24", "23.0.0", "23.0.3"]
            ),
        ),
    },
    "rq2_typing_holdout_v1:461": {
        "cve_id": "CVE-2024-24807",
        "ecosystem": "Packagist",
        "nvd_subject": "sulu",
        "ghsa_subject": "sulu/sulu",
        "edge_type": "package_identity",
        "authority_class": "official_root_manifest",
        "sources": composer_sources(
            "rq2_typing_holdout_v1:461",
            "sulu/sulu",
            "sulu/sulu",
            ["2.0.0", "2.4.16", "2.5.0", "2.5.12"],
            prefix="sulu",
        ),
    },
    "rq2_typing_holdout_v1:587": {
        "cve_id": "CVE-2024-2447",
        "ecosystem": "Go",
        "nvd_subject": "mattermost_server",
        "ghsa_subject": "github.com/mattermost/mattermost/server/v8",
        "edge_type": "product_contains_artifact",
        "authority_class": "official_repository_module_manifest",
        "sources": go_sources(
            "rq2_typing_holdout_v1:587",
            "mattermost/mattermost",
            "github.com/mattermost/mattermost/server/v8",
            ["8.1.0", "8.1.11", "9.3.0", "9.3.3", "9.4.0", "9.4.4", "9.5.0", "9.5.2"],
            prefix="mattermost_server",
            path="server/go.mod",
        ),
    },
    "rq2_typing_holdout_v1:615": {
        "cve_id": "CVE-2023-32679",
        "ecosystem": "Packagist",
        "nvd_subject": "craft_cms",
        "ghsa_subject": "craftcms/cms",
        "edge_type": "package_identity",
        "authority_class": "official_root_manifest",
        "sources": composer_sources(
            "rq2_typing_holdout_v1:615",
            "craftcms/cms",
            "craftcms/cms",
            ["4.0.0", "4.4.6"],
            prefix="craftcms",
        ),
    },
    "rq2_typing_holdout_v1:1149": {
        "cve_id": "CVE-2024-23449",
        "ecosystem": "Maven",
        "nvd_subject": "elasticsearch",
        "ghsa_subject": "org.elasticsearch:elasticsearch",
        "edge_type": "package_identity",
        "authority_class": "ecosystem_registry_pom",
        "required_project_url": "https://github.com/elastic/elasticsearch",
        "sources": maven_sources(
            "rq2_typing_holdout_v1:1149",
            "org.elasticsearch:elasticsearch",
            ["8.4.0", "8.11.1"],
            prefix="elasticsearch",
        ),
    },
    "rq2_typing_holdout_v1:1173": {
        "cve_id": "CVE-2023-22492",
        "ecosystem": "Go",
        "nvd_subject": "zitadel",
        "ghsa_subject": "github.com/zitadel/zitadel",
        "edge_type": "package_identity",
        "authority_class": "official_repository_module_manifest",
        "sources": go_sources(
            "rq2_typing_holdout_v1:1173",
            "zitadel/zitadel",
            "github.com/zitadel/zitadel",
            ["2.0.0", "2.16.4", "2.17.0", "2.17.3"],
            prefix="zitadel",
        ),
    },
}
EVIDENCE_SOURCES = tuple(
    source
    for sample_id in sorted(CASE_SPECS)
    for source in CASE_SPECS[sample_id]["sources"]
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


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return bytes_sha256(path.read_bytes())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def response_paths(cache_dir: Path, source: EvidenceSource) -> tuple[Path, Path]:
    return cache_dir / f"{source.key}.response", cache_dir / f"{source.key}.fetch.json"


def fetch_or_load(
    source: EvidenceSource,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> tuple[bytes, tuple[Path, Path]]:
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
            headers={"User-Agent": "vuln-adj-artifact-lineage-audit/1.0"},
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
    if metadata.get("http_status") != 200:
        raise ValueError(f"{source.key}: expected HTTP 200, got {metadata.get('http_status')}")
    return body, (response_path, metadata_path)


def xml_text(root: ET.Element, path: str) -> str | None:
    return root.findtext(path, namespaces={"m": "http://maven.apache.org/POM/4.0.0"})


def version_is_url_bound(source: EvidenceSource) -> bool:
    if source.version is None:
        return True
    version = re.escape(source.version)
    return bool(
        re.search(rf"/(?:v)?{version}(?:/|\+incompatible\.mod|\.mod)", source.url)
    )


def extract_evidence(source: EvidenceSource, body: bytes) -> dict:
    extracted: dict = {
        "key": source.key,
        "url": source.url,
        "parser": source.parser,
        "expected_version": source.version,
        "expected_identity": source.expected_identity,
    }
    if source.parser == "maven_pom":
        root = ET.fromstring(body)
        group = xml_text(root, "m:groupId") or xml_text(root, "m:parent/m:groupId")
        artifact = xml_text(root, "m:artifactId")
        version = xml_text(root, "m:version") or xml_text(root, "m:parent/m:version")
        extracted.update(
            identity=f"{group}:{artifact}" if group and artifact else None,
            manifest_version=version,
            project_name=xml_text(root, "m:name"),
            project_url=xml_text(root, "m:url"),
        )
        extracted["passed"] = (
            extracted["identity"] == source.expected_identity
            and version == source.version
            and version_is_url_bound(source)
        )
    elif source.parser == "composer_manifest":
        document = json.loads(body)
        extracted.update(
            identity=document.get("name"),
            project_name=document.get("description"),
            manifest_version=None,
        )
        extracted["passed"] = (
            extracted["identity"] == source.expected_identity
            and version_is_url_bound(source)
        )
    elif source.parser == "go_module":
        text = body.decode("utf-8")
        match = re.search(r"(?m)^module\s+(\S+)\s*$", text)
        extracted.update(identity=match.group(1) if match else None, manifest_version=None)
        extracted["passed"] = (
            extracted["identity"] == source.expected_identity
            and version_is_url_bound(source)
        )
    elif source.parser == "project_text":
        text = body.decode("utf-8")
        extracted["required_text_present"] = {
            phrase: phrase in text for phrase in source.required_text
        }
        extracted["passed"] = all(extracted["required_text_present"].values())
    else:
        raise ValueError(f"unsupported parser: {source.parser}")
    return extracted


def semantic_version_key(value: str) -> tuple | None:
    match = re.fullmatch(r"(\d+(?:\.\d+)*)(?:[-.]([A-Za-z]+)[.-]?(\d+)?)?", value)
    if not match:
        return None
    numeric, qualifier, qualifier_number = match.groups()
    qualifier_rank = {None: 4, "alpha": 1, "beta": 2, "milestone": 2, "rc": 3}.get(
        qualifier.lower() if qualifier else None
    )
    if qualifier_rank is None:
        return None
    return tuple(int(part) for part in numeric.split(".")) + (
        qualifier_rank,
        int(qualifier_number or 0),
    )


def boundary_versions(row: dict) -> set[str]:
    versions = set()
    for item in row["nvd_range_signature"]:
        versions.add(item["start"])
        if item["end"]:
            versions.add(item["end"])
    return versions


def projection_gate(checks: dict[str, bool], relation: str | None) -> dict:
    required = (
        "claim_subjects_bound",
        "boundary_releases_bound",
        "lineage_path_complete",
        "ordering_supported",
        "shared_release_domain_bound",
        "set_relation_computed",
    )
    failed = [name for name in required if not checks.get(name, False)]
    passed = not failed and relation == "equal"
    return {
        "status": (
            "artifact_lineage_projection_allowed_development_only"
            if passed
            else "abstain_artifact_lineage_projection_unresolved"
        ),
        "passed": passed,
        "required_checks": list(required),
        "failed_checks": failed,
        "development_typing_candidate": (
            "representation_discrepancy" if passed else "uncertain"
        ),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def analyze_case(row: dict, bodies: dict[str, bytes]) -> dict:
    spec = CASE_SPECS[row["sample_id"]]
    extracted = [extract_evidence(source, bodies[source.key]) for source in spec["sources"]]
    release_evidence = [item for item in extracted if item["expected_version"] is not None]
    evidence_versions = {item["expected_version"] for item in release_evidence}
    boundaries = boundary_versions(row)
    all_evidence_passed = all(item["passed"] for item in extracted)
    subject_match = (
        row["cve_id"] == spec["cve_id"]
        and row["nvd_subject"] == spec["nvd_subject"]
        and row["ghsa_subject"] == spec["ghsa_subject"]
        and spec["edge_type"] in ALLOWED_EDGE_TYPES
    )
    project_anchor = True
    if spec.get("required_project_text"):
        project_anchor = all(
            spec["required_project_text"] in str(item.get("project_name") or "")
            for item in release_evidence
        )
    if spec.get("required_project_url"):
        project_anchor = project_anchor and all(
            item.get("project_url") == spec["required_project_url"]
            for item in release_evidence
        )
    checks = {
        "claim_subjects_bound": subject_match and all_evidence_passed and project_anchor,
        "boundary_releases_bound": (
            evidence_versions == boundaries and all(item["passed"] for item in release_evidence)
        ),
        "lineage_path_complete": subject_match and all_evidence_passed,
        "ordering_supported": all(semantic_version_key(value) for value in boundaries),
        "shared_release_domain_bound": (
            row["nvd_range_signature"] == row["ghsa_range_signature"]
            and subject_match
            and all_evidence_passed
        ),
        "set_relation_computed": row["nvd_range_signature"] == row["ghsa_range_signature"],
    }
    relation = "equal" if checks["set_relation_computed"] else None
    gate = projection_gate(checks, relation)
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "ecosystem": spec["ecosystem"],
        "source_subjects": {"nvd": row["nvd_subject"], "ghsa": row["ghsa_subject"]},
        "identity_edge": {
            "from": row["nvd_subject"],
            "to": row["ghsa_subject"],
            "edge_type": spec["edge_type"],
            "authority_class": spec["authority_class"],
            "scope": "listed_boundary_releases",
            "bound": checks["claim_subjects_bound"],
        },
        "boundary_versions": sorted(boundaries, key=semantic_version_key),
        "evidence": extracted,
        "release_set_relation": relation,
        "checks": checks,
        "gate": gate,
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
    }


def reviewer_labels(path: Path) -> dict[str, str]:
    return {
        row["sample_id"]: row["annotation"]["discrepancy_label"]
        for row in load_jsonl(path)
    }


def build_summary(cases: list[dict], reviewer_a: dict, reviewer_b: dict) -> dict:
    passed = [case for case in cases if case["gate"]["passed"]]
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
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "artifact_lineage_cross_case_analysis",
        "row_count": len(cases),
        "projection_gate_passed": len(passed),
        "projection_coverage": len(passed) / len(cases) if cases else 0.0,
        "ecosystems": sorted({case["ecosystem"] for case in cases}),
        "identity_edge_types": sorted({case["identity_edge"]["edge_type"] for case in cases}),
        "development_candidate_counts": {
            label: sum(
                case["gate"]["development_typing_candidate"] == label for case in cases
            )
            for label in sorted(
                {case["gate"]["development_typing_candidate"] for case in cases}
            )
        },
        "non_human_consistency_only": {
            "rows_matching_both_sealed_ai_reviewers": sum(
                item["matches_both"] for item in consistency
            ),
            "row_count": len(consistency),
            "cases": consistency,
            "accuracy_claim_allowed": False,
            "human_gold_claim_allowed": False,
        },
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
    lines = [
        "# Cross-Case Artifact-Lineage Audit v1",
        "",
        "> Post-unsealing, non-human development diagnostic; not an accuracy result.",
        "",
        f"- Rows: `{analysis['row_count']}`",
        f"- Projection gate passed: `{analysis['projection_gate_passed']}/{analysis['row_count']}`",
        f"- Ecosystems: `{', '.join(analysis['ecosystems'])}`",
        "- Candidate labels: `" + json.dumps(analysis["development_candidate_counts"], sort_keys=True) + "`",
        "- Agreement with both sealed AI reviewers: "
        f"`{analysis['non_human_consistency_only']['rows_matching_both_sealed_ai_reviewers']}/{analysis['row_count']}`",
        "",
        "| Sample | Ecosystem | Edge | Gate | Candidate |",
        "|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        lines.append(
            f"| {case['sample_id']} | {case['ecosystem']} | "
            f"{case['identity_edge']['edge_type']} | {case['gate']['status']} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend(
        [
            "",
            "The eight rows were selected from raw cross-artifact identity and equal-range signatures without reading reviewer labels. The upstream calibration remains non-human-label-conditioned, so this is coverage and construct-consistency evidence only.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.timeout_seconds < 1:
        raise ValueError("--timeout-seconds must be positive")
    cohort_dir = resolve(args.cohort_dir)
    cohort_path = cohort_dir / "cohort.jsonl"
    cohort_manifest_path = cohort_dir / "manifest.sealed.json"
    contract_path = resolve(args.contract)
    reviewer_a_path = resolve(args.reviewer_a)
    reviewer_b_path = resolve(args.reviewer_b)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite cross-case audit: {output_dir}")
    cohort_manifest = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort_manifest["output"]["sha256"] != file_sha256(cohort_path):
        raise ValueError("cohort seal mismatch")
    cohort = load_jsonl(cohort_path)
    if {row["sample_id"] for row in cohort} != set(CASE_SPECS):
        raise ValueError("cohort and evidence specification sample IDs differ")

    cache_dir.mkdir(parents=True, exist_ok=True)
    bodies = {}
    cache_paths = []
    for source in EVIDENCE_SOURCES:
        body, paths = fetch_or_load(
            source,
            cache_dir,
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        bodies[source.key] = body
        cache_paths.extend(paths)
    cases = [analyze_case(row, bodies) for row in cohort]
    analysis = build_summary(
        cases,
        reviewer_labels(reviewer_a_path),
        reviewer_labels(reviewer_b_path),
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
        "artifact_type": "artifact_lineage_cross_case_manifest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": file_sha256(cohort_path)},
            "cohort_manifest": {
                "path": str(cohort_manifest_path),
                "sha256": file_sha256(cohort_manifest_path),
            },
            "contract": {"path": str(contract_path), "sha256": file_sha256(contract_path)},
            "reviewer_a_diagnostic_only": {
                "path": str(reviewer_a_path),
                "sha256": file_sha256(reviewer_a_path),
            },
            "reviewer_b_diagnostic_only": {
                "path": str(reviewer_b_path),
                "sha256": file_sha256(reviewer_b_path),
            },
            "code": {"path": str(Path(__file__).resolve()), "sha256": file_sha256(Path(__file__).resolve())},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": file_sha256(path)}
            for path in sorted(cache_paths)
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": file_sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": file_sha256(markdown_path)},
        },
        "summary": {
            "row_count": analysis["row_count"],
            "projection_gate_passed": analysis["projection_gate_passed"],
            "projection_coverage": analysis["projection_coverage"],
        },
        "boundary": analysis["boundary"],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {analysis_path}")
    print(f"Projection coverage: {analysis['projection_gate_passed']}/{analysis['row_count']}")
    print("Boundary: post-unsealing non-human development diagnostic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
