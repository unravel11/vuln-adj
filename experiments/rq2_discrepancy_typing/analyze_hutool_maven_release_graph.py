#!/usr/bin/env python3
"""Evaluate the frozen Hutool product/component Maven release graph."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "hutool_maven_release_graph_v1"
DEFAULT_WORKLIST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "blind/worklist_d.blind.jsonl"
)
DEFAULT_SEALED_MANIFEST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "manifest.sealed.json"
)
DEFAULT_EDGE_AUDIT = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "affected_versions_edge_class_audit_v1/analysis.json"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "affected_versions_hutool_maven_release_graph_contract_v1.md"
)
DEFAULT_CACHE_DIR = "data/evidence_cache/rq2/hutool_maven_release_graph_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "hutool_maven_release_graph_v1"
)
MAVEN_ROOT = "https://repo.maven.apache.org/maven2/cn/hutool"
SOURCE_ROOT = "https://raw.githubusercontent.com/dromara/hutool"
COORDINATES = (
    "cn.hutool:hutool-all",
    "cn.hutool:hutool-core",
    "cn.hutool:hutool-json",
)
COMPONENTS = ("cn.hutool:hutool-core", "cn.hutool:hutool-json")
ANCHOR_VERSIONS = ("5.8.19", "5.8.21", "5.8.22")
EXCLUDED_MILESTONES = (
    "5.8.0.M1",
    "5.8.0.M2",
    "5.8.0.M3",
    "5.8.0.M4",
    "5.8.4.M1",
)
STABLE_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
MAX_RESPONSE_BYTES = 20_000_000
XML_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = STABLE_VERSION.fullmatch(raw)
        if match is None:
            raise ValueError(f"unsupported stable Hutool version: {raw}")
        return cls(*(int(value) for value in match.groups()))


def span(start: str | None, end: str | None, *, end_inclusive: bool = False) -> tuple:
    return ("range", start, start is not None, end, end_inclusive)


CASE_SPECS = {
    "CVE-2023-3276": {
        "sample_id": "rq2_typing_holdout_v1:328",
        "nvd_subject": "hutool",
        "nvd_spans": (span(None, "5.8.19", end_inclusive=True),),
        "ghsa_components": ("cn.hutool:hutool-core",),
    },
    "CVE-2023-42276": {
        "sample_id": "rq2_typing_holdout_v1:1164",
        "nvd_subject": "hutool",
        "nvd_spans": (("singleton", "5.8.21", True, "5.8.21", True),),
        "ghsa_components": COMPONENTS,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--sealed-manifest", default=DEFAULT_SEALED_MANIFEST)
    parser.add_argument("--edge-audit", default=DEFAULT_EDGE_AUDIT)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def row_span(item: dict) -> tuple:
    version = item.get("version")
    if version not in {None, "*", "-"}:
        return ("singleton", version, True, version, True)
    start = item.get("version_start_excluding")
    start_inclusive = False
    if start is None:
        start = item.get("version_start_including")
        start_inclusive = start not in {None, "0"}
    if start in {None, "0"}:
        start = None
        start_inclusive = False
    end = item.get("version_end_excluding")
    end_inclusive = False
    if end is None:
        end = item.get("version_end_including")
        end_inclusive = end is not None
    return ("range", start, start_inclusive, end, end_inclusive)


def claim_signature(items: list[dict]) -> dict[str, list[tuple]]:
    grouped: dict[str, list[tuple]] = {}
    for item in items:
        subject = str(item.get("package_name") or item.get("product"))
        grouped.setdefault(subject, []).append(row_span(item))
    return {key: sorted(value, key=str) for key, value in sorted(grouped.items())}


def expected_claims(cve_id: str) -> tuple[dict, dict]:
    spec = CASE_SPECS[cve_id]
    return (
        {spec["nvd_subject"]: list(spec["nvd_spans"])},
        {component: [span(None, None)] for component in spec["ghsa_components"]},
    )


def load_fixed_rows(worklist: Path, sealed_manifest: Path, edge_audit: Path) -> list[dict]:
    sealed = json.loads(sealed_manifest.read_text(encoding="utf-8"))
    if file_sha256(worklist) != sealed["outputs"]["blind_worklist_d"]["sha256"]:
        raise ValueError("sealed worklist hash mismatch")
    audit = json.loads(edge_audit.read_text(encoding="utf-8"))
    family = next(
        (item for item in audit["family_ranking"] if item["project_family"] == "hutool"),
        None,
    )
    if family is None or family.get("eligible_rank") != 3 or family.get("score") != 8:
        raise ValueError("parent edge audit Hutool ranking drift")
    expected_ids = {spec["sample_id"] for spec in CASE_SPECS.values()}
    rows = [row for row in load_jsonl(worklist) if row.get("sample_id") in expected_ids]
    if len(rows) != 2:
        raise ValueError(f"expected two Hutool rows, found {len(rows)}")
    for row in rows:
        spec = CASE_SPECS.get(row.get("cve_id"))
        if spec is None or row.get("sample_id") != spec["sample_id"]:
            raise ValueError(f"unexpected Hutool row: {row.get('sample_id')}")
        if row.get("field") != "affected_versions":
            raise ValueError(f"field drift for {row['cve_id']}")
        expected_nvd, expected_ghsa = expected_claims(row["cve_id"])
        if claim_signature(row["nvd_value"]) != expected_nvd:
            raise ValueError(f"NVD claim drift for {row['cve_id']}")
        if claim_signature(row["ghsa_value"]) != expected_ghsa:
            raise ValueError(f"GHSA claim drift for {row['cve_id']}")
    return sorted(rows, key=lambda row: row["cve_id"])


def request_headers() -> dict[str, str]:
    headers = {"User-Agent": "vuln-adj-hutool-maven-release-graph-v1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_or_load(
    cache_dir: Path,
    key: str,
    url: str,
    *,
    timeout_seconds: int,
    refresh: bool,
) -> bytes:
    body_path = cache_dir / f"{key}.response"
    metadata_path = cache_dir / f"{key}.fetch.json"
    if body_path.exists() and metadata_path.exists() and not refresh:
        body = body_path.read_bytes()
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != url or metadata.get("response_sha256") != sha256_bytes(body):
            raise ValueError(f"cached source binding mismatch for {key}")
        if metadata.get("http_status") != 200:
            raise ValueError(f"cached source status drift for {key}")
        return body
    request = Request(url, headers=request_headers())
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout_seconds) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
                content_type = response.headers.get("Content-Type")
            break
        except HTTPError as exc:
            body = exc.read(MAX_RESPONSE_BYTES + 1)
            status = exc.code
            content_type = exc.headers.get("Content-Type") if exc.headers else None
            break
        except (TimeoutError, URLError) as exc:
            last_error = exc
            if attempt == 2:
                raise RuntimeError(f"failed to fetch {url}: {exc}") from exc
            time.sleep(2**attempt)
    else:  # pragma: no cover
        raise RuntimeError(f"failed to fetch {url}: {last_error}")
    if status != 200:
        raise RuntimeError(f"required source {key} returned HTTP {status}")
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"required source {key} exceeds byte limit")
    body_path.write_bytes(body)
    write_json(metadata_path, {
        "schema_version": SCHEMA_VERSION,
        "url": url,
        "http_status": status,
        "content_type": content_type,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "response_sha256": sha256_bytes(body),
        "response_bytes": len(body),
    })
    return body


def metadata_url(coordinate: str) -> str:
    artifact = coordinate.split(":", 1)[1]
    return f"{MAVEN_ROOT}/{artifact}/maven-metadata.xml"


def source_pom_url(version: str) -> str:
    return f"{SOURCE_ROOT}/{version}/hutool-all/pom.xml"


def aggregate_jar_url(version: str) -> str:
    return f"{MAVEN_ROOT}/hutool-all/{version}/hutool-all-{version}.jar"


def parse_catalog(body: bytes, expected_coordinate: str) -> dict:
    root = ET.fromstring(body)
    group, artifact = expected_coordinate.split(":", 1)
    versions = [element.text for element in root.findall("./versioning/versions/version")]
    if any(value is None for value in versions) or len(set(versions)) != len(versions):
        raise ValueError(f"invalid version inventory for {expected_coordinate}")
    stable = sorted((value for value in versions if STABLE_VERSION.fullmatch(value)), key=Version.parse)
    excluded = sorted(value for value in versions if not STABLE_VERSION.fullmatch(value))
    return {
        "coordinate": expected_coordinate,
        "observed_group_id": root.findtext("./groupId"),
        "observed_artifact_id": root.findtext("./artifactId"),
        "identity_bound": (
            root.findtext("./groupId") == group
            and root.findtext("./artifactId") == artifact
        ),
        "version_count": len(versions),
        "stable_version_count": len(stable),
        "stable_versions": stable,
        "excluded_versions": excluded,
        "last_updated": root.findtext("./versioning/lastUpdated"),
    }


def xml_text(root: ET.Element, path: str) -> str | None:
    return root.findtext(path, namespaces=XML_NS)


def parse_source_pom(body: bytes, expected_version: str) -> dict:
    root = ET.fromstring(body)
    parent = ":".join(filter(None, (
        xml_text(root, "m:parent/m:groupId"),
        xml_text(root, "m:parent/m:artifactId"),
    )))
    parent_version = xml_text(root, "m:parent/m:version")
    dependencies = {}
    for dependency in root.findall("./m:dependencies/m:dependency", XML_NS):
        coordinate = ":".join(filter(None, (
            xml_text(dependency, "m:groupId"),
            xml_text(dependency, "m:artifactId"),
        )))
        raw_version = xml_text(dependency, "m:version")
        resolved_version = expected_version if raw_version == "${project.parent.version}" else raw_version
        dependencies[coordinate] = {
            "raw_version": raw_version,
            "resolved_version": resolved_version,
        }
    shade_plugins = [
        plugin for plugin in root.findall("./m:build/m:plugins/m:plugin", XML_NS)
        if xml_text(plugin, "m:artifactId") == "maven-shade-plugin"
    ]
    shade_goal = any(
        xml_text(goal, ".") == "shade"
        for plugin in shade_plugins
        for goal in plugin.findall("./m:executions/m:execution/m:goals/m:goal", XML_NS)
    )
    required_dependencies_bound = all(
        dependencies.get(coordinate, {}).get("resolved_version") == expected_version
        for coordinate in COMPONENTS
    )
    checks = {
        "parent_identity_bound": parent == "cn.hutool:hutool-parent",
        "parent_version_bound": parent_version == expected_version,
        "aggregate_artifact_bound": xml_text(root, "m:artifactId") == "hutool-all",
        "jar_packaging_bound": xml_text(root, "m:packaging") == "jar",
        "required_dependencies_bound": required_dependencies_bound,
        "shade_goal_bound": shade_goal,
    }
    return {
        "expected_version": expected_version,
        "parent_identity": parent,
        "parent_version": parent_version,
        "artifact_id": xml_text(root, "m:artifactId"),
        "packaging": xml_text(root, "m:packaging"),
        "required_dependencies": {
            coordinate: dependencies.get(coordinate) for coordinate in COMPONENTS
        },
        "checks": checks,
        "bound": all(checks.values()),
    }


def parse_aggregate_jar(body: bytes, expected_version: str) -> dict:
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = archive.namelist()
    core_count = sum(
        name.startswith("cn/hutool/core/") and name.endswith(".class") for name in names
    )
    json_count = sum(
        name.startswith("cn/hutool/json/") and name.endswith(".class") for name in names
    )
    checks = {
        "core_classes_present": core_count > 0,
        "json_classes_present": json_count > 0,
    }
    return {
        "expected_version": expected_version,
        "entry_count": len(names),
        "core_class_count": core_count,
        "json_class_count": json_count,
        "checks": checks,
        "bound": all(checks.values()),
    }


def version_in_span(version: str, claim_span: tuple) -> bool:
    parsed = Version.parse(version)
    kind, start, start_inclusive, end, end_inclusive = claim_span
    if kind == "singleton":
        return version == start == end
    lower = Version.parse(start) if start else None
    upper = Version.parse(end) if end else None
    if lower is not None and (parsed < lower or (parsed == lower and not start_inclusive)):
        return False
    if upper is not None and (parsed > upper or (parsed == upper and not end_inclusive)):
        return False
    return True


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


def candidate_for_relation(relation: str) -> str:
    if relation == "equal":
        return "representation_discrepancy"
    if relation in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def analyze(
    rows: list[dict],
    catalogs: dict[str, dict],
    pom_anchors: dict[str, dict],
    jar_anchors: dict[str, dict],
) -> dict:
    stable_sets = {key: set(value["stable_versions"]) for key, value in catalogs.items()}
    release_domain = set.intersection(*stable_sets.values())
    catalogs_equal = len({frozenset(value) for value in stable_sets.values()}) == 1
    excluded_equal = all(
        value["excluded_versions"] == list(EXCLUDED_MILESTONES)
        for value in catalogs.values()
    )
    catalog_identities_bound = all(value["identity_bound"] for value in catalogs.values())
    anchors_in_domain = set(ANCHOR_VERSIONS) <= release_domain
    poms_bound = all(value["bound"] for value in pom_anchors.values())
    jars_bound = all(value["bound"] for value in jar_anchors.values())
    ordered_domain = sorted(release_domain, key=Version.parse)
    cases = []
    for row in rows:
        spec = CASE_SPECS[row["cve_id"]]
        checks = {
            "fixed_input_signature": True,
            "maven_catalog_identities_bound": catalog_identities_bound,
            "stable_catalog_release_correspondence_total": catalogs_equal and bool(release_domain),
            "milestone_exclusion_exact": excluded_equal,
            "critical_anchor_versions_bound": anchors_in_domain,
            "aggregate_source_pom_anchors_bound": poms_bound,
            "aggregate_binary_component_anchors_bound": jars_bound,
        }
        passed = all(checks.values())
        relation = None
        candidate = "uncertain"
        release_sets = None
        if passed:
            nvd = {
                version for version in release_domain
                if any(version_in_span(version, item) for item in spec["nvd_spans"])
            }
            component_sets = {
                coordinate: set(catalogs[coordinate]["stable_versions"])
                for coordinate in spec["ghsa_components"]
            }
            ghsa = set().union(*component_sets.values()) & release_domain
            relation = set_relation(nvd, ghsa)
            candidate = candidate_for_relation(relation)
            release_sets = {
                "nvd_product_versions": sorted(nvd, key=Version.parse),
                "ghsa_component_union_versions": sorted(ghsa, key=Version.parse),
                "nvd_count": len(nvd),
                "ghsa_union_count": len(ghsa),
                "nvd_only": sorted(nvd - ghsa, key=Version.parse),
                "ghsa_only": sorted(ghsa - nvd, key=Version.parse),
            }
        cases.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "ghsa_components": list(spec["ghsa_components"]),
            "checks": checks,
            "gate": {
                "passed": passed,
                "status": (
                    "hutool_snapshot_extensional_projection_allowed_mechanism_only"
                    if passed else "abstain_hutool_maven_projection_unresolved"
                ),
                "failed_checks": [name for name, value in checks.items() if not value],
                "development_typing_candidate": candidate,
                "promoted_candidate": None,
                "candidate_promotion_allowed": False,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            },
            "release_sets": release_sets,
            "release_set_relation": relation,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })
    passed_rows = sum(case["gate"]["passed"] for case in cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "hutool_maven_release_graph_analysis",
        "catalogs": catalogs,
        "release_domain": {
            "scope": "stable_numeric_intersection_of_frozen_maven_catalogs",
            "versions": ordered_domain,
            "version_count": len(ordered_domain),
            "first_version": ordered_domain[0] if ordered_domain else None,
            "last_version": ordered_domain[-1] if ordered_domain else None,
            "excluded_milestones": list(EXCLUDED_MILESTONES),
            "catalogs_equal": catalogs_equal,
        },
        "aggregate_anchor_evidence": {
            version: {"source_pom": pom_anchors[version], "aggregate_jar": jar_anchors[version]}
            for version in ANCHOR_VERSIONS
        },
        "cases": cases,
        "summary": {
            "row_count": len(cases),
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / len(cases),
            "development_candidate_counts": {
                label: sum(case["gate"]["development_typing_candidate"] == label for case in cases)
                for label in sorted({case["gate"]["development_typing_candidate"] for case in cases})
            },
            "promoted_candidate_count": 0,
            "combined_candidate_numerator_before": 1219,
            "combined_candidate_numerator_after": 1219,
            "combined_candidate_denominator": 1250,
        },
        "advancement_gate": {
            "minimum_projectable_rows": 2,
            "projectable_rows": passed_rows,
            "passed": passed_rows == 2,
            "status": (
                "mechanism_pass_requires_new_blind_cohort"
                if passed_rows == 2 else "no_go_hutool_maven_release_graph_unstable"
            ),
            "candidate_promotion_allowed": False,
            "independent_verification_required": True,
        },
        "boundary": {
            "post_unsealing": True,
            "protocol_discovery_disclosed": True,
            "selection_uses_reviewer_labels": False,
            "development_diagnostic_only": True,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    lines = [
        "# Hutool Maven Release Graph v1",
        "",
        "> Post-unsealing mechanism diagnostic with disclosed protocol discovery; not human gold.",
        "",
        f"- Stable Maven release domain: `{analysis['release_domain']['version_count']}`",
        f"- Excluded milestones: `{len(analysis['release_domain']['excluded_milestones'])}`",
        f"- Projection gate passed: `{analysis['summary']['projection_gate_passed']}/2`",
        f"- Family status: `{analysis['advancement_gate']['status']}`",
        "- Candidate promotion: `disabled`",
        "- Combined non-human candidate: `1,219/1,250 = 0.9752` (unchanged)",
        "",
        "| CVE | Gate | NVD count | GHSA union count | Relation | Codex development candidate |",
        "|---|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        sets = case["release_sets"] or {}
        lines.append(
            f"| {case['cve_id']} | {str(case['gate']['passed']).lower()} | "
            f"{sets.get('nvd_count', 'not computed')} | "
            f"{sets.get('ghsa_union_count', 'not computed')} | "
            f"{case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "",
        "The catalog relation is snapshot-extensional. Critical POM/JAR anchors bind the",
        "aggregate/component interpretation, but this run does not inspect every historical",
        "aggregate JAR and cannot establish an advisory's human-approved temporal semantics.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist = resolve(args.worklist)
    sealed_manifest = resolve(args.sealed_manifest)
    edge_audit = resolve(args.edge_audit)
    contract = resolve(args.contract)
    cache_dir = resolve(args.cache_dir)
    output_dir = resolve(args.output_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_fixed_rows(worklist, sealed_manifest, edge_audit)

    catalogs = {}
    for coordinate in COORDINATES:
        artifact = coordinate.split(":", 1)[1]
        body = fetch_or_load(
            cache_dir,
            f"{artifact.replace('-', '_')}_metadata",
            metadata_url(coordinate),
            timeout_seconds=args.timeout_seconds,
            refresh=args.refresh,
        )
        catalogs[coordinate] = parse_catalog(body, coordinate)

    pom_anchors = {}
    jar_anchors = {}
    for version in ANCHOR_VERSIONS:
        key_version = version.replace(".", "_")
        pom_anchors[version] = parse_source_pom(
            fetch_or_load(
                cache_dir,
                f"hutool_all_{key_version}_source_pom",
                source_pom_url(version),
                timeout_seconds=args.timeout_seconds,
                refresh=args.refresh,
            ),
            version,
        )
        jar_anchors[version] = parse_aggregate_jar(
            fetch_or_load(
                cache_dir,
                f"hutool_all_{key_version}_jar",
                aggregate_jar_url(version),
                timeout_seconds=args.timeout_seconds,
                refresh=args.refresh,
            ),
            version,
        )

    analysis = analyze(rows, catalogs, pom_anchors, jar_anchors)
    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    write_json(analysis_path, analysis)
    summary_path.write_text(render_markdown(analysis), encoding="utf-8")
    cache_files = sorted(path for path in cache_dir.iterdir() if path.is_file())
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "worklist": {"path": str(worklist), "sha256": file_sha256(worklist)},
            "sealed_manifest": {
                "path": str(sealed_manifest), "sha256": file_sha256(sealed_manifest)
            },
            "edge_audit": {"path": str(edge_audit), "sha256": file_sha256(edge_audit)},
            "contract": {"path": str(contract), "sha256": file_sha256(contract)},
            "code": {"path": str(Path(__file__).resolve()), "sha256": file_sha256(Path(__file__).resolve())},
        },
        "evidence_cache": {
            path.name: {"path": str(path), "sha256": file_sha256(path)} for path in cache_files
        },
        "outputs": {
            analysis_path.name: {"path": str(analysis_path), "sha256": file_sha256(analysis_path)},
            summary_path.name: {"path": str(summary_path), "sha256": file_sha256(summary_path)},
        },
        "summary": analysis["summary"],
        "advancement_gate": analysis["advancement_gate"],
        "boundary": analysis["boundary"],
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }
    write_json(output_dir / "manifest.json", manifest)
    print(json.dumps({
        "release_count": analysis["release_domain"]["version_count"],
        "projection_gate_passed": analysis["summary"]["projection_gate_passed"],
        "development_candidate_counts": analysis["summary"]["development_candidate_counts"],
        "status": analysis["advancement_gate"]["status"],
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
