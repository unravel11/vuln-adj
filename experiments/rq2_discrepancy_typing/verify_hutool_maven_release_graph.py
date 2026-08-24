#!/usr/bin/env python3
"""Independently verify the cached Hutool Maven release graph."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_PROJECT_ROOT = Path("/home/xiaoyuliang/code/vuln-adj")
SCHEMA_VERSION = "hutool_maven_release_graph_v1"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "hutool_maven_release_graph_v1/manifest.json"
)
MAVEN_ROOT = "https://repo.maven.apache.org/maven2/cn/hutool"
SOURCE_ROOT = "https://raw.githubusercontent.com/dromara/hutool"
COORDINATES = (
    "cn.hutool:hutool-all",
    "cn.hutool:hutool-core",
    "cn.hutool:hutool-json",
)
COMPONENTS = ("cn.hutool:hutool-core", "cn.hutool:hutool-json")
ANCHORS = ("5.8.19", "5.8.21", "5.8.22")
EXCLUDED = ("5.8.0.M1", "5.8.0.M2", "5.8.0.M3", "5.8.0.M4", "5.8.4.M1")
STABLE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
XML_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> "Version":
        match = STABLE.fullmatch(raw)
        if match is None:
            raise ValueError(f"unsupported stable Hutool version: {raw}")
        return cls(*(int(value) for value in match.groups()))


def span(start: str | None, end: str | None, *, end_inclusive: bool = False) -> tuple:
    return ("range", start, start is not None, end, end_inclusive)


SPECS = {
    "CVE-2023-3276": {
        "sample_id": "rq2_typing_holdout_v1:328",
        "nvd": {"hutool": [span(None, "5.8.19", end_inclusive=True)]},
        "components": ("cn.hutool:hutool-core",),
    },
    "CVE-2023-42276": {
        "sample_id": "rq2_typing_holdout_v1:1164",
        "nvd": {"hutool": [("singleton", "5.8.21", True, "5.8.21", True)]},
        "components": COMPONENTS,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        return (PROJECT_ROOT / path).resolve()
    if path.exists():
        return path
    try:
        relative = path.relative_to(AUTHORITATIVE_PROJECT_ROOT)
    except ValueError:
        return path
    return (PROJECT_ROOT / relative).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file():
        raise ValueError(f"{name} is missing: {path}")
    if file_sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} hash mismatch")
    return path


def metadata_url(coordinate: str) -> str:
    artifact = coordinate.split(":", 1)[1]
    return f"{MAVEN_ROOT}/{artifact}/maven-metadata.xml"


def source_url(version: str) -> str:
    return f"{SOURCE_ROOT}/{version}/hutool-all/pom.xml"


def jar_url(version: str) -> str:
    return f"{MAVEN_ROOT}/hutool-all/{version}/hutool-all-{version}.jar"


def cache_body(cache: dict[str, Path], key: str, expected_url: str) -> bytes:
    body = cache[f"{key}.response"].read_bytes()
    metadata = json.loads(cache[f"{key}.fetch.json"].read_text(encoding="utf-8"))
    if metadata.get("url") != expected_url or metadata.get("http_status") != 200:
        raise ValueError(f"cache provenance mismatch for {key}")
    if metadata.get("response_sha256") != hashlib.sha256(body).hexdigest():
        raise ValueError(f"cache body hash mismatch for {key}")
    if metadata.get("response_bytes") != len(body):
        raise ValueError(f"cache byte count mismatch for {key}")
    return body


def parse_catalog(body: bytes, coordinate: str) -> dict:
    root = ET.fromstring(body)
    group, artifact = coordinate.split(":", 1)
    versions = [element.text for element in root.findall("./versioning/versions/version")]
    if any(value is None for value in versions) or len(set(versions)) != len(versions):
        raise ValueError(f"invalid catalog inventory for {coordinate}")
    stable = sorted((value for value in versions if STABLE.fullmatch(value)), key=Version.parse)
    return {
        "coordinate": coordinate,
        "observed_group_id": root.findtext("./groupId"),
        "observed_artifact_id": root.findtext("./artifactId"),
        "identity_bound": root.findtext("./groupId") == group and root.findtext("./artifactId") == artifact,
        "version_count": len(versions),
        "stable_version_count": len(stable),
        "stable_versions": stable,
        "excluded_versions": sorted(value for value in versions if not STABLE.fullmatch(value)),
        "last_updated": root.findtext("./versioning/lastUpdated"),
    }


def xml_text(root: ET.Element, path: str) -> str | None:
    return root.findtext(path, namespaces=XML_NS)


def parse_pom(body: bytes, version: str) -> dict:
    root = ET.fromstring(body)
    parent = ":".join(filter(None, (
        xml_text(root, "m:parent/m:groupId"), xml_text(root, "m:parent/m:artifactId")
    )))
    parent_version = xml_text(root, "m:parent/m:version")
    dependencies = {}
    for dependency in root.findall("./m:dependencies/m:dependency", XML_NS):
        coordinate = ":".join(filter(None, (
            xml_text(dependency, "m:groupId"), xml_text(dependency, "m:artifactId")
        )))
        raw = xml_text(dependency, "m:version")
        dependencies[coordinate] = {
            "raw_version": raw,
            "resolved_version": version if raw == "${project.parent.version}" else raw,
        }
    shade = False
    for plugin in root.findall("./m:build/m:plugins/m:plugin", XML_NS):
        if xml_text(plugin, "m:artifactId") != "maven-shade-plugin":
            continue
        shade = any(
            xml_text(goal, ".") == "shade"
            for goal in plugin.findall("./m:executions/m:execution/m:goals/m:goal", XML_NS)
        )
    checks = {
        "parent_identity_bound": parent == "cn.hutool:hutool-parent",
        "parent_version_bound": parent_version == version,
        "aggregate_artifact_bound": xml_text(root, "m:artifactId") == "hutool-all",
        "jar_packaging_bound": xml_text(root, "m:packaging") == "jar",
        "required_dependencies_bound": all(
            dependencies.get(component, {}).get("resolved_version") == version
            for component in COMPONENTS
        ),
        "shade_goal_bound": shade,
    }
    return {
        "expected_version": version,
        "parent_identity": parent,
        "parent_version": parent_version,
        "artifact_id": xml_text(root, "m:artifactId"),
        "packaging": xml_text(root, "m:packaging"),
        "required_dependencies": {
            component: dependencies.get(component) for component in COMPONENTS
        },
        "checks": checks,
        "bound": all(checks.values()),
    }


def parse_jar(body: bytes, version: str) -> dict:
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = archive.namelist()
    core = sum(name.startswith("cn/hutool/core/") and name.endswith(".class") for name in names)
    json_classes = sum(name.startswith("cn/hutool/json/") and name.endswith(".class") for name in names)
    checks = {"core_classes_present": core > 0, "json_classes_present": json_classes > 0}
    return {
        "expected_version": version,
        "entry_count": len(names),
        "core_class_count": core,
        "json_class_count": json_classes,
        "checks": checks,
        "bound": all(checks.values()),
    }


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


def signature(items: list[dict]) -> dict[str, list[tuple]]:
    result: dict[str, list[tuple]] = {}
    for item in items:
        subject = str(item.get("package_name") or item.get("product"))
        result.setdefault(subject, []).append(row_span(item))
    return {key: sorted(value, key=str) for key, value in sorted(result.items())}


def version_in_span(version: str, claim: tuple) -> bool:
    parsed = Version.parse(version)
    kind, start, start_inclusive, end, end_inclusive = claim
    if kind == "singleton":
        return version == start == end
    lower = Version.parse(start) if start else None
    upper = Version.parse(end) if end else None
    if lower is not None and (parsed < lower or (parsed == lower and not start_inclusive)):
        return False
    if upper is not None and (parsed > upper or (parsed == upper and not end_inclusive)):
        return False
    return True


def relation(nvd: set[str], ghsa: set[str]) -> str:
    if nvd == ghsa:
        return "equal"
    if nvd < ghsa:
        return "nvd_subset_of_ghsa"
    if ghsa < nvd:
        return "ghsa_subset_of_nvd"
    return "overlap" if nvd & ghsa else "disjoint"


def candidate(value: str) -> str:
    if value == "equal":
        return "representation_discrepancy"
    if value in {"nvd_subset_of_ghsa", "ghsa_subset_of_nvd"}:
        return "incomplete"
    return "factual_conflict"


def render_markdown(analysis: dict) -> str:
    lines = [
        "# Hutool Maven Release Graph v1", "",
        "> Post-unsealing mechanism diagnostic with disclosed protocol discovery; not human gold.", "",
        f"- Stable Maven release domain: `{analysis['release_domain']['version_count']}`",
        f"- Excluded milestones: `{len(analysis['release_domain']['excluded_milestones'])}`",
        f"- Projection gate passed: `{analysis['summary']['projection_gate_passed']}/2`",
        f"- Family status: `{analysis['advancement_gate']['status']}`",
        "- Candidate promotion: `disabled`",
        "- Combined non-human candidate: `1,219/1,250 = 0.9752` (unchanged)", "",
        "| CVE | Gate | NVD count | GHSA union count | Relation | Codex development candidate |",
        "|---|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        sets = case["release_sets"] or {}
        lines.append(
            f"| {case['cve_id']} | {str(case['gate']['passed']).lower()} | "
            f"{sets.get('nvd_count', 'not computed')} | {sets.get('ghsa_union_count', 'not computed')} | "
            f"{case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "", "The catalog relation is snapshot-extensional. Critical POM/JAR anchors bind the",
        "aggregate/component interpretation, but this run does not inspect every historical",
        "aggregate JAR and cannot establish an advisory's human-approved temporal semantics.", "",
    ])
    return "\n".join(lines)


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected manifest schema")
    inputs = {
        name: verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    outputs = {
        name: verified_record(record, f"output:{name}")
        for name, record in manifest["outputs"].items()
    }
    cache = {
        name: verified_record(record, f"cache:{name}")
        for name, record in manifest["evidence_cache"].items()
    }
    expected_cache = set()
    for coordinate in COORDINATES:
        artifact = coordinate.split(":", 1)[1].replace("-", "_")
        expected_cache.update({f"{artifact}_metadata.response", f"{artifact}_metadata.fetch.json"})
    for version in ANCHORS:
        token = version.replace(".", "_")
        expected_cache.update({
            f"hutool_all_{token}_source_pom.response",
            f"hutool_all_{token}_source_pom.fetch.json",
            f"hutool_all_{token}_jar.response",
            f"hutool_all_{token}_jar.fetch.json",
        })
    if set(cache) != expected_cache:
        raise ValueError("evidence cache inventory differs from fixed v1 contract")

    sealed = json.loads(inputs["sealed_manifest"].read_text(encoding="utf-8"))
    if sealed["outputs"]["blind_worklist_d"]["sha256"] != file_sha256(inputs["worklist"]):
        raise ValueError("worklist seal mismatch")
    audit = json.loads(inputs["edge_audit"].read_text(encoding="utf-8"))
    family = next(
        (item for item in audit["family_ranking"] if item["project_family"] == "hutool"), None
    )
    if family is None or family.get("eligible_rank") != 3 or family.get("score") != 8:
        raise ValueError("edge audit Hutool ranking drift")
    rows = {
        row["cve_id"]: row
        for row in (
            json.loads(line) for line in inputs["worklist"].read_text(encoding="utf-8").splitlines()
            if line
        )
        if row.get("cve_id") in SPECS
    }
    if set(rows) != set(SPECS):
        raise ValueError("fixed Hutool rows are missing")
    for cve_id, spec in SPECS.items():
        row = rows[cve_id]
        if row.get("sample_id") != spec["sample_id"] or row.get("field") != "affected_versions":
            raise ValueError(f"fixed row identity drift for {cve_id}")
        if signature(row["nvd_value"]) != spec["nvd"]:
            raise ValueError(f"NVD claim drift for {cve_id}")
        expected_ghsa = {component: [span(None, None)] for component in spec["components"]}
        if signature(row["ghsa_value"]) != expected_ghsa:
            raise ValueError(f"GHSA claim drift for {cve_id}")

    catalogs = {}
    for coordinate in COORDINATES:
        artifact = coordinate.split(":", 1)[1]
        key = f"{artifact.replace('-', '_')}_metadata"
        catalogs[coordinate] = parse_catalog(cache_body(cache, key, metadata_url(coordinate)), coordinate)
    poms = {}
    jars = {}
    for version in ANCHORS:
        token = version.replace(".", "_")
        poms[version] = parse_pom(
            cache_body(cache, f"hutool_all_{token}_source_pom", source_url(version)), version
        )
        jars[version] = parse_jar(
            cache_body(cache, f"hutool_all_{token}_jar", jar_url(version)), version
        )

    stable_sets = {coordinate: set(value["stable_versions"]) for coordinate, value in catalogs.items()}
    domain = set.intersection(*stable_sets.values())
    catalogs_equal = len({frozenset(value) for value in stable_sets.values()}) == 1
    excluded_equal = all(value["excluded_versions"] == list(EXCLUDED) for value in catalogs.values())
    ordered = sorted(domain, key=Version.parse)
    expected_cases = []
    for cve_id in sorted(SPECS):
        spec = SPECS[cve_id]
        checks = {
            "fixed_input_signature": True,
            "maven_catalog_identities_bound": all(value["identity_bound"] for value in catalogs.values()),
            "stable_catalog_release_correspondence_total": catalogs_equal and bool(domain),
            "milestone_exclusion_exact": excluded_equal,
            "critical_anchor_versions_bound": set(ANCHORS) <= domain,
            "aggregate_source_pom_anchors_bound": all(value["bound"] for value in poms.values()),
            "aggregate_binary_component_anchors_bound": all(value["bound"] for value in jars.values()),
        }
        passed = all(checks.values())
        set_value = None
        label = "uncertain"
        release_sets = None
        if passed:
            nvd_claims = next(iter(spec["nvd"].values()))
            nvd = {
                version for version in domain
                if any(version_in_span(version, item) for item in nvd_claims)
            }
            ghsa = set().union(*(set(catalogs[item]["stable_versions"]) for item in spec["components"])) & domain
            set_value = relation(nvd, ghsa)
            label = candidate(set_value)
            release_sets = {
                "nvd_product_versions": sorted(nvd, key=Version.parse),
                "ghsa_component_union_versions": sorted(ghsa, key=Version.parse),
                "nvd_count": len(nvd),
                "ghsa_union_count": len(ghsa),
                "nvd_only": sorted(nvd - ghsa, key=Version.parse),
                "ghsa_only": sorted(ghsa - nvd, key=Version.parse),
            }
        expected_cases.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": spec["sample_id"],
            "cve_id": cve_id,
            "ghsa_components": list(spec["components"]),
            "checks": checks,
            "gate": {
                "passed": passed,
                "status": (
                    "hutool_snapshot_extensional_projection_allowed_mechanism_only"
                    if passed else "abstain_hutool_maven_projection_unresolved"
                ),
                "failed_checks": [name for name, value in checks.items() if not value],
                "development_typing_candidate": label,
                "promoted_candidate": None,
                "candidate_promotion_allowed": False,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            },
            "release_sets": release_sets,
            "release_set_relation": set_value,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })
    passed_rows = sum(case["gate"]["passed"] for case in expected_cases)
    expected = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "hutool_maven_release_graph_analysis",
        "catalogs": catalogs,
        "release_domain": {
            "scope": "stable_numeric_intersection_of_frozen_maven_catalogs",
            "versions": ordered,
            "version_count": len(ordered),
            "first_version": ordered[0] if ordered else None,
            "last_version": ordered[-1] if ordered else None,
            "excluded_milestones": list(EXCLUDED),
            "catalogs_equal": catalogs_equal,
        },
        "aggregate_anchor_evidence": {
            version: {"source_pom": poms[version], "aggregate_jar": jars[version]}
            for version in ANCHORS
        },
        "cases": expected_cases,
        "summary": {
            "row_count": 2,
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / 2,
            "development_candidate_counts": {
                label: sum(case["gate"]["development_typing_candidate"] == label for case in expected_cases)
                for label in sorted({case["gate"]["development_typing_candidate"] for case in expected_cases})
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
    observed = json.loads(outputs["analysis.json"].read_text(encoding="utf-8"))
    if observed != expected:
        raise ValueError("analysis differs from independent cache reconstruction")
    if outputs["summary.md"].read_text(encoding="utf-8") != render_markdown(expected):
        raise ValueError("summary Markdown differs from reconstruction")
    if manifest.get("summary") != expected["summary"]:
        raise ValueError("manifest summary differs from reconstruction")
    if manifest.get("advancement_gate") != expected["advancement_gate"]:
        raise ValueError("manifest advancement gate differs from reconstruction")
    if manifest.get("boundary") != expected["boundary"]:
        raise ValueError("manifest boundary differs from reconstruction")

    if len(domain) != 209 or ordered[0] != "4.0.0" or ordered[-1] != "5.8.47":
        raise ValueError("fixed Hutool stable release outcome drift")
    if any(value["version_count"] != 214 for value in catalogs.values()):
        raise ValueError("fixed Hutool full catalog count drift")
    if passed_rows != 2:
        raise ValueError("fixed Hutool mechanism result must project 2/2")
    if expected["summary"]["development_candidate_counts"] != {"incomplete": 2}:
        raise ValueError("fixed Hutool development candidate drift")
    if any(case["release_set_relation"] != "nvd_subset_of_ghsa" for case in expected_cases):
        raise ValueError("fixed Hutool set relation drift")
    return expected


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified Hutool Maven release graph: "
        f"{analysis['summary']['projection_gate_passed']}/2 mechanism projection; "
        "candidate promotion remains disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
