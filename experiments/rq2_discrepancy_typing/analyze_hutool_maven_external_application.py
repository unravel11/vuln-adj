#!/usr/bin/env python3
"""Apply the frozen Hutool Maven mechanism to the sealed external cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import analyze_hutool_maven_release_graph as base


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_PROJECT_ROOT = Path("/home/xiaoyuliang/code/vuln-adj")
SCHEMA_VERSION = "hutool_maven_external_application_v1"
DEFAULT_COHORT = (
    "data/annotations/holdout/rq2_typing_v1/"
    "hutool_maven_external_application_v1/cohort.jsonl"
)
DEFAULT_COHORT_MANIFEST = (
    "data/annotations/holdout/rq2_typing_v1/"
    "hutool_maven_external_application_v1/manifest.sealed.json"
)
DEFAULT_V1_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "hutool_maven_release_graph_v1/manifest.json"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "affected_versions_hutool_external_application_contract_v1.md"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "hutool_maven_external_application_v1"
)
AGGREGATE = "cn.hutool:hutool-all"
COMPONENTS = {"cn.hutool:hutool-core", "cn.hutool:hutool-json"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", default=DEFAULT_COHORT)
    parser.add_argument("--cohort-manifest", default=DEFAULT_COHORT_MANIFEST)
    parser.add_argument("--v1-manifest", default=DEFAULT_V1_MANIFEST)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def load_v1_analysis(manifest_path: Path) -> tuple[dict, dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != base.SCHEMA_VERSION:
        raise ValueError("Hutool v1 manifest schema drift")
    for name, record in manifest["inputs"].items():
        verified_record(record, f"v1 input:{name}")
    for name, record in manifest["evidence_cache"].items():
        verified_record(record, f"v1 cache:{name}")
    outputs = {
        name: verified_record(record, f"v1 output:{name}")
        for name, record in manifest["outputs"].items()
    }
    analysis = json.loads(outputs["analysis.json"].read_text(encoding="utf-8"))
    if analysis.get("schema_version") != base.SCHEMA_VERSION:
        raise ValueError("Hutool v1 analysis schema drift")
    return manifest, analysis


def mechanism_checks(v1: dict) -> dict:
    catalogs = v1.get("catalogs") or {}
    anchors = v1.get("aggregate_anchor_evidence") or {}
    return {
        "v1_advancement_gate_passed": (v1.get("advancement_gate") or {}).get("passed") is True,
        "v1_candidate_promotion_disabled": (
            (v1.get("advancement_gate") or {}).get("candidate_promotion_allowed") is False
        ),
        "catalog_coordinates_bound": (
            set(catalogs) == set(base.COORDINATES)
            and all(item.get("identity_bound") is True for item in catalogs.values())
        ),
        "stable_release_domain_bound": (
            (v1.get("release_domain") or {}).get("version_count") == 209
            and (v1.get("release_domain") or {}).get("catalogs_equal") is True
            and (v1.get("release_domain") or {}).get("excluded_milestones")
            == list(base.EXCLUDED_MILESTONES)
        ),
        "aggregate_anchor_evidence_bound": (
            set(anchors) == set(base.ANCHOR_VERSIONS)
            and all(
                item["source_pom"].get("bound") is True
                and item["aggregate_jar"].get("bound") is True
                for item in anchors.values()
            )
        ),
    }


def claim_boundaries(items: list[dict]) -> set[str]:
    values = set()
    for item in items:
        version = item.get("version")
        if version not in {None, "*", "-", "0"}:
            values.add(str(version))
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
            "fixed",
        ):
            value = item.get(key)
            if value not in {None, "", "0"}:
                values.add(str(value))
    return values


def affected_set(items: list[dict], domain: set[str]) -> set[str]:
    return {
        version
        for version in domain
        if any(base.version_in_span(version, base.row_span(item)) for item in items)
    }


def analyze(cohort: list[dict], cohort_manifest: dict, v1: dict) -> dict:
    ordered_domain = list(v1["release_domain"]["versions"])
    domain = set(ordered_domain)
    common_checks = mechanism_checks(v1)
    cases = []
    for row in cohort:
        packages = set(row["ghsa_packages"])
        boundaries = claim_boundaries(row["nvd_value"] + row["ghsa_value"])
        boundary_parseable = all(base.STABLE_VERSION.fullmatch(value) for value in boundaries)
        route_bound = (
            row["route"] == "product_to_aggregate_direct" and packages == {AGGREGATE}
        ) or (
            row["route"] == "product_via_aggregate_component"
            and bool(packages)
            and packages <= COMPONENTS
        )
        checks = {
            **common_checks,
            "cohort_epistemic_boundary_bound": all(
                row.get(key) is expected
                for key, expected in (
                    ("cve_exposure_disjoint", True),
                    ("selection_uses_labels", False),
                    ("selection_uses_reviewer_labels", False),
                    ("candidate_promotion_allowed", False),
                    ("label_is_human", False),
                )
            ),
            "frozen_route_bound": route_bound,
            "claim_boundaries_parseable": boundary_parseable,
            "claim_boundaries_in_release_domain": boundary_parseable and boundaries <= domain,
        }
        passed = all(checks.values())
        relation = None
        candidate = "uncertain"
        release_sets = None
        if passed:
            nvd = affected_set(row["nvd_value"], domain)
            ghsa_by_package = {
                package: affected_set(
                    [
                        item for item in row["ghsa_value"]
                        if (item.get("package_name") or item.get("product")) == package
                    ],
                    domain,
                )
                for package in packages
            }
            ghsa = set().union(*ghsa_by_package.values())
            relation = base.set_relation(nvd, ghsa)
            candidate = base.candidate_for_relation(relation)
            release_sets = {
                "nvd_product_versions": sorted(nvd, key=base.Version.parse),
                "ghsa_union_versions": sorted(ghsa, key=base.Version.parse),
                "nvd_count": len(nvd),
                "ghsa_union_count": len(ghsa),
                "nvd_only": sorted(nvd - ghsa, key=base.Version.parse),
                "ghsa_only": sorted(ghsa - nvd, key=base.Version.parse),
                "component_counts": {
                    package: len(values) for package, values in sorted(ghsa_by_package.items())
                },
            }
        cases.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "route": row["route"],
            "ghsa_packages": row["ghsa_packages"],
            "checks": checks,
            "gate": {
                "passed": passed,
                "status": (
                    "frozen_hutool_v1_projection_allowed_retrospective_only"
                    if passed else "abstain_external_application_unresolved"
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
            "selection_uses_labels": False,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })
    passed_rows = sum(case["gate"]["passed"] for case in cases)
    candidate_labels = sorted({case["gate"]["development_typing_candidate"] for case in cases})
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "hutool_maven_external_application_analysis",
        "cohort_selection_audit": cohort_manifest["selection_audit"],
        "reused_mechanism": {
            "schema_version": v1["schema_version"],
            "stable_release_count": len(ordered_domain),
            "first_release": ordered_domain[0],
            "last_release": ordered_domain[-1],
            "common_checks": common_checks,
        },
        "cases": cases,
        "summary": {
            "row_count": len(cases),
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / len(cases),
            "route_counts": cohort_manifest["selection_audit"]["route_counts"],
            "development_candidate_counts": {
                label: sum(
                    case["gate"]["development_typing_candidate"] == label
                    for case in cases
                )
                for label in candidate_labels
            },
            "promoted_candidate_count": 0,
            "original_rq2_combined_candidate_unchanged": "1219/1250",
        },
        "advancement_gate": {
            "required_projectable_rows": len(cases),
            "projectable_rows": passed_rows,
            "passed": passed_rows == len(cases),
            "status": (
                "retrospective_external_application_supported_nonhuman_only"
                if passed_rows == len(cases)
                else "no_go_hutool_external_application_unstable"
            ),
            "future_time_or_human_confirmation_required": True,
            "candidate_promotion_allowed": False,
        },
        "boundary": {
            "mechanism_frozen_before_availability_audit": True,
            "availability_discovery_disclosed": True,
            "same_snapshot_retrospective": True,
            "cve_exposure_disjoint": True,
            "selection_uses_labels": False,
            "selection_uses_reviewer_labels": False,
            "candidate_promotion_allowed": False,
            "development_diagnostic_only": True,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
            "generalization_claim_allowed": False,
        },
    }


def render_markdown(analysis: dict) -> str:
    lines = [
        "# Hutool Maven External Application v1",
        "",
        "> CVE-exposure-disjoint, same-snapshot retrospective application; not human gold.",
        "",
        f"- Cohort rows: `{analysis['summary']['row_count']}`",
        f"- Projection: `{analysis['summary']['projection_gate_passed']}/{analysis['summary']['row_count']}`",
        f"- Stable release domain: `{analysis['reused_mechanism']['stable_release_count']}`",
        f"- Status: `{analysis['advancement_gate']['status']}`",
        "- Candidate promotion: `disabled`",
        "",
        "| CVE | Route | NVD count | GHSA count | Relation | Codex development candidate |",
        "|---|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        sets = case["release_sets"] or {}
        lines.append(
            f"| {case['cve_id']} | {case['route']} | "
            f"{sets.get('nvd_count', 'not computed')} | "
            f"{sets.get('ghsa_union_count', 'not computed')} | "
            f"{case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "",
        "The mechanism was frozen before this availability audit, but the cohort comes from",
        "the same aligned snapshot and its structure was observed before sealing. These labels",
        "therefore remain non-promoted development candidates pending a time holdout or real review.",
        "",
    ])
    return "\n".join(lines)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    cohort_path = resolve(args.cohort)
    cohort_manifest_path = resolve(args.cohort_manifest)
    v1_manifest_path = resolve(args.v1_manifest)
    contract_path = resolve(args.contract)
    output_dir = resolve(args.output_dir)
    cohort_manifest = json.loads(cohort_manifest_path.read_text(encoding="utf-8"))
    if cohort_manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("external cohort manifest schema drift")
    if cohort_manifest["output"]["cohort"]["sha256"] != sha256(cohort_path):
        raise ValueError("external cohort seal mismatch")
    cohort = load_jsonl(cohort_path)
    if len(cohort) != cohort_manifest["output"]["cohort"]["row_count"]:
        raise ValueError("external cohort row count mismatch")
    _, v1_analysis = load_v1_analysis(v1_manifest_path)
    analysis = analyze(cohort, cohort_manifest, v1_analysis)
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path = output_dir / "analysis.json"
    summary_path = output_dir / "summary.md"
    write_json(analysis_path, analysis)
    summary_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "cohort": {"path": str(cohort_path), "sha256": sha256(cohort_path)},
            "cohort_manifest": {
                "path": str(cohort_manifest_path), "sha256": sha256(cohort_manifest_path)
            },
            "v1_manifest": {
                "path": str(v1_manifest_path), "sha256": sha256(v1_manifest_path)
            },
            "contract": {"path": str(contract_path), "sha256": sha256(contract_path)},
            "code": {"path": str(Path(__file__).resolve()), "sha256": sha256(Path(__file__).resolve())},
        },
        "outputs": {
            "analysis.json": {"path": str(analysis_path), "sha256": sha256(analysis_path)},
            "summary.md": {"path": str(summary_path), "sha256": sha256(summary_path)},
        },
        "summary": analysis["summary"],
        "advancement_gate": analysis["advancement_gate"],
        "boundary": analysis["boundary"],
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }
    write_json(output_dir / "manifest.json", manifest)
    print(json.dumps({
        "row_count": analysis["summary"]["row_count"],
        "projection_gate_passed": analysis["summary"]["projection_gate_passed"],
        "candidate_counts": analysis["summary"]["development_candidate_counts"],
        "status": analysis["advancement_gate"]["status"],
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
