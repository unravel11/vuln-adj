#!/usr/bin/env python3
"""Independently verify the sealed Hutool external application."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import verify_hutool_maven_release_graph as base


PROJECT_ROOT = Path(__file__).resolve().parents[2]
AUTHORITATIVE_PROJECT_ROOT = Path("/home/xiaoyuliang/code/vuln-adj")
SCHEMA_VERSION = "hutool_maven_external_application_v1"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "hutool_maven_external_application_v1/manifest.json"
)
AGGREGATE = "cn.hutool:hutool-all"
COMPONENTS = {"cn.hutool:hutool-core", "cn.hutool:hutool-json"}


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


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                yield line_number, json.loads(line)


def cve_set(path: Path) -> set[str]:
    return {
        str(row["cve_id"])
        for _, row in iter_jsonl(path)
        if row.get("cve_id")
    }


def vulnerable(items: list[dict]) -> list[dict]:
    return [item for item in items if item.get("vulnerable") is not False]


def family_extract(row: dict) -> dict | None:
    if not row.get("nvd") or not row.get("ghsa"):
        return None
    nvd = vulnerable(row["nvd"].get("affected") or [])
    ghsa = vulnerable([
        item for advisory in row["ghsa"] for item in (advisory.get("affected") or [])
    ])
    nvd_products = {
        str(item.get("package_name") or item.get("product") or "").lower()
        for item in nvd
    }
    packages = {
        str(item.get("package_name") or item.get("product") or "") for item in ghsa
    }
    if "hutool" not in nvd_products or not any(value.startswith("cn.hutool:") for value in packages):
        return None
    if not packages or any(
        item.get("ecosystem") != "Maven"
        or not str(item.get("package_name") or item.get("product") or "").startswith("cn.hutool:")
        for item in ghsa
    ):
        raise ValueError(f"mixed Hutool family row: {row['cve_id']}")
    route = (
        "product_to_aggregate_direct"
        if packages == {AGGREGATE}
        else "product_via_aggregate_component"
        if packages <= COMPONENTS
        else "out_of_scope_coordinate"
    )
    return {"nvd": nvd, "ghsa": ghsa, "packages": sorted(packages), "route": route}


def recompute_cohort(cohort_manifest: dict, inputs: dict[str, Path]) -> tuple[list[dict], dict]:
    exclusion_records = cohort_manifest["inputs"]["exclusions"]
    exclusions = {
        name: cve_set(verified_record(record, f"cohort exclusion:{name}"))
        for name, record in exclusion_records.items()
    }
    excluded = set().union(*exclusions.values())
    if len(excluded) != 1967:
        raise ValueError("fixed external exclusion union drift")
    matched = 0
    family = []
    for line_number, row in iter_jsonl(inputs["aligned"]):
        if row.get("ghsa"):
            matched += 1
        extracted = family_extract(row)
        if extracted is not None:
            family.append((line_number, row["cve_id"], extracted))
    selected = []
    excluded_family = []
    for line_number, cve_id, item in family:
        if cve_id in excluded:
            excluded_family.append({
                "cve_id": cve_id, "route": item["route"], "reason": "prior_cve_exposure"
            })
            continue
        if item["route"] == "out_of_scope_coordinate":
            raise ValueError(f"unseen external row outside frozen route: {cve_id}")
        selected.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": f"hutool_maven_external_v1:{cve_id}",
            "cve_id": cve_id,
            "field": "affected_versions",
            "route": item["route"],
            "ghsa_packages": item["packages"],
            "nvd_value": item["nvd"],
            "ghsa_value": item["ghsa"],
            "source_line_number": line_number,
            "cve_exposure_disjoint": True,
            "selection_uses_labels": False,
            "selection_uses_reviewer_labels": False,
            "mechanism_frozen_before_availability_audit": True,
            "availability_discovery_disclosed": True,
            "same_snapshot_retrospective": True,
            "candidate_promotion_allowed": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })
    selected.sort(key=lambda row: row["cve_id"])
    audit = {
        "matched_row_count": matched,
        "hutool_family_row_count": len(family),
        "excluded_family_row_count": len(excluded_family),
        "excluded_family_rows": sorted(excluded_family, key=lambda row: row["cve_id"]),
        "selected_row_count": len(selected),
        "route_counts": dict(sorted(Counter(row["route"] for row in selected).items())),
    }
    if (
        matched != 8066
        or len(family) != 10
        or len(selected) != 6
        or audit["route_counts"] != {
            "product_to_aggregate_direct": 2,
            "product_via_aggregate_component": 4,
        }
    ):
        raise ValueError("fixed external cohort outcome drift")
    return selected, audit


def boundaries(items: list[dict]) -> set[str]:
    result = set()
    for item in items:
        version = item.get("version")
        if version not in {None, "*", "-", "0"}:
            result.add(str(version))
        for key in (
            "version_start_including", "version_start_excluding",
            "version_end_including", "version_end_excluding", "fixed",
        ):
            value = item.get(key)
            if value not in {None, "", "0"}:
                result.add(str(value))
    return result


def affected(items: list[dict], domain: set[str]) -> set[str]:
    return {
        version for version in domain
        if any(base.version_in_span(version, base.row_span(item)) for item in items)
    }


def mechanism_checks(v1: dict) -> dict:
    catalogs = v1["catalogs"]
    anchors = v1["aggregate_anchor_evidence"]
    return {
        "v1_advancement_gate_passed": v1["advancement_gate"]["passed"] is True,
        "v1_candidate_promotion_disabled": v1["advancement_gate"]["candidate_promotion_allowed"] is False,
        "catalog_coordinates_bound": (
            set(catalogs) == set(base.COORDINATES)
            and all(item["identity_bound"] is True for item in catalogs.values())
        ),
        "stable_release_domain_bound": (
            v1["release_domain"]["version_count"] == 209
            and v1["release_domain"]["catalogs_equal"] is True
            and v1["release_domain"]["excluded_milestones"] == list(base.EXCLUDED)
        ),
        "aggregate_anchor_evidence_bound": (
            set(anchors) == set(base.ANCHORS)
            and all(
                value["source_pom"]["bound"] is True
                and value["aggregate_jar"]["bound"] is True
                for value in anchors.values()
            )
        ),
    }


def recompute_analysis(cohort: list[dict], selection_audit: dict, v1: dict) -> dict:
    ordered = list(v1["release_domain"]["versions"])
    domain = set(ordered)
    common = mechanism_checks(v1)
    cases = []
    for row in cohort:
        packages = set(row["ghsa_packages"])
        endpoint_set = boundaries(row["nvd_value"] + row["ghsa_value"])
        parseable = all(base.STABLE.fullmatch(value) for value in endpoint_set)
        route_bound = (
            row["route"] == "product_to_aggregate_direct" and packages == {AGGREGATE}
        ) or (
            row["route"] == "product_via_aggregate_component"
            and bool(packages) and packages <= COMPONENTS
        )
        checks = {
            **common,
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
            "claim_boundaries_parseable": parseable,
            "claim_boundaries_in_release_domain": parseable and endpoint_set <= domain,
        }
        passed = all(checks.values())
        set_relation = None
        label = "uncertain"
        release_sets = None
        if passed:
            nvd = affected(row["nvd_value"], domain)
            per_package = {
                package: affected([
                    item for item in row["ghsa_value"]
                    if (item.get("package_name") or item.get("product")) == package
                ], domain)
                for package in packages
            }
            ghsa = set().union(*per_package.values())
            set_relation = base.relation(nvd, ghsa)
            label = base.candidate(set_relation)
            release_sets = {
                "nvd_product_versions": sorted(nvd, key=base.Version.parse),
                "ghsa_union_versions": sorted(ghsa, key=base.Version.parse),
                "nvd_count": len(nvd),
                "ghsa_union_count": len(ghsa),
                "nvd_only": sorted(nvd - ghsa, key=base.Version.parse),
                "ghsa_only": sorted(ghsa - nvd, key=base.Version.parse),
                "component_counts": {
                    package: len(values) for package, values in sorted(per_package.items())
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
                "development_typing_candidate": label,
                "promoted_candidate": None,
                "candidate_promotion_allowed": False,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
            },
            "release_sets": release_sets,
            "release_set_relation": set_relation,
            "selection_uses_labels": False,
            "selection_uses_reviewer_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
        })
    passed_rows = sum(case["gate"]["passed"] for case in cases)
    labels = sorted({case["gate"]["development_typing_candidate"] for case in cases})
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "hutool_maven_external_application_analysis",
        "cohort_selection_audit": selection_audit,
        "reused_mechanism": {
            "schema_version": v1["schema_version"],
            "stable_release_count": len(ordered),
            "first_release": ordered[0],
            "last_release": ordered[-1],
            "common_checks": common,
        },
        "cases": cases,
        "summary": {
            "row_count": len(cases),
            "projection_gate_passed": passed_rows,
            "projection_coverage": passed_rows / len(cases),
            "route_counts": selection_audit["route_counts"],
            "development_candidate_counts": {
                label: sum(case["gate"]["development_typing_candidate"] == label for case in cases)
                for label in labels
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
        "# Hutool Maven External Application v1", "",
        "> CVE-exposure-disjoint, same-snapshot retrospective application; not human gold.", "",
        f"- Cohort rows: `{analysis['summary']['row_count']}`",
        f"- Projection: `{analysis['summary']['projection_gate_passed']}/{analysis['summary']['row_count']}`",
        f"- Stable release domain: `{analysis['reused_mechanism']['stable_release_count']}`",
        f"- Status: `{analysis['advancement_gate']['status']}`",
        "- Candidate promotion: `disabled`", "",
        "| CVE | Route | NVD count | GHSA count | Relation | Codex development candidate |",
        "|---|---|---|---|---|---|",
    ]
    for case in analysis["cases"]:
        sets = case["release_sets"] or {}
        lines.append(
            f"| {case['cve_id']} | {case['route']} | {sets.get('nvd_count', 'not computed')} | "
            f"{sets.get('ghsa_union_count', 'not computed')} | "
            f"{case['release_set_relation'] or 'not computed'} | "
            f"{case['gate']['development_typing_candidate']} |"
        )
    lines.extend([
        "", "The mechanism was frozen before this availability audit, but the cohort comes from",
        "the same aligned snapshot and its structure was observed before sealing. These labels",
        "therefore remain non-promoted development candidates pending a time holdout or real review.", "",
    ])
    return "\n".join(lines)


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("external application manifest schema drift")
    inputs = {
        name: verified_record(record, f"application input:{name}")
        for name, record in manifest["inputs"].items()
    }
    outputs = {
        name: verified_record(record, f"application output:{name}")
        for name, record in manifest["outputs"].items()
    }
    cohort_manifest = json.loads(inputs["cohort_manifest"].read_text(encoding="utf-8"))
    if cohort_manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("cohort manifest schema drift")
    aligned_path = verified_record(cohort_manifest["inputs"]["aligned"], "cohort aligned")
    recomputed_cohort, selection_audit = recompute_cohort(
        cohort_manifest, {"aligned": aligned_path}
    )
    observed_cohort = [row for _, row in iter_jsonl(inputs["cohort"])]
    if observed_cohort != recomputed_cohort:
        raise ValueError("sealed cohort differs from independent selection")
    if cohort_manifest.get("selection_audit") != selection_audit:
        raise ValueError("cohort selection audit differs from reconstruction")
    if cohort_manifest["output"]["cohort"]["sha256"] != sha256(inputs["cohort"]):
        raise ValueError("cohort output seal mismatch")

    v1_manifest = json.loads(inputs["v1_manifest"].read_text(encoding="utf-8"))
    v1_analysis = base.validate(v1_manifest)
    expected = recompute_analysis(recomputed_cohort, selection_audit, v1_analysis)
    observed = json.loads(outputs["analysis.json"].read_text(encoding="utf-8"))
    if observed != expected:
        raise ValueError("external analysis differs from independent reconstruction")
    if outputs["summary.md"].read_text(encoding="utf-8") != render_markdown(expected):
        raise ValueError("external summary differs from independent reconstruction")
    if manifest.get("summary") != expected["summary"]:
        raise ValueError("application manifest summary drift")
    if manifest.get("advancement_gate") != expected["advancement_gate"]:
        raise ValueError("application advancement gate drift")
    if manifest.get("boundary") != expected["boundary"]:
        raise ValueError("application boundary drift")
    if expected["summary"]["projection_gate_passed"] != 6:
        raise ValueError("fixed external projection must pass 6/6")
    if expected["summary"]["development_candidate_counts"] != {
        "incomplete": 5, "representation_discrepancy": 1
    }:
        raise ValueError("fixed external candidate counts drift")
    if expected["summary"]["promoted_candidate_count"] != 0:
        raise ValueError("external candidates must remain unpromoted")
    return expected


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    analysis = validate(json.loads(manifest_path.read_text(encoding="utf-8")))
    print(
        "Verified Hutool external application: "
        f"{analysis['summary']['projection_gate_passed']}/{analysis['summary']['row_count']} "
        "retrospective projection; promotion disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
