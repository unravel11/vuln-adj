#!/usr/bin/env python3
"""Seal CVE-exposure-disjoint Hutool rows before candidate computation."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "hutool_maven_external_application_v1"
DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/"
    "hutool_maven_external_application_v1"
)
EXCLUSION_PATHS = {
    "rq2_primary": "data/annotations/rq2/discrepancy_typing_seed.jsonl",
    "reference_impact": (
        "results/rq2_discrepancy_typing/reference_normalization_impact_validation/"
        "reference_identity_secondary_worklist.masked.jsonl"
    ),
    "cwe_impact": (
        "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/"
        "cwe_taxonomy_impact_worklist.blind.jsonl"
    ),
    "phase_d_affected": (
        "data/annotations/phase_d/affected_versions_fc_manual_check.jsonl"
    ),
    "phase_d_severity": (
        "data/annotations/phase_d/severity_fc_adjudication_seed.jsonl"
    ),
    "affected_versions_v1": (
        "data/annotations/holdout/affected_versions_v1/source_rows.jsonl"
    ),
    "affected_versions_v2": (
        "data/annotations/holdout/affected_versions_v2/source_rows.jsonl"
    ),
    "fresh_typing_1250": (
        "data/annotations/holdout/rq2_typing_v1/source_rows.jsonl"
    ),
}
AGGREGATE = "cn.hutool:hutool-all"
COMPONENTS = {"cn.hutool:hutool-core", "cn.hutool:hutool-json"}
EXPECTED_MATCHED_ROWS = 8066
EXPECTED_HUTOOL_FAMILY_ROWS = 10
EXPECTED_EXCLUSION_UNION = 1967
EXPECTED_SELECTED_ROWS = 6
EXPECTED_ROUTE_COUNTS = {
    "product_to_aggregate_direct": 2,
    "product_via_aggregate_component": 4,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def vulnerable_records(items: list[dict]) -> list[dict]:
    return [item for item in items if item.get("vulnerable") is not False]


def hutool_family_row(row: dict) -> dict | None:
    if not row.get("ghsa") or not row.get("nvd"):
        return None
    nvd_items = vulnerable_records(row["nvd"].get("affected") or [])
    ghsa_items = vulnerable_records([
        item
        for advisory in row["ghsa"]
        for item in (advisory.get("affected") or [])
    ])
    nvd_products = {
        str(item.get("package_name") or item.get("product") or "").lower()
        for item in nvd_items
    }
    packages = {
        str(item.get("package_name") or item.get("product") or "")
        for item in ghsa_items
    }
    if "hutool" not in nvd_products or not any(
        package.startswith("cn.hutool:") for package in packages
    ):
        return None
    if not packages or any(
        item.get("ecosystem") != "Maven"
        or not str(item.get("package_name") or item.get("product") or "").startswith(
            "cn.hutool:"
        )
        for item in ghsa_items
    ):
        raise ValueError(f"mixed or malformed Hutool GHSA row: {row['cve_id']}")
    if packages == {AGGREGATE}:
        route = "product_to_aggregate_direct"
    elif packages <= COMPONENTS:
        route = "product_via_aggregate_component"
    else:
        route = "out_of_scope_coordinate"
    return {
        "nvd_value": nvd_items,
        "ghsa_value": ghsa_items,
        "ghsa_packages": sorted(packages),
        "route": route,
    }


def select_rows(aligned: Path, excluded: set[str]) -> tuple[list[dict], dict]:
    matched_count = 0
    family_rows = []
    for line_number, row in iter_jsonl(aligned):
        if row.get("ghsa"):
            matched_count += 1
        extracted = hutool_family_row(row)
        if extracted is None:
            continue
        family_rows.append({
            "cve_id": row["cve_id"],
            "source_line_number": line_number,
            **extracted,
        })
    selected = []
    excluded_family = []
    for row in family_rows:
        if row["cve_id"] in excluded:
            excluded_family.append({
                "cve_id": row["cve_id"],
                "route": row["route"],
                "reason": "prior_cve_exposure",
            })
            continue
        if row["route"] == "out_of_scope_coordinate":
            raise ValueError(
                "exposure-disjoint Hutool row falls outside frozen routes: "
                f"{row['cve_id']} {row['ghsa_packages']}"
            )
        selected.append({
            "schema_version": SCHEMA_VERSION,
            "sample_id": f"hutool_maven_external_v1:{row['cve_id']}",
            "cve_id": row["cve_id"],
            "field": "affected_versions",
            "route": row["route"],
            "ghsa_packages": row["ghsa_packages"],
            "nvd_value": row["nvd_value"],
            "ghsa_value": row["ghsa_value"],
            "source_line_number": row["source_line_number"],
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
    selected.sort(key=lambda item: item["cve_id"])
    audit = {
        "matched_row_count": matched_count,
        "hutool_family_row_count": len(family_rows),
        "excluded_family_row_count": len(excluded_family),
        "excluded_family_rows": sorted(excluded_family, key=lambda item: item["cve_id"]),
        "selected_row_count": len(selected),
        "route_counts": dict(sorted(Counter(row["route"] for row in selected).items())),
    }
    return selected, audit


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    aligned = resolve(args.aligned)
    output_dir = resolve(args.output_dir)
    cohort_path = output_dir / "cohort.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    if output_dir.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite sealed cohort: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    exclusion_paths = {name: resolve(value) for name, value in EXCLUSION_PATHS.items()}
    exclusion_sets = {name: cve_set(path) for name, path in exclusion_paths.items()}
    excluded = set().union(*exclusion_sets.values())
    if len(excluded) != EXPECTED_EXCLUSION_UNION:
        raise ValueError(
            f"expected exclusion union {EXPECTED_EXCLUSION_UNION}, found {len(excluded)}"
        )
    rows, audit = select_rows(aligned, excluded)
    expected_audit = {
        "matched_row_count": EXPECTED_MATCHED_ROWS,
        "hutool_family_row_count": EXPECTED_HUTOOL_FAMILY_ROWS,
        "selected_row_count": EXPECTED_SELECTED_ROWS,
        "route_counts": EXPECTED_ROUTE_COUNTS,
    }
    for key, expected in expected_audit.items():
        if audit[key] != expected:
            raise ValueError(f"Hutool selection drift for {key}: {audit[key]} != {expected}")
    write_jsonl(cohort_path, rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "hutool_maven_external_application_cohort_seal",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "aligned": {"path": str(aligned), "sha256": sha256(aligned)},
            "exclusions": {
                name: {
                    "path": str(path),
                    "sha256": sha256(path),
                    "cve_count": len(exclusion_sets[name]),
                }
                for name, path in exclusion_paths.items()
            },
            "builder": {
                "path": str(Path(__file__).resolve()),
                "sha256": sha256(Path(__file__).resolve()),
            },
        },
        "output": {
            "cohort": {
                "path": str(cohort_path),
                "sha256": sha256(cohort_path),
                "row_count": len(rows),
            }
        },
        "selection_audit": audit,
        "excluded_union_cves": len(excluded),
        "selection_uses_labels": False,
        "selection_uses_reviewer_labels": False,
        "mechanism_frozen_before_availability_audit": True,
        "availability_discovery_disclosed": True,
        "same_snapshot_retrospective": True,
        "candidate_promotion_allowed": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }
    write_json(manifest_path, manifest)
    print(json.dumps({
        "selected_rows": len(rows),
        "route_counts": audit["route_counts"],
        "excluded_union_cves": len(excluded),
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
