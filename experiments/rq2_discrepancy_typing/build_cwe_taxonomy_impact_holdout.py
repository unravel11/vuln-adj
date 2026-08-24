#!/usr/bin/env python3
"""Seal a blind full-impact audit for the 17 CWE taxonomy candidate changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from analyze_cwe_taxonomy_variants import (
    CWE_SOURCE_URL,
    TAXONOMY_VIEW_ID,
    CweCatalog,
    aligned_context,
    cwe_id,
    iter_jsonl,
    relation_profile,
    strip_cwe,
    taxonomy_v1_status,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout"
)
DEFAULT_CHANGED = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/"
    "cwe_taxonomy_changed_cases.jsonl"
)
DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_PRIMARY_SEED = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_PROMPT = "docs/prompts/rq2_cwe_taxonomy_impact_review.md"
DEFAULT_AGENT_A = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_impact_agent_a.jsonl"
)
DEFAULT_AGENT_B = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_impact_agent_b.jsonl"
)
FORBIDDEN_BLIND_KEYS = {
    "baseline_status",
    "current_status",
    "taxonomy_v1_status",
    "current_prediction",
    "taxonomy_v1_prediction",
    "candidate_label",
    "gold_label",
}
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changed-cases", default=DEFAULT_CHANGED)
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--primary-seed", default=DEFAULT_PRIMARY_SEED)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key
            for child in value.values()
            for key in recursive_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in recursive_keys(child)}
    return set()


def validate_blind_row(row: dict) -> None:
    leaked = recursive_keys(row) & FORBIDDEN_BLIND_KEYS
    if leaked:
        raise ValueError(f"blind row contains prediction keys: {sorted(leaked)}")


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"duplicate {key}={value} in {path}")
        rows[value] = row
    return rows


def build_worklist_row(
    index: int,
    field_row: dict,
    aligned_row: dict,
    catalog: CweCatalog,
) -> tuple[dict, dict]:
    cve = field_row["cve_id"]
    discrepancy = field_row["field_discrepancies"]["cwe_ids"]
    nvd_values = discrepancy.get("nvd_value") or []
    ghsa_values = discrepancy.get("ghsa_value") or []
    profile = relation_profile(nvd_values, ghsa_values, catalog)
    identifiers = sorted(
        {strip_cwe(value) for value in [*nvd_values, *ghsa_values]},
        key=int,
    )
    worklist = {
        "review_id": f"rq2_cwe_taxonomy_impact:{index:03d}",
        "cve_id": cve,
        "field": "cwe_ids",
        "nvd_value": [cwe_id(value) for value in nvd_values],
        "ghsa_value": [cwe_id(value) for value in ghsa_values],
        "vulnerability_context": aligned_context(aligned_row),
        "official_cwe_entries": [catalog.entries[value] for value in identifiers],
        "official_cross_source_ancestor_descendant_paths": profile[
            "ancestor_descendant_paths"
        ],
        "taxonomy_source": {
            "catalog_version": catalog.version,
            "catalog_date": catalog.date,
            "view_id": TAXONOMY_VIEW_ID,
            "source_url": CWE_SOURCE_URL,
        },
        "review_contract": {
            "set_relation": [
                "exact_set",
                "literal_strict_subset",
                "fully_ancestor_descendant_compatible",
                "partially_related_mixed",
                "semantically_distinct",
                "insufficient_taxonomy_or_context",
            ],
            "discrepancy_label": list(LABELS),
            "taxonomy_support_verdict": [
                "supports_granularity_only",
                "does_not_support_granularity_only",
                "mixed",
                "insufficient",
            ],
            "confidence": ["high", "medium", "low"],
        },
    }
    validate_blind_row(worklist)
    predictions = {
        "review_id": worklist["review_id"],
        "cve_id": cve,
        "current_prediction": discrepancy["status"],
        "taxonomy_v1_prediction": taxonomy_v1_status(
            discrepancy["status"], profile
        ),
        "relation_category": profile["category"],
    }
    return worklist, predictions


def main() -> int:
    args = parse_args()
    paths = {
        "changed_cases": resolve(args.changed_cases),
        "field_views": resolve(args.field_views),
        "aligned": resolve(args.aligned),
        "cwe_zip": resolve(args.cwe_xml_zip),
        "primary_seed": resolve(args.primary_seed),
        "prompt": resolve(args.prompt),
        "agent_a": resolve(args.agent_a),
        "agent_b": resolve(args.agent_b),
    }
    if paths["agent_a"].exists() or paths["agent_b"].exists():
        raise ValueError("reviewer output exists before sealing")

    output_dir = resolve(args.output_dir)
    worklist_path = output_dir / "cwe_taxonomy_impact_worklist.blind.jsonl"
    predictions_path = output_dir / "cwe_taxonomy_impact_predictions.sealed.jsonl"
    manifest_path = output_dir / "cwe_taxonomy_impact_manifest.sealed.json"
    outputs = (worklist_path, predictions_path, manifest_path)
    if not args.force and any(path.exists() for path in outputs):
        raise ValueError("sealed output already exists; use --force only before reviews")

    changed = load_unique(paths["changed_cases"], "cve_id")
    if len(changed) != 17:
        raise ValueError(f"expected 17 changed rows, found {len(changed)}")
    primary_cves = {
        row["cve_id"] for row in iter_jsonl(paths["primary_seed"])
    }
    field_rows = {
        row["cve_id"]: row
        for row in iter_jsonl(paths["field_views"])
        if row["cve_id"] in changed
    }
    if set(field_rows) != set(changed):
        raise ValueError("changed CVEs are missing from field views")
    aligned = load_unique(paths["aligned"], "cve_id")
    catalog = CweCatalog(paths["cwe_zip"])

    worklist = []
    predictions = []
    for index, cve in enumerate(sorted(changed), start=1):
        source = field_rows[cve]
        blind_row, prediction_row = build_worklist_row(
            index, source, aligned[cve], catalog
        )
        expected = changed[cve]
        if prediction_row["current_prediction"] != expected["current_status"]:
            raise ValueError(f"current prediction drift for {cve}")
        if (
            prediction_row["taxonomy_v1_prediction"]
            != expected["taxonomy_v1_status"]
        ):
            raise ValueError(f"taxonomy prediction drift for {cve}")
        if prediction_row["relation_category"] != "disjoint_full_taxonomy_coverage":
            raise ValueError(f"unexpected relation category for {cve}")
        worklist.append(blind_row)
        predictions.append(prediction_row)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(worklist_path, worklist)
    write_jsonl(predictions_path, predictions)
    cve_commitment = hashlib.sha256(
        ("\n".join(row["cve_id"] for row in worklist) + "\n").encode()
    ).hexdigest()
    sealed_at_ns = time.time_ns()
    manifest = {
        "artifact_type": "rq2_cwe_taxonomy_impact_holdout_manifest",
        "sealed_at_ns": sealed_at_ns,
        "row_count": len(worklist),
        "prediction_count": len(predictions) * 2,
        "cve_commitment_sha256": cve_commitment,
        "primary_seed_overlap_cves": sorted(set(changed) & primary_cves),
        "primary_seed_disjoint_rows": len(set(changed) - primary_cves),
        "reviewer_outputs_absent_at_seal": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "worklist": {
            "path": str(worklist_path),
            "sha256": sha256(worklist_path),
        },
        "predictions": {
            "path": str(predictions_path),
            "sha256": sha256(predictions_path),
        },
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
            if name not in {"agent_a", "agent_b"}
        },
        "reviewer_outputs": {
            "agent_a": str(paths["agent_a"]),
            "agent_b": str(paths["agent_b"]),
        },
        "code": {
            "path": str(Path(__file__)),
            "sha256": sha256(Path(__file__)),
        },
        "cautions": [
            "The 17 rows are the complete impact set of a post-hoc candidate rule.",
            "Sixteen rows are CVE-disjoint from the 300-row primary RQ2 seed; one is not.",
            "Codex reviewer consensus is not human gold or independent-human validation.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {worklist_path}")
    print(f"Wrote {predictions_path}")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
