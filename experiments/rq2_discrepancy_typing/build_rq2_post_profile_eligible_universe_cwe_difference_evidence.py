#!/usr/bin/env python3
"""Seal frozen evidence for all 29 eligible-universe CWE profile differences."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
for directory in (PROJECT_ROOT, MODULE_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from scripts.build_rq3_evidence_samples import (  # noqa: E402
    FetchConfig,
    cache_path_for_url,
)
from analyze_cwe_taxonomy_variants import CweCatalog  # noqa: E402
from build_rq2_post_profile_cwe_all50_evidence import build_row  # noqa: E402
from build_rq2_post_profile_cwe_evidence_secondary import recursive_keys  # noqa: E402
from build_rq2_typing_holdout import (  # noqa: E402
    codex_cli_contract,
    iter_jsonl,
    source_row,
    unique_by_cve,
    write_jsonl,
)
from verify_rq2_post_profile_eligible_universe_prediction_census import (  # noqa: E402
    main as verify_census,
)


DEFAULT_CENSUS_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "eligible_universe_prediction_census_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_eligible_universe_cwe_difference_evidence_contract_v1.md"
)
DEFAULT_PROMPT = (
    "docs/prompts/"
    "rq2_post_profile_eligible_universe_cwe_difference_evidence_review_v1.md"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_eligible_difference_evidence_v1"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/"
    "post_profile_cwe_eligible_difference_evidence_v1/url_cache"
)
EXPECTED_ROWS = 29
MAX_BYTES = 1_500_000
MAX_TEXT_CHARS = 6_000
FORBIDDEN_KEYS = {
    "annotation",
    "baseline_note",
    "baseline_status",
    "candidate",
    "changed_profiles_from_current",
    "combined_audited_v1",
    "combined_original_v1",
    "consensus_label",
    "current",
    "current_prediction",
    "cwe_taxonomy_v1",
    "design_weight",
    "gold_label",
    "label_is_human",
    "profile_difference",
    "profile_direction",
    "profile_prediction",
    "reference_resource_identity_audited_v1",
    "reference_resource_identity_original_v1",
    "reviewer_a",
    "reviewer_b",
    "sampling_stratum",
    "strict_consensus",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-dir", default=DEFAULT_CENSUS_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=25)
    parser.add_argument("--codex-cli-path", default="codex")
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--refresh", action="store_true")
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


def checked(record: dict, name: str) -> Path:
    path = Path(record.get("path", ""))
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def select_cwe_differences(rows: list[dict]) -> list[dict]:
    selected = [row for row in rows if row.get("field") == "cwe_ids"]
    if len(selected) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} CWE differences, found {len(selected)}")
    if len({row.get("cve_id") for row in selected}) != EXPECTED_ROWS:
        raise ValueError("CWE difference CVEs are not unique")
    for row in selected:
        if row.get("current") != "factual_conflict":
            raise ValueError(f"{row.get('cve_id')}: current prediction drift")
        if row.get("cwe_taxonomy_v1") != "representation_discrepancy":
            raise ValueError(f"{row.get('cve_id')}: taxonomy prediction drift")
        if row.get("label_is_human") is not False:
            raise ValueError("prediction row claims human provenance")
    return sorted(selected, key=lambda row: row["sample_id"])


def build_sources(
    differences: list[dict],
    field_rows: dict[str, dict],
    aligned: dict[str, dict],
    catalog: CweCatalog,
) -> list[dict]:
    rows = []
    for difference in differences:
        cve_id = difference["cve_id"]
        source = source_row(
            field_rows[cve_id],
            "cwe_ids",
            difference["sample_id"],
            1,
            1,
            aligned[cve_id],
            catalog,
        )
        source.pop("sampling_stratum", None)
        rows.append(source)
    return rows


def main() -> int:
    args = parse_args()
    census_dir = resolve(args.census_dir)
    census_manifest_path = census_dir / "manifest.json"
    census_manifest = json.loads(census_manifest_path.read_text(encoding="utf-8"))
    if census_manifest.get("artifact_type") != (
        "rq2_post_profile_eligible_universe_prediction_census_manifest_v1"
    ):
        raise ValueError("unexpected census manifest")
    original_argv = sys.argv
    try:
        sys.argv = ["verify_census", "--result-dir", str(census_dir)]
        if verify_census() != 0:
            raise ValueError("prediction census verifier failed")
    finally:
        sys.argv = original_argv

    census_inputs = census_manifest["inputs"]
    census_outputs = census_manifest["outputs"]
    paths = {
        "census_manifest": census_manifest_path,
        "census_analysis": checked(census_outputs["analysis"], "census analysis"),
        "difference_rows": checked(
            census_outputs["prediction_difference_rows"], "difference rows"
        ),
        "parent_cohort_manifest": checked(
            census_inputs["parent_cohort_manifest"], "parent cohort manifest"
        ),
        "parent_field_views": checked(
            census_inputs["parent_input_field_views"], "parent field views"
        ),
        "parent_aligned": checked(
            census_inputs["parent_input_aligned"], "parent aligned"
        ),
        "cwe_xml_zip": checked(
            census_inputs["parent_input_cwe_xml_zip"], "CWE catalog"
        ),
        "prior_all50_consensus": resolve(
            "results/holdout/rq2_post_profile_snapshot_v1/review/"
            "cwe_all50_evidence_v3/dual_review_consensus.jsonl"
        ),
        "prior_all50_merge_manifest": resolve(
            "results/holdout/rq2_post_profile_snapshot_v1/review/"
            "cwe_all50_evidence_v3/merge_manifest.json"
        ),
        "sealed_profile_evaluation": resolve(
            "results/holdout/rq2_post_profile_snapshot_v1/review/"
            "profile_evaluation.json"
        ),
        "contract": resolve(args.contract),
        "prompt": resolve(args.prompt),
        "fetcher_code": resolve("scripts/build_rq3_evidence_samples.py"),
        "source_builder_code": resolve(
            "experiments/rq2_discrepancy_typing/build_rq2_typing_holdout.py"
        ),
        "evidence_helper_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "build_rq2_post_profile_cwe_evidence_secondary.py"
        ),
        "all50_builder_helper_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "build_rq2_post_profile_cwe_all50_evidence.py"
        ),
        "runner_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "run_rq2_post_profile_eligible_universe_cwe_difference_review.py"
        ),
        "merge_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "merge_rq2_post_profile_eligible_universe_cwe_difference_reviews.py"
        ),
        "verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_eligible_universe_cwe_difference_review.py"
        ),
        "builder_code": Path(__file__).resolve(),
        "census_verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_eligible_universe_prediction_census.py"
        ),
    }
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")
    hashes = {name: sha256(path) for name, path in paths.items()}
    prior_merge = json.loads(
        paths["prior_all50_merge_manifest"].read_text(encoding="utf-8")
    )
    if prior_merge.get("artifact_type") != "rq2_post_profile_cwe_all50_merge_manifest_v3":
        raise ValueError("unexpected prior all-50 merge manifest")
    prior_consensus = prior_merge.get("outputs", {}).get("consensus") or {}
    if prior_consensus != {
        "path": str(paths["prior_all50_consensus"]),
        "sha256": hashes["prior_all50_consensus"],
    }:
        raise ValueError("prior all-50 consensus is not bound by its merge manifest")

    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    worklist_e = output_dir / "worklist_e.blind.jsonl"
    worklist_f = output_dir / "worklist_f.blind.jsonl"
    source_path = output_dir / "source_rows.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    reviewer_outputs = {
        "reviewer_e": output_dir / "reviewer_e.jsonl",
        "reviewer_f": output_dir / "reviewer_f.jsonl",
        "requests_e": output_dir / "reviewer_e.requests.jsonl",
        "requests_f": output_dir / "reviewer_f.requests.jsonl",
    }
    protected = (source_path, worklist_e, worklist_f, manifest_path, *reviewer_outputs.values())
    existing = [str(path) for path in protected if path.exists()]
    if existing:
        raise ValueError(f"refusing to overwrite sealed/reviewer artifacts: {existing}")

    differences = select_cwe_differences(list(iter_jsonl(paths["difference_rows"])))
    prior_cves = {row["cve_id"] for row in iter_jsonl(paths["prior_all50_consensus"])}
    overlap_cves = sorted(row["cve_id"] for row in differences if row["cve_id"] in prior_cves)
    if len(overlap_cves) != 3:
        raise ValueError(f"expected three prior all-50 overlaps, found {len(overlap_cves)}")
    field_records = list(iter_jsonl(paths["parent_field_views"]))
    for line_number, row in enumerate(field_records, start=1):
        row["_source_line_number"] = line_number
    field_rows = unique_by_cve(field_records, "field views")
    aligned = unique_by_cve(iter_jsonl(paths["parent_aligned"]), "aligned")
    if any(row["cve_id"] not in field_rows or row["cve_id"] not in aligned for row in differences):
        raise ValueError("CWE difference is absent from parent sources")
    catalog = CweCatalog(paths["cwe_xml_zip"])
    source_rows = build_sources(differences, field_rows, aligned, catalog)

    cache_dir.mkdir(parents=True, exist_ok=True)
    fetch_config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=MAX_BYTES,
        max_text_chars=MAX_TEXT_CHARS,
        sleep_seconds=0.2,
        refresh=args.refresh,
    )
    blind_rows = []
    status_counts = Counter()
    for index, source in enumerate(source_rows, start=1):
        row, counts = build_row(index, source, catalog, cache_dir, fetch_config)
        row["review_id"] = f"rq2_post_profile_cwe_eligible_diff_v1:{index:03d}"
        if row["deterministic_set_relation"] != "disjoint":
            raise ValueError(f"{source['cve_id']}: expected disjoint set relation")
        leaked = recursive_keys(row) & FORBIDDEN_KEYS
        if leaked:
            raise ValueError(f"blind row leaks forbidden keys: {sorted(leaked)}")
        blind_rows.append(row)
        status_counts.update(counts)

    cache_files = {}
    for row in blind_rows:
        for record in row["evidence_context"]["records"]:
            path = cache_path_for_url(cache_dir, record["fetch_url"])
            if not path.is_file():
                raise FileNotFoundError(f"missing evidence cache file: {path}")
            cache_files[str(path)] = sha256(path)
    for name, path in paths.items():
        if sha256(path) != hashes[name]:
            raise ValueError(f"input changed during build: {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(source_path, source_rows)
    write_jsonl(worklist_e, blind_rows)
    write_jsonl(worklist_f, list(reversed(blind_rows)))
    execution = codex_cli_contract(
        args.codex_cli_path, args.model, args.reasoning_effort
    )
    execution.update(
        {
            "batch_size": 5,
            "schedule": "input",
            "ephemeral_session_per_batch": True,
        }
    )
    manifest = {
        "artifact_type": (
            "rq2_post_profile_eligible_universe_cwe_difference_evidence_manifest_v1"
        ),
        "sealed_at_ns": time.time_ns(),
        "row_count": EXPECTED_ROWS,
        "selection": {
            "complete_eligible_universe_cwe_profile_difference_set": True,
            "selected_after_prediction_census_revealed": True,
            "selected_after_prior_reviews_revealed": True,
            "sampling_performed": False,
            "unique_cves": EXPECTED_ROWS,
            "current_prediction": "factual_conflict",
            "candidate_prediction": "representation_discrepancy",
            "profile_values_hidden_from_reviewers": True,
            "selection_reason_hidden_from_reviewers": True,
            "selection_blinding_complete": False,
            "overlap_with_prior_all50_rows": len(overlap_cves),
            "prior_all50_overlap_cves": overlap_cves,
        },
        "evidence": {
            "max_references_per_row": 3,
            "max_bytes": MAX_BYTES,
            "max_text_chars": MAX_TEXT_CHARS,
            "timeout_seconds": args.timeout_seconds,
            "refresh": args.refresh,
            "fetch_status_counts": dict(sorted(status_counts.items())),
            "cache_files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(cache_files.items())
            ],
            "evidence_availability_does_not_change_selection": True,
            "live_lookup_during_review_allowed": False,
        },
        "claim_boundary": {
            "uses_any_labels": True,
            "uses_human_labels": False,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_absolute_accuracy_claim": False,
            "eligible_for_confirmatory_gain_claim": False,
            "eligible_for_temporal_generalization_claim": False,
            "eligible_for_preregistered_power_claim": False,
            "candidate_promotion_allowed": False,
            "production_default_changed": False,
            "sealed_250_row_evaluation_changed": False,
            "real_person_review_requirement_reduced": False,
        },
        "reviewer_outputs_absent_at_seal": True,
        "execution": execution,
        "inputs": {
            name: {"path": str(path), "sha256": hashes[name]}
            for name, path in paths.items()
        },
        "outputs": {
            "source_rows": {"path": str(source_path), "sha256": sha256(source_path)}
        },
        "worklists": {
            "reviewer_e": {
                "path": str(worklist_e),
                "sha256": sha256(worklist_e),
                "order": "sample_id_sorted",
                "reasoning_order": "set_then_taxonomy_then_mechanism",
            },
            "reviewer_f": {
                "path": str(worklist_f),
                "sha256": sha256(worklist_f),
                "order": "exact_reverse",
                "reasoning_order": "mechanism_then_taxonomy_then_set",
            },
        },
        "reviewer_outputs": {name: str(path) for name, path in reviewer_outputs.items()},
        "cautions": [
            "All rows are selected after the complete prediction census was revealed.",
            "Every row exposes the taxonomy relation, so selection blinding is incomplete.",
            "Both reviewers are non-human Codex runs from one model family.",
            "The three prior all-50 rows are repeat same-model stability observations.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Sealed eligible-universe CWE difference evidence: "
        f"rows=29 evidence={sum(status_counts.values())} "
        f"statuses={dict(sorted(status_counts.items()))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
