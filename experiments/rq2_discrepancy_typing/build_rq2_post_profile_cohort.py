#!/usr/bin/env python3
"""Freeze a label-free snapshot-external RQ2 cohort and candidate predictions."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for directory in (Path(__file__).resolve().parent, SCRIPTS_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from analyze_cwe_taxonomy_variants import (  # noqa: E402
    CweCatalog,
    relation_profile,
    taxonomy_v1_status,
)
from build_field_discrepancies import compare_references  # noqa: E402
from build_rq2_typing_holdout import (  # noqa: E402
    FIELDS,
    LABELS,
    atomic_write_text,
    blind_row,
    codex_cli_contract,
    hybrid_stratum_quotas,
    iter_jsonl,
    openai_contract,
    prediction_row,
    rank_key,
    select_globally_unique_strata,
    sha256,
    source_row,
    unique_by_cve,
    write_jsonl,
)
from verify_rq2_post_profile_snapshot import validate as verify_acquisition  # noqa: E402


SCHEMA_VERSION = "rq2_post_profile_snapshot_cohort_v1"
DEFAULT_ACQUISITION_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/acquisition/manifest.json"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/rq2_post_profile_snapshot_cohort_contract_v1.md"
)
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_PROMPT = "docs/prompts/rq2_typing_holdout_review.md"
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_SEED = "rq2_post_profile_snapshot_v1_20260719"
BOUNDARY = {
    "selected_tier": "snapshot_external",
    "strict_event_time_claim_allowed": False,
    "snapshot_external_is_time_confirmatory": False,
    "selection_uses_reviewer_outputs": False,
    "selection_uses_candidate_predictions": False,
    "contains_annotations": False,
    "contains_human_labels": False,
    "label_is_human": False,
    "eligible_for_human_gold_claim": False,
    "production_switch_allowed": False,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquisition-manifest", default=DEFAULT_ACQUISITION_MANIFEST)
    parser.add_argument("--cohort-contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument(
        "--review-backend", choices=["openai", "codex-cli"], default="codex-cli"
    )
    parser.add_argument("--review-model", default="gpt-5.5")
    parser.add_argument("--review-max-output-tokens", type=int, default=512)
    parser.add_argument("--codex-cli-path", default="codex")
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default="medium",
    )
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def acquisition_path(manifest: dict, section: str, name: str) -> Path:
    return resolve(manifest[section][name]["path"])


def single_ghsa_rows(rows) -> list[dict]:
    return [row for row in rows if len(row.get("ghsa") or []) == 1]


def eligible_cves(
    aligned: dict[str, dict],
    old_cves: set[str],
    tier: str,
    profile_freeze: datetime,
) -> set[str]:
    eligible = set()
    for cve_id, row in aligned.items():
        if cve_id in old_cves or len(row.get("ghsa") or []) != 1:
            continue
        if tier == "snapshot_external":
            if cve_id.startswith("CVE-2026-"):
                eligible.add(cve_id)
            continue
        if tier != "strict_event_time":
            raise ValueError(f"unsupported selected tier: {tier}")
        nvd_time = parse_time((row.get("nvd") or {}).get("published"))
        ghsa_time = parse_time(row["ghsa"][0].get("published"))
        if (
            nvd_time
            and ghsa_time
            and nvd_time > profile_freeze
            and ghsa_time > profile_freeze
        ):
            eligible.add(cve_id)
    return eligible


def profile_predictions(
    source_rows: list[dict],
    aligned: dict[str, dict],
    catalog: CweCatalog,
) -> list[dict]:
    original_reference_changes: dict[str, str] = {}
    audited_reference_changes: dict[str, str] = {}
    cwe_changes: dict[str, str] = {}
    for row in source_rows:
        cve_id = row["cve_id"]
        aligned_row = aligned[cve_id]
        nvd = aligned_row.get("nvd") or {}
        ghsa_rows = aligned_row.get("ghsa") or []
        if len(ghsa_rows) != 1:
            raise ValueError(f"{cve_id}: expected exactly one reviewed GHSA record")
        current = row["baseline_status"]
        if row["field"] == "references":
            original = compare_references(
                nvd,
                ghsa_rows[0],
                normalization_profile="resource_identity_v1",
            )["status"]
            audited = compare_references(
                nvd,
                ghsa_rows[0],
                normalization_profile="resource_identity_audited_v1",
            )["status"]
            if original != current:
                original_reference_changes[cve_id] = original
            if audited != current:
                audited_reference_changes[cve_id] = audited
        elif row["field"] == "cwe_ids":
            profile = relation_profile(
                list(row.get("nvd_value") or []),
                list(row.get("ghsa_value") or []),
                catalog,
            )
            candidate = taxonomy_v1_status(current, profile)
            if candidate != current:
                cwe_changes[cve_id] = candidate
    return [
        prediction_row(
            row,
            original_reference_changes,
            audited_reference_changes,
            cwe_changes,
        )
        for row in source_rows
    ]


def selected_profile_difference_counts(predictions: list[dict]) -> dict:
    profiles = (
        "reference_resource_identity_original_v1",
        "reference_resource_identity_audited_v1",
        "cwe_taxonomy_v1",
        "combined_original_v1",
        "combined_audited_v1",
    )
    return {
        profile: sum(row[profile] != row["current"] for row in predictions)
        for profile in profiles
    }


def assert_frozen_profile_bindings(paths: dict[str, Path], profile_seal: dict) -> None:
    expected = profile_seal.get("inputs") or {}
    for local_name, sealed_name in (
        ("field_predictor", "field_predictor"),
        ("cwe_xml_zip", "cwe_xml_zip"),
        ("prompt", "prompt"),
    ):
        sealed = expected.get(sealed_name) or {}
        if sha256(paths[local_name]) != sealed.get("sha256"):
            raise ValueError(f"frozen profile binding drift: {local_name}")


def main() -> int:
    args = parse_args()
    if args.review_max_output_tokens < 1:
        raise ValueError("--review-max-output-tokens must be positive")

    acquisition_manifest_path = resolve(args.acquisition_manifest)
    acquisition_manifest = json.loads(
        acquisition_manifest_path.read_text(encoding="utf-8")
    )
    verify_acquisition(acquisition_manifest)
    acquisition_analysis_path = acquisition_path(
        acquisition_manifest, "outputs", "analysis"
    )
    acquisition_analysis = json.loads(
        acquisition_analysis_path.read_text(encoding="utf-8")
    )
    availability = acquisition_analysis["availability"]
    selected_tier = availability["selected_tier_for_next_stage"]
    rows_per_field = int(availability["selected_rows_per_field"])
    if selected_tier != BOUNDARY["selected_tier"]:
        raise ValueError(f"contract expects snapshot_external, found {selected_tier}")
    if rows_per_field != 50 or availability["strict_event_time_unique_cves"] != 0:
        raise ValueError("acquisition availability differs from the frozen cohort contract")

    paths = {
        "acquisition_manifest": acquisition_manifest_path,
        "acquisition_analysis": acquisition_analysis_path,
        "field_views": acquisition_path(acquisition_manifest, "inputs", "field_views"),
        "aligned": acquisition_path(acquisition_manifest, "inputs", "aligned"),
        "old_aligned": acquisition_path(acquisition_manifest, "inputs", "old_aligned"),
        "profile_seal": acquisition_path(acquisition_manifest, "inputs", "profile_seal"),
        "cohort_contract": resolve(args.cohort_contract),
        "cwe_xml_zip": resolve(args.cwe_xml_zip),
        "prompt": resolve(args.prompt),
        "field_predictor": resolve("scripts/build_field_discrepancies.py"),
        "cwe_predictor": resolve(
            "experiments/rq2_discrepancy_typing/analyze_cwe_taxonomy_variants.py"
        ),
        "sampling_helper": resolve(
            "experiments/rq2_discrepancy_typing/build_rq2_typing_holdout.py"
        ),
        "builder": Path(__file__).resolve(),
        "runner": resolve("scripts/run_expert_candidate_annotation.py"),
    }
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")
    profile_seal = json.loads(paths["profile_seal"].read_text(encoding="utf-8"))
    assert_frozen_profile_bindings(paths, profile_seal)
    input_hashes = {name: sha256(path) for name, path in paths.items()}

    review_execution = (
        codex_cli_contract(
            args.codex_cli_path,
            args.review_model,
            args.codex_reasoning_effort,
        )
        if args.review_backend == "codex-cli"
        else openai_contract(args.review_model, args.review_max_output_tokens)
    )

    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock_handle = (output_dir / ".build.lock").open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError("another post-profile cohort build is active") from exc

    blind_dir = output_dir / "blind"
    source_path = output_dir / "source_rows.jsonl"
    prediction_path = output_dir / "predictions.sealed.jsonl"
    blind_a_path = blind_dir / "worklist_a.blind.jsonl"
    blind_b_path = blind_dir / "worklist_b.blind.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    reviewer_a = output_dir / "reviewer_a.jsonl"
    reviewer_b = output_dir / "reviewer_b.jsonl"
    request_a = output_dir / "reviewer_a.requests.jsonl"
    request_b = output_dir / "reviewer_b.requests.jsonl"
    if reviewer_a.exists() or reviewer_b.exists() or request_a.exists() or request_b.exists():
        raise FileExistsError("review output exists; the cohort cannot be resealed")
    outputs = [source_path, prediction_path, blind_a_path, blind_b_path, manifest_path]
    if not args.force and any(path.exists() for path in outputs):
        raise FileExistsError("sealed cohort output exists; use --force only before review")

    field_rows = list(iter_jsonl(paths["field_views"], include_line=True))
    field_by_cve = unique_by_cve(field_rows, "post-profile field views")
    aligned_all = unique_by_cve(
        single_ghsa_rows(iter_jsonl(paths["aligned"])),
        "post-profile single-GHSA aligned rows",
    )
    if set(field_by_cve) != set(aligned_all):
        raise ValueError("post-profile aligned and field-view CVE sets differ")
    old_cves = {row["cve_id"] for row in iter_jsonl(paths["old_aligned"])}
    freeze = datetime.fromtimestamp(
        profile_seal["sealed_at_ns"] / 1_000_000_000, timezone.utc
    )
    eligible = eligible_cves(aligned_all, old_cves, selected_tier, freeze)
    expected_eligible = availability[f"{selected_tier}_unique_cves"]
    if len(eligible) != expected_eligible:
        raise ValueError(f"eligible CVE drift: {len(eligible)} != {expected_eligible}")

    ranked_strata: dict[tuple[str, str], list[dict]] = {}
    stratum_quotas: dict[tuple[str, str], int] = {}
    stratum_counts: dict[tuple[str, str], int] = {}
    stratum_manifest = []
    for field in FIELDS:
        strata: dict[str, list[dict]] = defaultdict(list)
        for cve_id in eligible:
            row = field_by_cve[cve_id]
            discrepancy = row["field_discrepancies"].get(field)
            status = (discrepancy or {}).get("status")
            if status not in LABELS:
                raise ValueError(f"{cve_id}: invalid {field} current status {status!r}")
            strata[status].append(row)
        counts = {status: len(rows) for status, rows in strata.items()}
        quotas = hybrid_stratum_quotas(counts, rows_per_field)
        for status in LABELS:
            if status not in quotas:
                continue
            key = (field, status)
            ranked_strata[key] = sorted(
                strata[status],
                key=lambda row: rank_key(args.seed, field, status, row["cve_id"]),
            )
            stratum_quotas[key] = quotas[status]
            stratum_counts[key] = counts[status]
            stratum_manifest.append(
                {
                    "field": field,
                    "baseline_status": status,
                    "eligible_rows": counts[status],
                    "sampled_rows": quotas[status],
                    "design_weight": counts[status] / quotas[status],
                }
            )

    selected_specs = [
        (
            row,
            field,
            status,
            stratum_counts[(field, status)],
            stratum_quotas[(field, status)],
        )
        for row, field, status in select_globally_unique_strata(
            ranked_strata, stratum_quotas
        )
    ]
    selected_specs.sort(
        key=lambda item: rank_key(
            args.seed + ":global", item[1], item[2], item[0]["cve_id"]
        )
    )
    expected_rows = rows_per_field * len(FIELDS)
    if len(selected_specs) != expected_rows:
        raise ValueError(f"expected {expected_rows} rows, selected {len(selected_specs)}")
    if len({item[0]["cve_id"] for item in selected_specs}) != expected_rows:
        raise ValueError("selected CVEs are not globally unique")

    catalog = CweCatalog(paths["cwe_xml_zip"])
    source_rows = [
        source_row(
            row,
            field,
            f"rq2_post_profile_snapshot_v1:{index:03d}",
            count,
            sampled,
            aligned_all[row["cve_id"]],
            catalog,
        )
        for index, (row, field, _status, count, sampled) in enumerate(
            selected_specs, start=1
        )
    ]
    predictions = profile_predictions(source_rows, aligned_all, catalog)
    difference_counts = selected_profile_difference_counts(predictions)
    difference_rows = sum(
        len({value for key, value in row.items() if key not in {"sample_id", "cve_id", "field"}})
        > 1
        for row in predictions
    )

    blind_a = [blind_row(row) for row in source_rows]
    blind_b = list(reversed(blind_a))
    blind_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(source_path, source_rows)
    write_jsonl(prediction_path, predictions)
    write_jsonl(blind_a_path, blind_a)
    write_jsonl(blind_b_path, blind_b)
    for name, path in paths.items():
        if sha256(path) != input_hashes[name]:
            raise ValueError(f"input changed during cohort build: {name}")

    output_map = {
        "source_rows": source_path,
        "predictions": prediction_path,
        "blind_worklist_a": blind_a_path,
        "blind_worklist_b": blind_b_path,
    }
    sealed_at_ns = time.time_ns()
    manifest = {
        "artifact_type": "rq2_post_profile_snapshot_cohort_v1_manifest",
        "schema_version": SCHEMA_VERSION,
        "sealed_at_ns": sealed_at_ns,
        "boundary": BOUNDARY,
        "seed": args.seed,
        "selected_tier": selected_tier,
        "eligible_unique_cves": len(eligible),
        "rows_per_field": rows_per_field,
        "selected_rows": len(source_rows),
        "selected_unique_cves": len({row["cve_id"] for row in source_rows}),
        "field_counts": dict(sorted(Counter(row["field"] for row in source_rows).items())),
        "sampling_algorithm": (
            "70% proportional plus 30% equal audit supplement over non-empty current-"
            "status strata per field; ascending sha256(seed:field:status:cve_id); "
            "deterministic bipartite matching with global CVE uniqueness"
        ),
        "strata": stratum_manifest,
        "prediction_profiles": [
            "current",
            "reference_resource_identity_original_v1",
            "reference_resource_identity_audited_v1",
            "cwe_taxonomy_v1",
            "combined_original_v1",
            "combined_audited_v1",
        ],
        "candidate_profile_comparison_identifiable": difference_rows > 0,
        "candidate_profile_prediction_difference_rows": difference_rows,
        "candidate_profile_prediction_difference_counts": difference_counts,
        "blind_projection": (
            "Raw aligned NVD/GHSA field values plus source summaries, package names, "
            "reference URLs, and individual official CWE entries; no baseline status, "
            "sampling stratum, prediction, prior annotation, or correctness field."
        ),
        "review_outputs_absent_at_seal": True,
        "inputs": {
            name: {"path": str(path), "sha256": input_hashes[name]}
            for name, path in paths.items()
        },
        "outputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in output_map.items()
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": args.review_backend,
            "execution_contract": review_execution,
            "schedule": "input",
            "reviewer_a_pass_id": "rq2_post_profile_snapshot_v1_reviewer_a",
            "reviewer_b_pass_id": "rq2_post_profile_snapshot_v1_reviewer_b",
            "reviewer_a_output": str(reviewer_a),
            "reviewer_b_output": str(reviewer_b),
            "reviewer_a_request_log": str(request_a),
            "reviewer_b_request_log": str(request_b),
            "strict_consensus": (
                "exact non-uncertain label agreement, neither confidence low, and neither "
                "reviewer requests human review"
            ),
        },
        "source_inputs_unchanged_during_build": True,
    }
    atomic_write_text(
        manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )
    print(f"Wrote {source_path}")
    print(f"Wrote {prediction_path}")
    print(f"Wrote {blind_a_path}")
    print(f"Wrote {blind_b_path}")
    print(f"Wrote {manifest_path}")
    print(
        f"Selected tier={selected_tier} rows={len(source_rows)} "
        f"candidate_difference_rows={difference_rows}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
