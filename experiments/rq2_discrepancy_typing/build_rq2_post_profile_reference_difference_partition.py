#!/usr/bin/env python3
"""Seal profile-independent partitions for all five reference differences."""

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

from build_reference_normalization_impact_validation import (  # noqa: E402
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_TEXT_CHARS,
    PROBE_SCHEMA_VERSION,
    cache_path,
    load_or_probe,
)
from build_rq2_typing_holdout import (  # noqa: E402
    codex_cli_contract,
    iter_jsonl,
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
    "rq2_post_profile_reference_difference_partition_contract_v1.md"
)
DEFAULT_PROMPT = (
    "docs/prompts/rq2_post_profile_reference_difference_partition_review_v1.md"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "reference_difference_partition_v2"
)
DEFAULT_CACHE_DIR = (
    "data/evidence_cache/rq2/post_profile_reference_difference_partition_v1/"
    "url_cache"
)
DEFAULT_FAILED_V1_ARCHIVE = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "reference_difference_partition_v1_failed_merge_code_attempt.tar.gz"
)
EXPECTED_ROWS = 5
EXPECTED_AUDITED_DIFFERENCES = 3
EXPECTED_ORIGINAL_ONLY = 2
FORBIDDEN_KEYS = {
    "cve_id",
    "side",
    "sides",
    "nvd",
    "ghsa",
    "current",
    "candidate",
    "profile",
    "profiles",
    "changed_profiles_from_current",
    "combined_audited_v1",
    "combined_original_v1",
    "reference_resource_identity_audited_v1",
    "reference_resource_identity_original_v1",
    "gold_label",
    "label_is_human",
    "correctness",
    "selection_reason",
    "trigger_stage",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census-dir", default=DEFAULT_CENSUS_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=15)
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


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key for child in value.values() for key in recursive_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in recursive_keys(child)}
    return set()


def select_reference_differences(rows: list[dict]) -> list[dict]:
    selected = [row for row in rows if row.get("field") == "references"]
    if len(selected) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} reference differences, found {len(selected)}")
    if len({row.get("cve_id") for row in selected}) != EXPECTED_ROWS:
        raise ValueError("reference difference CVEs are not unique")
    audited = 0
    original_only = 0
    for row in selected:
        if row.get("label_is_human") is not False:
            raise ValueError("prediction row claims human provenance")
        if row.get("current") != "representation_discrepancy":
            raise ValueError(f"{row.get('cve_id')}: current prediction drift")
        if row.get("reference_resource_identity_original_v1") != "incomplete":
            raise ValueError(f"{row.get('cve_id')}: original prediction drift")
        audited_value = row.get("reference_resource_identity_audited_v1")
        if audited_value == "incomplete":
            audited += 1
        elif audited_value == "representation_discrepancy":
            original_only += 1
        else:
            raise ValueError(f"{row.get('cve_id')}: audited prediction drift")
    if audited != EXPECTED_AUDITED_DIFFERENCES or original_only != EXPECTED_ORIGINAL_ONLY:
        raise ValueError("reference difference partition counts drift")
    return sorted(selected, key=lambda row: row["sample_id"])


def raw_urls(record: dict) -> set[str]:
    return {
        str(item["url"])
        for item in record.get("references") or []
        if item.get("url")
    }


def build_mapping(difference: dict, aligned: dict, index: int) -> dict:
    ghsa_rows = aligned.get("ghsa") or []
    if len(ghsa_rows) != 1:
        raise ValueError(f"{difference['cve_id']}: expected one GHSA row")
    nvd_urls = raw_urls(aligned.get("nvd") or {})
    ghsa_urls = raw_urls(ghsa_rows[0])
    urls = sorted(nvd_urls | ghsa_urls)
    if not urls:
        raise ValueError(f"{difference['cve_id']}: empty reference union")
    review_id = f"rq2_reference_partition_v2:{index:03d}"
    members = []
    for member_index, url in enumerate(urls, start=1):
        members.append(
            {
                "member_id": f"{review_id}:m{member_index:02d}",
                "url": url,
                "sides": sorted(
                    side
                    for side, values in (("nvd", nvd_urls), ("ghsa", ghsa_urls))
                    if url in values
                ),
            }
        )
    return {
        "review_id": review_id,
        "original_sample_id": difference["sample_id"],
        "cve_id": difference["cve_id"],
        "field": "references",
        "members": members,
        "predictions": {
            "current": difference["current"],
            "original": difference["reference_resource_identity_original_v1"],
            "audited": difference["reference_resource_identity_audited_v1"],
        },
    }


def blind_row(mapping: dict, probes: dict[str, dict]) -> dict:
    row = {
        "review_id": mapping["review_id"],
        "members": [
            {
                "member_id": member["member_id"],
                "url": member["url"],
                "frozen_probe": probes[member["url"]],
            }
            for member in mapping["members"]
        ],
        "definitions": {
            "underlying_reference_resource_v1": (
                "Same persistent document, advisory, repository artifact, or revision/path."
            ),
            "frozen_http_resource_v1": (
                "Same only with positive common-final, complete-body-hash, or observed stable-ID evidence."
            ),
        },
    }
    leaked = recursive_keys(row) & FORBIDDEN_KEYS
    if leaked:
        raise ValueError(f"blind reference row leaks forbidden keys: {sorted(leaked)}")
    return row


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

    inputs = census_manifest["inputs"]
    outputs = census_manifest["outputs"]
    paths = {
        "census_manifest": census_manifest_path,
        "census_analysis": checked(outputs["analysis"], "census analysis"),
        "difference_rows": checked(outputs["prediction_difference_rows"], "difference rows"),
        "parent_cohort_manifest": checked(inputs["parent_cohort_manifest"], "parent cohort"),
        "parent_field_views": checked(inputs["parent_input_field_views"], "parent field views"),
        "parent_aligned": checked(inputs["parent_input_aligned"], "parent aligned"),
        "audited_profile_manifest": resolve(
            "results/rq2_discrepancy_typing/reference_normalization_audited_profile/"
            "reference_normalization_audited_profile_manifest.json"
        ),
        "audited_profile": resolve(
            "results/rq2_discrepancy_typing/reference_normalization_audited_profile/"
            "reference_normalization_audited_profile.json"
        ),
        "sealed_profile_evaluation": resolve(
            "results/holdout/rq2_post_profile_snapshot_v1/review/profile_evaluation.json"
        ),
        "failed_v1_archive": resolve(DEFAULT_FAILED_V1_ARCHIVE),
        "contract": resolve(args.contract),
        "prompt": resolve(args.prompt),
        "field_comparator_code": resolve("scripts/build_field_discrepancies.py"),
        "variant_code": resolve(
            "experiments/rq2_discrepancy_typing/analyze_reference_normalization_variants.py"
        ),
        "audited_profile_code": resolve(
            "experiments/rq2_discrepancy_typing/analyze_reference_normalization_audited_profile.py"
        ),
        "probe_helper_code": resolve(
            "experiments/rq2_discrepancy_typing/build_reference_normalization_impact_validation.py"
        ),
        "runner_code": resolve(
            "experiments/rq2_discrepancy_typing/run_rq2_post_profile_reference_difference_partition_review.py"
        ),
        "merge_code": resolve(
            "experiments/rq2_discrepancy_typing/merge_rq2_post_profile_reference_difference_partition_reviews.py"
        ),
        "verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/verify_rq2_post_profile_reference_difference_partition_review.py"
        ),
        "builder_code": Path(__file__).resolve(),
        "census_verifier_code": resolve(
            "experiments/rq2_discrepancy_typing/verify_rq2_post_profile_eligible_universe_prediction_census.py"
        ),
    }
    for name, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing {name}: {path}")
    audited_manifest = json.loads(paths["audited_profile_manifest"].read_text(encoding="utf-8"))
    audited_output = audited_manifest.get("outputs", {}).get("json") or {}
    if audited_output != {
        "path": str(paths["audited_profile"]),
        "sha256": sha256(paths["audited_profile"]),
    }:
        raise ValueError("audited profile is not bound by its manifest")
    hashes = {name: sha256(path) for name, path in paths.items()}

    output_dir = resolve(args.output_dir)
    cache_dir = resolve(args.cache_dir)
    mapping_path = output_dir / "author_mapping.jsonl"
    worklist_e = output_dir / "worklist_e.blind.jsonl"
    worklist_f = output_dir / "worklist_f.blind.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    reviewer_outputs = {
        "reviewer_e": output_dir / "reviewer_e.jsonl",
        "reviewer_f": output_dir / "reviewer_f.jsonl",
        "requests_e": output_dir / "reviewer_e.requests.jsonl",
        "requests_f": output_dir / "reviewer_f.requests.jsonl",
    }
    protected = (mapping_path, worklist_e, worklist_f, manifest_path, *reviewer_outputs.values())
    existing = [str(path) for path in protected if path.exists()]
    if existing:
        raise ValueError(f"refusing to overwrite sealed/reviewer artifacts: {existing}")

    differences = select_reference_differences(list(iter_jsonl(paths["difference_rows"])))
    aligned_rows = unique_by_cve(iter_jsonl(paths["parent_aligned"]), "parent aligned")
    if any(row["cve_id"] not in aligned_rows for row in differences):
        raise ValueError("reference difference is absent from parent aligned input")
    mappings = [
        build_mapping(row, aligned_rows[row["cve_id"]], index)
        for index, row in enumerate(differences, start=1)
    ]
    urls = sorted({member["url"] for row in mappings for member in row["members"]})
    cache_dir.mkdir(parents=True, exist_ok=True)
    probes = {}
    cache_hits = 0
    for url in urls:
        record, from_cache = load_or_probe(
            url, cache_dir, args.timeout_seconds, args.refresh
        )
        probes[url] = record
        cache_hits += int(from_cache)
    blind_rows = [blind_row(row, probes) for row in mappings]
    cache_files = [
        {"path": str(cache_path(cache_dir, url)), "sha256": sha256(cache_path(cache_dir, url))}
        for url in urls
    ]
    for name, path in paths.items():
        if sha256(path) != hashes[name]:
            raise ValueError(f"input changed during reference build: {name}")

    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(mapping_path, mappings)
    write_jsonl(worklist_e, blind_rows)
    write_jsonl(worklist_f, list(reversed(blind_rows)))
    execution = codex_cli_contract(
        args.codex_cli_path, args.model, args.reasoning_effort
    )
    execution.update(
        {"batch_size": 5, "schedule": "input", "ephemeral_session_per_batch": True}
    )
    manifest = {
        "artifact_type": "rq2_post_profile_reference_difference_partition_manifest_v2",
        "review_protocol_revision": 2,
        "superseded_v1_excluded": True,
        "protocol_repair_reason": (
            "The v1 merge called a nonexistent runner write_jsonl helper and failed "
            "before writing any consensus or summary artifact."
        ),
        "sealed_at_ns": time.time_ns(),
        "row_count": EXPECTED_ROWS,
        "selection": {
            "complete_reference_profile_difference_union": True,
            "sampling_performed": False,
            "original_difference_rows": EXPECTED_ROWS,
            "audited_difference_rows": EXPECTED_AUDITED_DIFFERENCES,
            "original_only_rows": EXPECTED_ORIGINAL_ONLY,
            "selected_after_prediction_census_revealed": True,
            "profile_values_hidden_from_reviewers": True,
            "source_side_hidden_from_reviewers": True,
            "direct_cve_field_hidden_from_reviewers": True,
            "selection_blinding_complete": False,
            "cve_identifier_blinding_complete": False,
        },
        "evidence": {
            "probe_schema_version": PROBE_SCHEMA_VERSION,
            "unique_urls": len(urls),
            "cache_hits": cache_hits,
            "cache_misses": len(urls) - cache_hits,
            "status_counts": dict(sorted(Counter(row["status"] for row in probes.values()).items())),
            "timeout_seconds": args.timeout_seconds,
            "max_bytes": DEFAULT_MAX_BYTES,
            "max_text_chars": DEFAULT_MAX_TEXT_CHARS,
            "refresh": args.refresh,
            "cache_files": cache_files,
            "live_lookup_during_review_allowed": False,
        },
        "definitions": [
            "underlying_reference_resource_v1",
            "frozen_http_resource_v1",
        ],
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
            "author_mapping": {"path": str(mapping_path), "sha256": sha256(mapping_path)}
        },
        "worklists": {
            "reviewer_e": {"path": str(worklist_e), "sha256": sha256(worklist_e), "order": "sample_id_sorted"},
            "reviewer_f": {"path": str(worklist_f), "sha256": sha256(worklist_f), "order": "exact_reverse"},
        },
        "reviewer_outputs": {name: str(path) for name, path in reviewer_outputs.items()},
        "cautions": [
            "The archived v1 attempt is excluded because its merge code failed before result output.",
            "All five rows were selected after the complete prediction census was revealed.",
            "Raw URLs can reveal CVE identity and the alias structure under test.",
            "Both reviewers are non-human Codex runs from one model family.",
            "The two resource definitions are reported separately and cannot be selected by outcome.",
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Sealed reference difference partitions v2: "
        f"rows={len(mappings)} urls={len(urls)} statuses={manifest['evidence']['status_counts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
