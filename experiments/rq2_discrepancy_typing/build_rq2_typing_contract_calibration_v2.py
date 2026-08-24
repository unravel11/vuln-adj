#!/usr/bin/env python3
"""Build a disjoint RQ2 construct calibration for the v2 refined contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from pathlib import Path

import analyze_rq2_typing_contract_calibration_failures as failure_analysis
import analyze_rq2_typing_holdout_failure_modes as failure_modes
import build_rq2_typing_contract_calibration as v1


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = v1.DEFAULT_SOURCE
DEFAULT_CONSENSUS = v1.DEFAULT_CONSENSUS
DEFAULT_V1_SOURCE = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v1/source_rows.jsonl"
)
DEFAULT_PROMPT = "docs/prompts/rq2_typing_contract_calibration_v2.md"
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v2"
)
SCHEMA_VERSION = "rq2_typing_contract_calibration_v2"
ARTIFACT_TYPE = "rq2_typing_contract_calibration_v2_manifest"
SELECTION_SEED = "rq2-typing-contract-calibration-v2"
STRATUM_TARGETS = {
    "severity_same_cvss_version_different_vector": 8,
    "severity_cross_cvss_version_different_vector": 6,
    "affected_same_normalized_range_package_mismatch": 8,
    "affected_singleton_vs_interval": 7,
    "affected_prerelease_boundary": 3,
    "severity_exact_or_prefix_one_missing_score_repeat": 5,
    "affected_one_sided_unbounded_repeat": 5,
}
EXPECTED_CALIBRATION_ROWS = sum(STRATUM_TARGETS.values())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--v1-source", default=DEFAULT_V1_SOURCE)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--review-backend", choices=["openai", "codex-cli"], default="codex-cli")
    parser.add_argument("--review-model", default="gpt-5.5")
    parser.add_argument("--review-max-output-tokens", type=int, default=512)
    parser.add_argument("--codex-cli-path", default="codex")
    parser.add_argument(
        "--codex-reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default="medium",
    )
    return parser.parse_args()


def rank_key(stratum: str, sample_id: str) -> str:
    return hashlib.sha256(
        f"{SELECTION_SEED}:{stratum}:{sample_id}".encode("utf-8")
    ).hexdigest()


def normalized_range_signature(values: object) -> tuple:
    if not isinstance(values, list):
        return ()
    records = []
    for value in values:
        if not isinstance(value, dict):
            return ()
        version = value.get("version")
        if version in {None, "", "*", "-"}:
            version = None
        records.append(
            (
                value.get("version_start_including") or value.get("introduced"),
                value.get("version_end_excluding") or value.get("fixed"),
                value.get("version_start_excluding"),
                value.get("version_end_including"),
                version,
                bool(value.get("vulnerable", True)),
            )
        )
    return tuple(sorted(records, key=repr))


def classify(row: dict) -> str | None:
    if row.get("field") == "severity":
        left = row.get("nvd_value")
        right = row.get("ghsa_value")
        if (
            failure_modes.canonical_severity(left)
            != failure_modes.canonical_severity(right)
            or failure_modes.score_relation(left, right) != "one_missing"
        ):
            return None
        relation = failure_modes.vector_relation(left, right)
        if relation in {"exact", "strict_prefix"}:
            return "severity_exact_or_prefix_one_missing_score_repeat"
        if relation != "different":
            return None
        left_version = failure_analysis.cvss_version(left)
        right_version = failure_analysis.cvss_version(right)
        if not left_version or not right_version:
            return None
        return (
            "severity_same_cvss_version_different_vector"
            if left_version == right_version
            else "severity_cross_cvss_version_different_vector"
        )

    if row.get("field") != "affected_versions":
        return None
    left = row.get("nvd_value")
    right = row.get("ghsa_value")
    if (
        row.get("baseline_status") == "equivalent"
        and bool(left) != bool(right)
        and (
            failure_modes.is_unbounded_affected_claim(left)
            or failure_modes.is_unbounded_affected_claim(right)
        )
    ):
        return "affected_one_sided_unbounded_repeat"
    if not left or not right:
        return None
    if failure_analysis.has_prerelease_token([left, right]):
        return "affected_prerelease_boundary"
    if (
        failure_analysis.concrete_singletons(left)
        and failure_analysis.contains_range(right)
    ) or (
        failure_analysis.concrete_singletons(right)
        and failure_analysis.contains_range(left)
    ):
        return "affected_singleton_vs_interval"
    if (
        normalized_range_signature(left)
        and normalized_range_signature(left) == normalized_range_signature(right)
        and set(row.get("package_names", {}).get("nvd") or [])
        != set(row.get("package_names", {}).get("ghsa") or [])
    ):
        return "affected_same_normalized_range_package_mismatch"
    return None


def select_rows(
    source_rows: list[dict],
    consensus_rows: list[dict],
    excluded_ids: set[str],
) -> list[dict]:
    if len(source_rows) != v1.EXPECTED_SOURCE_ROWS or len(consensus_rows) != v1.EXPECTED_SOURCE_ROWS:
        raise ValueError(f"expected {v1.EXPECTED_SOURCE_ROWS} source and consensus rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    consensus_ids = [row.get("sample_id") for row in consensus_rows]
    if source_ids != consensus_ids or len(set(source_ids)) != v1.EXPECTED_SOURCE_ROWS:
        raise ValueError("source and consensus IDs must be unique and ordered identically")
    pools = {stratum: [] for stratum in STRATUM_TARGETS}
    for row, consensus in zip(source_rows, consensus_rows):
        if row["sample_id"] in excluded_ids or not consensus.get("strict_consensus"):
            continue
        stratum = classify(row)
        if stratum:
            pools[stratum].append((row, consensus))

    selected = []
    for stratum, target in STRATUM_TARGETS.items():
        pool = sorted(
            pools[stratum], key=lambda item: rank_key(stratum, item[0]["sample_id"])
        )
        if len(pool) < target:
            raise ValueError(f"v2 stratum {stratum} has {len(pool)} rows; needs {target}")
        for row, consensus in pool[:target]:
            selected.append(
                {
                    **row,
                    "calibration_stratum": stratum,
                    "prior_non_human_consensus_label": consensus["consensus_label"],
                    "selection_uses_non_human_consensus": True,
                }
            )
    selected.sort(key=lambda row: (
        row["calibration_stratum"], rank_key(row["calibration_stratum"], row["sample_id"])
    ))
    if len(selected) != EXPECTED_CALIBRATION_ROWS:
        raise AssertionError("unexpected v2 calibration row count")
    if len({row["sample_id"] for row in selected}) != len(selected):
        raise ValueError("v2 calibration selection contains duplicate sample IDs")
    return selected


def main() -> int:
    args = parse_args()
    source_path = v1.resolve(args.source)
    consensus_path = v1.resolve(args.consensus)
    v1_source_path = v1.resolve(args.v1_source)
    prompt_path = v1.resolve(args.prompt)
    output_dir = v1.resolve(args.output_dir)
    if args.review_max_output_tokens < 1:
        raise ValueError("--review-max-output-tokens must be positive")
    review_execution = (
        v1.holdout.codex_cli_contract(
            args.codex_cli_path, args.review_model, args.codex_reasoning_effort
        )
        if args.review_backend == "codex-cli"
        else v1.holdout.openai_contract(args.review_model, args.review_max_output_tokens)
    )
    paths = {
        "source_rows": output_dir / "source_rows.jsonl",
        "blind_worklist_a": output_dir / "blind" / "worklist_a.blind.jsonl",
        "blind_worklist_b": output_dir / "blind" / "worklist_b.blind.jsonl",
        "manifest": output_dir / "manifest.sealed.json",
        "reviewer_a": output_dir / "reviewer_a.jsonl",
        "reviewer_b": output_dir / "reviewer_b.jsonl",
    }
    existing = [path for path in paths.values() if path.exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite v2 calibration artifacts: {existing}")
    excluded_ids = {row["sample_id"] for row in v1.iter_jsonl(v1_source_path)}
    selected = select_rows(
        list(v1.iter_jsonl(source_path)),
        list(v1.iter_jsonl(consensus_path)),
        excluded_ids,
    )
    blind_a = [v1.holdout.blind_row(row) for row in selected]
    blind_b = list(reversed(blind_a))
    output_dir.mkdir(parents=True, exist_ok=False)
    paths["blind_worklist_a"].parent.mkdir(parents=True, exist_ok=False)
    v1.write_jsonl(paths["source_rows"], selected)
    v1.write_jsonl(paths["blind_worklist_a"], blind_a)
    v1.write_jsonl(paths["blind_worklist_b"], blind_b)

    inputs = {
        "source": source_path,
        "consensus": consensus_path,
        "v1_source": v1_source_path,
        "prompt": prompt_path,
    }
    outputs = {
        "source_rows": paths["source_rows"],
        "blind_worklist_a": paths["blind_worklist_a"],
        "blind_worklist_b": paths["blind_worklist_b"],
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "sealed_at_ns": time.time_ns(),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_calibration_only": True,
        "disjoint_from_v1": True,
        "selection_uses_non_human_consensus": True,
        "valid_for_confirmatory_performance_claim": False,
        "selected_rows": len(selected),
        "selected_unique_cves": len({row["cve_id"] for row in selected}),
        "excluded_v1_sample_ids": len(excluded_ids),
        "selection_seed": SELECTION_SEED,
        "stratum_targets": STRATUM_TARGETS,
        "stratum_counts": dict(sorted(Counter(
            row["calibration_stratum"] for row in selected
        ).items())),
        "inputs": {
            name: {"path": str(path), "sha256": v1.sha256(path)}
            for name, path in inputs.items()
        },
        "outputs": {
            name: {"path": str(path), "sha256": v1.sha256(path)}
            for name, path in outputs.items()
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": args.review_backend,
            "execution_contract": review_execution,
            "reviewer_a_pass_id": "rq2_contract_calibration_v2_reviewer_a",
            "reviewer_b_pass_id": "rq2_contract_calibration_v2_reviewer_b",
            "reviewer_a_output": str(paths["reviewer_a"]),
            "reviewer_b_output": str(paths["reviewer_b"]),
            "same_prompt_and_raw_values_for_both_reviewers": True,
            "reviewer_b_order": "exact_reverse_of_a",
        },
    }
    paths["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {paths['manifest']}")
    print(f"Calibration rows={len(selected)} strata={manifest['stratum_counts']}")
    print("Boundary: disjoint non-human development calibration; no human gold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
