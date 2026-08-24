#!/usr/bin/env python3
"""Build a sealed dual-review calibration for disputed RQ2 field constructs."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from pathlib import Path

import analyze_rq2_typing_holdout_failure_modes as failure_modes
import build_rq2_typing_holdout as holdout


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = "data/annotations/holdout/rq2_typing_v1/source_rows.jsonl"
DEFAULT_CONSENSUS = "results/holdout/rq2_typing_v1/dual_review_consensus.jsonl"
DEFAULT_PROMPT = "docs/prompts/rq2_typing_holdout_review.md"
DEFAULT_OUTPUT_DIR = (
    "data/annotations/holdout/rq2_typing_v1/contract_calibration_v1"
)
SCHEMA_VERSION = "rq2_typing_contract_calibration_v1"
ARTIFACT_TYPE = "rq2_typing_contract_calibration_v1_manifest"
SELECTION_SEED = "rq2-typing-contract-calibration-v1"
EXPECTED_SOURCE_ROWS = 1250
STRATUM_TARGETS = {
    "severity_exact_vector_one_missing_score": 10,
    "severity_prefix_vector_one_missing_score": 10,
    "severity_different_vector_one_missing_score": 10,
    "severity_missing_vector_one_missing_score": 1,
    "affected_one_sided_unbounded_claim": 10,
    "severity_unchanged_control": 10,
    "affected_versions_unchanged_control": 9,
}
EXPECTED_CALIBRATION_ROWS = sum(STRATUM_TARGETS.values())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
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
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def rank_key(stratum: str, sample_id: str) -> str:
    return hashlib.sha256(
        f"{SELECTION_SEED}:{stratum}:{sample_id}".encode("utf-8")
    ).hexdigest()


def boundary_stratum(row: dict) -> str | None:
    if row.get("field") == "severity":
        left = row.get("nvd_value")
        right = row.get("ghsa_value")
        if (
            failure_modes.canonical_severity(left)
            == failure_modes.canonical_severity(right)
            and failure_modes.score_relation(left, right) == "one_missing"
        ):
            relation = failure_modes.vector_relation(left, right)
            return {
                "exact": "severity_exact_vector_one_missing_score",
                "strict_prefix": "severity_prefix_vector_one_missing_score",
                "different": "severity_different_vector_one_missing_score",
                "one_or_both_missing": "severity_missing_vector_one_missing_score",
            }[relation]
    if (
        row.get("field") == "affected_versions"
        and row.get("baseline_status") == "equivalent"
        and bool(row.get("nvd_value")) != bool(row.get("ghsa_value"))
        and (
            failure_modes.is_unbounded_affected_claim(row.get("nvd_value"))
            or failure_modes.is_unbounded_affected_claim(row.get("ghsa_value"))
        )
    ):
        return "affected_one_sided_unbounded_claim"
    return None


def control_stratum(row: dict, consensus: dict) -> str | None:
    if not consensus.get("strict_consensus"):
        return None
    label = consensus.get("consensus_label")
    candidate, _reason = failure_modes.post_hoc_candidate(row)
    if candidate != row.get("baseline_status") or label != row.get("baseline_status"):
        return None
    if row.get("field") == "severity":
        return "severity_unchanged_control"
    if row.get("field") == "affected_versions":
        return "affected_versions_unchanged_control"
    return None


def select_rows(source_rows: list[dict], consensus_rows: list[dict]) -> list[dict]:
    if len(source_rows) != EXPECTED_SOURCE_ROWS or len(consensus_rows) != EXPECTED_SOURCE_ROWS:
        raise ValueError(f"expected {EXPECTED_SOURCE_ROWS} source and consensus rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    consensus_ids = [row.get("sample_id") for row in consensus_rows]
    if source_ids != consensus_ids or len(set(source_ids)) != EXPECTED_SOURCE_ROWS:
        raise ValueError("source and consensus IDs must be unique and ordered identically")

    pools: dict[str, list[tuple[dict, dict]]] = {
        stratum: [] for stratum in STRATUM_TARGETS
    }
    for row, consensus in zip(source_rows, consensus_rows):
        if not consensus.get("strict_consensus"):
            continue
        stratum = boundary_stratum(row) or control_stratum(row, consensus)
        if stratum:
            pools[stratum].append((row, consensus))

    selected = []
    for stratum, target in STRATUM_TARGETS.items():
        pool = sorted(
            pools[stratum], key=lambda item: rank_key(stratum, item[0]["sample_id"])
        )
        if len(pool) < target:
            raise ValueError(
                f"calibration stratum {stratum} has {len(pool)} rows; needs {target}"
            )
        for row, consensus in pool[:target]:
            selected.append(
                {
                    **row,
                    "calibration_stratum": stratum,
                    "prior_non_human_consensus_label": consensus["consensus_label"],
                    "selection_uses_non_human_consensus": True,
                }
            )
    selected.sort(key=lambda row: (row["calibration_stratum"], rank_key(
        row["calibration_stratum"], row["sample_id"]
    )))
    if len(selected) != EXPECTED_CALIBRATION_ROWS:
        raise AssertionError("unexpected calibration row count")
    if len({row["sample_id"] for row in selected}) != EXPECTED_CALIBRATION_ROWS:
        raise ValueError("calibration selection contains duplicate sample IDs")
    return selected


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    consensus_path = resolve(args.consensus)
    prompt_path = resolve(args.prompt)
    output_dir = resolve(args.output_dir)
    if args.review_max_output_tokens < 1:
        raise ValueError("--review-max-output-tokens must be positive")

    review_execution = (
        holdout.codex_cli_contract(
            args.codex_cli_path, args.review_model, args.codex_reasoning_effort
        )
        if args.review_backend == "codex-cli"
        else holdout.openai_contract(args.review_model, args.review_max_output_tokens)
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
        raise FileExistsError(f"refusing to overwrite calibration artifacts: {existing}")

    selected = select_rows(
        list(iter_jsonl(source_path)), list(iter_jsonl(consensus_path))
    )
    blind_a = [holdout.blind_row(row) for row in selected]
    blind_b = list(reversed(blind_a))
    output_dir.mkdir(parents=True, exist_ok=False)
    paths["blind_worklist_a"].parent.mkdir(parents=True, exist_ok=False)
    write_jsonl(paths["source_rows"], selected)
    write_jsonl(paths["blind_worklist_a"], blind_a)
    write_jsonl(paths["blind_worklist_b"], blind_b)

    inputs = {"source": source_path, "consensus": consensus_path, "prompt": prompt_path}
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
        "selection_uses_non_human_consensus": True,
        "valid_for_confirmatory_performance_claim": False,
        "selected_rows": len(selected),
        "selected_unique_cves": len({row["cve_id"] for row in selected}),
        "selection_seed": SELECTION_SEED,
        "stratum_targets": STRATUM_TARGETS,
        "stratum_counts": dict(sorted(Counter(
            row["calibration_stratum"] for row in selected
        ).items())),
        "blind_projection": (
            "The exact frozen raw source values and contexts from the fresh holdout; "
            "no baseline, prior label, candidate label, or calibration stratum."
        ),
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in inputs.items()
        },
        "outputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in outputs.items()
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": args.review_backend,
            "execution_contract": review_execution,
            "reviewer_a_pass_id": "rq2_contract_calibration_v1_reviewer_a",
            "reviewer_b_pass_id": "rq2_contract_calibration_v1_reviewer_b",
            "reviewer_a_output": str(paths["reviewer_a"]),
            "reviewer_b_output": str(paths["reviewer_b"]),
            "same_prompt_and_raw_values_for_both_reviewers": True,
            "reviewer_b_order": "exact_reverse_of_a",
        },
    }
    paths["manifest"].write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {paths['manifest']}")
    print(f"Calibration rows={len(selected)} strata={manifest['stratum_counts']}")
    print("Boundary: non-human development calibration; human gold remains absent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
