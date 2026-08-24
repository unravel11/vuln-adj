#!/usr/bin/env python3
"""Freeze a blind third-pass worklist for non-strict RQ2 holdout rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rq2_typing_tiebreak_v1"
DEFAULT_BASE_DIR = "data/annotations/holdout/rq2_typing_v1"
DEFAULT_REVIEW_DIR = "results/holdout/rq2_typing_v1"
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/rq2_typing_v1/tiebreak_v1"
RANK_SEED = "rq2_typing_holdout_v1_tiebreak_v1"
EXPECTED_ROWS = 103
EXPECTED_FIELD_COUNTS = {
    "affected_versions": 58,
    "cwe_ids": 21,
    "references": 13,
    "severity": 11,
}
MIN_SELECTED_RESOLUTION = 0.70
MIN_OVERALL_COVERAGE = 0.975


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--review-dir", default=DEFAULT_REVIEW_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def load_unique(path: Path) -> dict[str, dict]:
    result = {}
    for row in load_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in result:
            raise ValueError(f"{path}: missing or duplicate sample_id={sample_id}")
        result[sample_id] = row
    return result


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def rank(sample_id: str) -> str:
    return hashlib.sha256(f"{RANK_SEED}:{sample_id}".encode()).hexdigest()


def select_worklist(blind_rows: dict[str, dict], consensus_rows: list[dict]) -> list[dict]:
    selected_ids = [row["sample_id"] for row in consensus_rows if row.get("strict_consensus") is False]
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("non-strict consensus sample IDs are not unique")
    if set(selected_ids) - set(blind_rows):
        raise ValueError("consensus contains rows absent from the blind worklist")
    return [blind_rows[sample_id] for sample_id in sorted(selected_ids, key=rank)]


def verified_record(record: dict, name: str) -> Path:
    path = Path(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"hash or path mismatch for {name}: {path}")
    return path


def verify_execution_contract(contract: dict) -> None:
    if contract.get("backend") != "codex-cli" or contract.get("api_route") != "codex_cli":
        raise ValueError("tiebreak requires the sealed codex-cli execution contract")
    path = Path(contract["path"])
    if not path.is_file() or sha256(path) != contract.get("sha256"):
        raise ValueError("sealed codex-cli executable hash mismatch")
    observed_version = subprocess.run(
        [str(path), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if observed_version != contract.get("version"):
        raise ValueError(f"codex-cli version drift: {observed_version}")
    expected = {
        "model": "gpt-5.5",
        "reasoning_effort": "medium",
        "max_output_tokens": None,
        "sandbox": "read-only",
        "ephemeral": True,
    }
    drift = {name: (contract.get(name), value) for name, value in expected.items() if contract.get(name) != value}
    if drift:
        raise ValueError(f"execution contract drift: {drift}")


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    review_dir = resolve(args.review_dir)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite sealed tiebreak directory: {output_dir}")

    source_manifest_path = base_dir / "manifest.sealed.json"
    merge_manifest_path = review_dir / "merge_manifest.json"
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    merge_manifest = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if source_manifest.get("artifact_type") != "rq2_typing_holdout_v1_manifest":
        raise ValueError("unexpected source manifest")
    if source_manifest.get("label_is_human") is not False:
        raise ValueError("source holdout must remain non-human")
    if merge_manifest.get("artifact_type") != "rq2_typing_holdout_merge_manifest":
        raise ValueError("unexpected dual-review merge manifest")
    for section in ("inputs", "outputs"):
        for name, record in merge_manifest[section].items():
            verified_record(record, f"merge.{section}.{name}")

    blind_path = Path(source_manifest["outputs"]["blind_worklist_a"]["path"])
    prompt_path = Path(source_manifest["inputs"]["prompt"]["path"])
    predictions_path = Path(source_manifest["outputs"]["predictions"]["path"])
    source_rows_path = Path(source_manifest["outputs"]["source_rows"]["path"])
    consensus_path = Path(merge_manifest["outputs"]["consensus"]["path"])
    reviewer_a_path = Path(source_manifest["review_protocol"]["reviewer_a_output"])
    reviewer_b_path = Path(source_manifest["review_protocol"]["reviewer_b_output"])
    for name, path in {
        "blind": blind_path,
        "prompt": prompt_path,
        "predictions": predictions_path,
        "source_rows": source_rows_path,
        "consensus": consensus_path,
        "reviewer_a": reviewer_a_path,
        "reviewer_b": reviewer_b_path,
    }.items():
        if not path.is_file():
            raise FileNotFoundError(f"{name}: {path}")
    source_records = {
        "blind": source_manifest["outputs"]["blind_worklist_a"],
        "prompt": source_manifest["inputs"]["prompt"],
        "predictions": source_manifest["outputs"]["predictions"],
        "source_rows": source_manifest["outputs"]["source_rows"],
    }
    for name, record in source_records.items():
        verified_record(record, f"source_manifest.{name}")
    if reviewer_a_path != Path(merge_manifest["inputs"]["reviewer_a"]["path"]):
        raise ValueError("reviewer A path differs between source and merge manifests")
    if reviewer_b_path != Path(merge_manifest["inputs"]["reviewer_b"]["path"]):
        raise ValueError("reviewer B path differs between source and merge manifests")
    if consensus_path != Path(merge_manifest["outputs"]["consensus"]["path"]):
        raise ValueError("consensus path differs from the verified merge output")
    runner_path = Path(source_manifest["inputs"]["runner"]["path"])
    if not runner_path.is_file():
        raise FileNotFoundError(runner_path)

    execution = source_manifest["review_protocol"]["execution_contract"]
    verify_execution_contract(execution)
    blind_rows = load_unique(blind_path)
    consensus_rows = load_jsonl(consensus_path)
    worklist = select_worklist(blind_rows, consensus_rows)
    field_counts = dict(sorted(Counter(row["field"] for row in worklist).items()))
    if len(worklist) != EXPECTED_ROWS or field_counts != EXPECTED_FIELD_COUNTS:
        raise ValueError(f"fixed non-strict selection changed: rows={len(worklist)}, fields={field_counts}")
    if any(
        key in row
        for row in worklist
        for key in ("baseline_status", "consensus_label", "reviewer_a", "reviewer_b")
    ):
        raise ValueError("tiebreak worklist leaks a prediction or reviewer field")

    output_dir.mkdir(parents=True, exist_ok=False)
    blind_dir = output_dir / "blind"
    blind_dir.mkdir()
    worklist_path = blind_dir / "worklist_c.blind.jsonl"
    reviewer_c_path = output_dir / "reviewer_c.jsonl"
    requests_path = output_dir / "reviewer_c.requests.jsonl"
    manifest_path = output_dir / "manifest.sealed.json"
    write_jsonl(worklist_path, worklist)
    sealed_at_ns = time.time_ns()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "rq2_typing_tiebreak_manifest",
        "sealed_at_ns": sealed_at_ns,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "development_diagnostic_only": True,
        "post_unsealing": True,
        "selection_uses_reviewer_labels": True,
        "selection_rule": "all and only rows with strict_consensus=false in the sealed A/B merge; order by sha256(seed:sample_id)",
        "selection_seed": RANK_SEED,
        "selected_rows": len(worklist),
        "field_counts": field_counts,
        "thresholds_fixed_before_reviewer_c": {
            "minimum_selected_resolution": MIN_SELECTED_RESOLUTION,
            "minimum_overall_candidate_coverage": MIN_OVERALL_COVERAGE,
        },
        "inputs": {
            "source_manifest": {"path": str(source_manifest_path), "sha256": sha256(source_manifest_path)},
            "dual_merge_manifest": {"path": str(merge_manifest_path), "sha256": sha256(merge_manifest_path)},
            "dual_consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "reviewer_a": {"path": str(reviewer_a_path), "sha256": sha256(reviewer_a_path)},
            "reviewer_b": {"path": str(reviewer_b_path), "sha256": sha256(reviewer_b_path)},
            "source_rows": {"path": str(source_rows_path), "sha256": sha256(source_rows_path)},
            "predictions": {"path": str(predictions_path), "sha256": sha256(predictions_path)},
            "prompt": {"path": str(prompt_path), "sha256": sha256(prompt_path)},
            "runner": {"path": str(runner_path), "sha256": sha256(runner_path)},
            "builder": {"path": str(Path(__file__).resolve()), "sha256": sha256(Path(__file__).resolve())},
        },
        "outputs": {
            "blind_worklist_c": {"path": str(worklist_path), "sha256": sha256(worklist_path)},
            "reviewer_c": str(reviewer_c_path),
            "reviewer_c_requests": str(requests_path),
        },
        "review_protocol": {
            "runner_contract_mode": "strict",
            "execution_backend": "codex-cli",
            "execution_contract": execution,
            "reviewer_c_pass_id": "rq2_typing_holdout_v1_tiebreak_c",
            "schedule": "input",
            "blindness": "reviewer C receives only original blind row data and the original prompt; no baseline, A/B output, consensus, or selection reason",
            "resolution_rule": "retain original strict A/B rows; otherwise require at least two qualified votes for one determinate label, where qualified means non-uncertain, confidence not low, and needs_human_review=false",
        },
        "boundary": {
            "same_model_family": True,
            "source_runner_sealed_sha256": source_manifest["inputs"]["runner"]["sha256"],
            "current_runner_sha256": sha256(runner_path),
            "source_runner_file_changed_after_original_seal": (
                sha256(runner_path) != source_manifest["inputs"]["runner"]["sha256"]
            ),
            "human_gold_claim_allowed": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
            "confirmatory_claim_allowed": False,
        },
    }
    write_json(manifest_path, manifest)
    print(f"Wrote {worklist_path}")
    print(f"Wrote {manifest_path}")
    print(f"Selected rows={len(worklist)} fields={field_counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
