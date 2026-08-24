#!/usr/bin/env python3
"""Independently verify the post-profile all-50 CWE evidence result."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_all50_evidence_v3/manifest.sealed.json"
)
DEFAULT_MERGE = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_all50_evidence_v3/merge_manifest.json"
)
FORBIDDEN_KEYS = {
    "candidate",
    "consensus_label",
    "current",
    "current_prediction",
    "cwe_taxonomy_v1",
    "gold_label",
    "profile_difference",
    "profile_prediction",
    "reviewer_a",
    "reviewer_b",
    "strict_consensus",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--merge-manifest", default=DEFAULT_MERGE)
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


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key for child in value.values() for key in recursive_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in recursive_keys(child)}
    return set()


def expected_relation(nvd: list[str], ghsa: list[str]) -> str:
    left, right = set(nvd), set(ghsa)
    if left == right:
        return "exact_set"
    if left < right or right < left:
        return "literal_strict_subset"
    if left & right:
        return "overlap_non_subset"
    return "disjoint"


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    merge_path = resolve(args.merge_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    merge = json.loads(merge_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_cwe_all50_evidence_manifest_v3":
        raise ValueError("unexpected all-50 sealed manifest")
    if merge.get("artifact_type") != "rq2_post_profile_cwe_all50_merge_manifest_v3":
        raise ValueError("unexpected all-50 merge manifest")
    selection = manifest.get("selection") or {}
    if selection.get("supersedes_failed_v1_fixed_subset_contract_attempt") is not True:
        raise ValueError("v3 does not bind the failed fixed-subset attempt")
    if selection.get("supersedes_failed_v2_literal_evidence_contract_attempt") is not True:
        raise ValueError("v3 does not bind the failed literal-evidence attempt")
    if merge["source_manifest"] != {"path": str(manifest_path), "sha256": sha256(manifest_path)}:
        raise ValueError("merge is not bound to the sealed all-50 manifest")
    for entry in manifest["inputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise ValueError(f"sealed input hash mismatch: {path}")
    for entry in merge["inputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise ValueError(f"merge input hash mismatch: {path}")
    for entry in merge["outputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise ValueError(f"merge output hash mismatch: {path}")

    worklist_e = Path(manifest["worklists"]["reviewer_e"]["path"])
    worklist_f = Path(manifest["worklists"]["reviewer_f"]["path"])
    rows_e = list(iter_jsonl(worklist_e))
    rows_f = list(iter_jsonl(worklist_f))
    if len(rows_e) != 50 or [row["review_id"] for row in rows_f] != list(
        reversed([row["review_id"] for row in rows_e])
    ):
        raise ValueError("all-50 worklist count/order mismatch")
    if len({row["original_sample_id"] for row in rows_e}) != 50:
        raise ValueError("all-50 worklist sample IDs are not unique")
    for row in rows_e:
        leaked = recursive_keys(row) & FORBIDDEN_KEYS
        if leaked:
            raise ValueError(f"blind worklist leaks profile/reviewer keys: {sorted(leaked)}")
        if row["deterministic_set_relation"] != expected_relation(
            row["nvd_value"], row["ghsa_value"]
        ):
            raise ValueError(f"set relation mismatch: {row['review_id']}")
    relation_counts = Counter(row["deterministic_set_relation"] for row in rows_e)
    if dict(sorted(relation_counts.items())) != manifest["set_relation_counts"]:
        raise ValueError("set relation counts differ from sealed manifest")

    source_rows = list(iter_jsonl(Path(manifest["inputs"]["source_rows"]["path"])))
    source_cwe_ids = [row["sample_id"] for row in source_rows if row["field"] == "cwe_ids"]
    if [row["original_sample_id"] for row in rows_e] != source_cwe_ids:
        raise ValueError("all-50 worklist is not the full CWE source projection")
    predictions = {
        row["sample_id"]: row
        for row in iter_jsonl(Path(manifest["inputs"]["predictions"]["path"]))
    }
    actual_difference_ids = {
        sample_id
        for sample_id in source_cwe_ids
        if predictions[sample_id]["current"] != predictions[sample_id]["cwe_taxonomy_v1"]
    }
    sealed_difference_ids = {
        row["sample_id"] for row in manifest["selection"]["profile_difference_rows"]
    }
    if actual_difference_ids != sealed_difference_ids or len(actual_difference_ids) != 3:
        raise ValueError("hidden profile-difference binding mismatch")

    summary = json.loads(Path(merge["outputs"]["summary"]["path"]).read_text(encoding="utf-8"))
    consensus = list(iter_jsonl(Path(merge["outputs"]["consensus"]["path"])))
    if len(consensus) != 50 or summary["rows"] != 50:
        raise ValueError("all-50 consensus row count mismatch")
    if {row["original_sample_id"] for row in consensus if row["profile_difference"]} != actual_difference_ids:
        raise ValueError("consensus profile-difference rows mismatch")
    strict_rows = sum(row["strict_consensus"] for row in consensus)
    current = sum(
        row["strict_consensus"] and row["consensus_label"] == row["current_prediction"]
        for row in consensus
    )
    candidate = sum(
        row["strict_consensus"] and row["consensus_label"] == row["candidate_prediction"]
        for row in consensus
    )
    difference = [row for row in consensus if row["profile_difference"]]
    recomputed = {
        "strict_rows": strict_rows,
        "current_agreement_strict": current,
        "candidate_agreement_strict": candidate,
        "profile_agreement_difference_strict": candidate - current,
        "difference_rows_total": len(difference),
        "difference_strict_rows": sum(row["strict_consensus"] for row in difference),
        "candidate_direction_strict_rows": sum(
            row["profile_direction"] == "candidate" for row in difference
        ),
        "current_direction_strict_rows": sum(
            row["profile_direction"] == "current" for row in difference
        ),
        "neither_direction_strict_rows": sum(
            row["profile_direction"] == "neither" for row in difference
        ),
        "difference_unresolved_rows": sum(
            row["profile_direction"] == "unresolved" for row in difference
        ),
    }
    for key, value in recomputed.items():
        if summary.get(key) != value:
            raise ValueError(f"summary mismatch for {key}: {summary.get(key)} != {value}")
    required_false = (
        "label_is_human",
        "eligible_for_human_gold_claim",
        "eligible_for_confirmatory_method_gain_claim",
        "strict_event_time_claim_allowed",
        "candidate_promotion_allowed",
        "production_default_changed",
        "sealed_250_row_evaluation_changed",
    )
    if any(summary.get(key) is not False for key in required_false):
        raise ValueError("all-50 summary claim boundary drift")
    evaluation = json.loads(
        Path(manifest["inputs"]["profile_evaluation"]["path"]).read_text(encoding="utf-8")
    )
    if evaluation["methods"]["current"]["agreement_count"] != 185:
        raise ValueError("sealed main current count changed")
    if evaluation["methods"]["cwe_taxonomy_v1"]["agreement_count"] != 186:
        raise ValueError("sealed main candidate count changed")
    if evaluation["paired_profile_comparisons"]["cwe_taxonomy_v1"]["prediction_difference_rows"] != 3:
        raise ValueError("sealed main profile-difference count changed")
    print(
        "Verified post-profile CWE all-50 evidence result: "
        f"rows=50 strict={strict_rows} current={current} candidate={candidate} "
        f"difference_candidate={recomputed['candidate_direction_strict_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
