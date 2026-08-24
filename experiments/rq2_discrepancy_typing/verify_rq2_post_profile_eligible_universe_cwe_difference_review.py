#!/usr/bin/env python3
"""Independently verify the 29-row eligible-universe CWE evidence audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_eligible_difference_evidence_v1/manifest.sealed.json"
)
DEFAULT_MERGE = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_eligible_difference_evidence_v1/merge_manifest.json"
)
STRICT_KEYS = (
    "set_relation",
    "discrepancy_label",
    "taxonomy_compatibility",
    "specific_mapping_verdict",
)
FORBIDDEN_KEYS = {
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


def checked(record: dict, name: str) -> Path:
    path = Path(record.get("path", ""))
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


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


def exact_p(candidate: int, current: int) -> float:
    n = candidate + current
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, value) for value in range(min(candidate, current) + 1))
    return min(1.0, 2.0 * tail / (2**n))


def independent_strict(left: dict, right: dict) -> tuple[bool, str | None]:
    exact = all(left[key] == right[key] for key in STRICT_KEYS)
    strict = (
        exact
        and left["discrepancy_label"] != "uncertain"
        and left["confidence"] in {"high", "medium"}
        and right["confidence"] in {"high", "medium"}
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    return strict, left["discrepancy_label"] if strict else None


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    merge_path = resolve(args.merge_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    merge = json.loads(merge_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != (
        "rq2_post_profile_eligible_universe_cwe_difference_evidence_manifest_v1"
    ):
        raise ValueError("unexpected sealed manifest")
    if merge.get("artifact_type") != (
        "rq2_post_profile_eligible_universe_cwe_difference_merge_manifest_v1"
    ):
        raise ValueError("unexpected merge manifest")
    if merge.get("source_manifest") != {
        "path": str(manifest_path),
        "sha256": sha256(manifest_path),
    }:
        raise ValueError("merge is not bound to sealed manifest")
    input_paths = {
        name: checked(record, f"sealed input {name}")
        for name, record in manifest["inputs"].items()
    }
    for name, record in manifest["outputs"].items():
        checked(record, f"sealed output {name}")
    for index, record in enumerate(manifest["evidence"]["cache_files"], start=1):
        checked(record, f"cache file {index}")
    for name, record in merge["inputs"].items():
        checked(record, f"merge input {name}")
    output_paths = {
        name: checked(record, f"merge output {name}")
        for name, record in merge["outputs"].items()
    }

    worklist_e = checked(manifest["worklists"]["reviewer_e"], "reviewer E worklist")
    worklist_f = checked(manifest["worklists"]["reviewer_f"], "reviewer F worklist")
    rows_e = list(iter_jsonl(worklist_e))
    rows_f = list(iter_jsonl(worklist_f))
    ids_e = [row["review_id"] for row in rows_e]
    if len(rows_e) != 29 or [row["review_id"] for row in rows_f] != list(reversed(ids_e)):
        raise ValueError("worklist count/order drift")
    if len({row["original_sample_id"] for row in rows_e}) != 29:
        raise ValueError("worklist source IDs are not unique")
    for row in rows_e:
        leaked = recursive_keys(row) & FORBIDDEN_KEYS
        if leaked:
            raise ValueError(f"blind worklist leaks forbidden keys: {sorted(leaked)}")
        if row.get("field") != "cwe_ids" or row.get("deterministic_set_relation") != "disjoint":
            raise ValueError(f"{row.get('review_id')}: unexpected field/relation")
        if not row.get("allowed_cwe_path_strings"):
            raise ValueError(f"{row.get('review_id')}: missing official CWE path")
        if len(row["evidence_context"]["records"]) > 3:
            raise ValueError(f"{row.get('review_id')}: evidence cap exceeded")

    differences = [
        row for row in iter_jsonl(input_paths["difference_rows"])
        if row.get("field") == "cwe_ids"
    ]
    if len(differences) != 29 or len({row["cve_id"] for row in differences}) != 29:
        raise ValueError("census CWE difference selection drift")
    for row in differences:
        if row.get("current") != "factual_conflict" or row.get("cwe_taxonomy_v1") != "representation_discrepancy":
            raise ValueError(f"{row.get('cve_id')}: prediction direction drift")
    if {row["original_sample_id"] for row in rows_e} != {row["sample_id"] for row in differences}:
        raise ValueError("worklist is not the complete census CWE impact set")

    prior_merge = json.loads(
        input_paths["prior_all50_merge_manifest"].read_text(encoding="utf-8")
    )
    if prior_merge.get("artifact_type") != "rq2_post_profile_cwe_all50_merge_manifest_v3":
        raise ValueError("unexpected prior all-50 merge manifest")
    prior_consensus = prior_merge.get("outputs", {}).get("consensus") or {}
    if prior_consensus != {
        "path": str(input_paths["prior_all50_consensus"]),
        "sha256": sha256(input_paths["prior_all50_consensus"]),
    }:
        raise ValueError("prior all-50 consensus binding drift")

    requests_e = list(iter_jsonl(Path(manifest["reviewer_outputs"]["requests_e"])))
    requests_f = list(iter_jsonl(Path(manifest["reviewer_outputs"]["requests_f"])))
    if {row["session_id"] for row in requests_e} & {row["session_id"] for row in requests_f}:
        raise ValueError("reviewer sessions overlap")
    if {row["run_id"] for row in requests_e} & {row["run_id"] for row in requests_f}:
        raise ValueError("reviewer runs overlap")
    if any(row.get("label_is_human") is not False for row in requests_e + requests_f):
        raise ValueError("request log claims human provenance")

    consensus_rows = list(iter_jsonl(output_paths["consensus"]))
    if len(consensus_rows) != 29:
        raise ValueError("consensus row count drift")
    predictions = {row["sample_id"]: row for row in differences}
    directions = Counter()
    strict_count = 0
    for row in consensus_rows:
        strict, label = independent_strict(row["reviewer_e"], row["reviewer_f"])
        if row["strict_consensus"] is not strict or row["consensus_label"] != label:
            raise ValueError(f"{row['cve_id']}: strict merge drift")
        prediction = predictions[row["original_sample_id"]]
        if not strict:
            direction = "unresolved"
        elif label == prediction["cwe_taxonomy_v1"]:
            direction = "candidate"
        elif label == prediction["current"]:
            direction = "current"
        else:
            direction = "neither"
        if row["profile_direction"] != direction:
            raise ValueError(f"{row['cve_id']}: profile direction drift")
        directions[direction] += 1
        strict_count += int(strict)
    summary = json.loads(output_paths["summary"].read_text(encoding="utf-8"))
    recomputed = {
        "rows": 29,
        "strict_rows": strict_count,
        "candidate_direction_rows": directions["candidate"],
        "current_direction_rows": directions["current"],
        "neither_direction_rows": directions["neither"],
        "unresolved_rows": directions["unresolved"],
        "paired_correctness_discordant_rows": directions["candidate"] + directions["current"],
        "candidate_minus_current_agreement_count": directions["candidate"] - directions["current"],
        "conditional_exact_two_sided_mcnemar_p": exact_p(
            directions["candidate"], directions["current"]
        ),
    }
    for key, value in recomputed.items():
        if summary.get(key) != value:
            raise ValueError(f"summary mismatch for {key}: {summary.get(key)} != {value}")
    prior = {row["cve_id"]: row for row in iter_jsonl(input_paths["prior_all50_consensus"])}
    overlap = [row for row in consensus_rows if row["cve_id"] in prior]
    if len(overlap) != 3 or summary.get("prior_overlap_rows") != 3:
        raise ValueError("prior all-50 overlap drift")
    evaluation = json.loads(input_paths["sealed_profile_evaluation"].read_text(encoding="utf-8"))
    if evaluation["methods"]["current"]["agreement_count"] != 185:
        raise ValueError("sealed current metric changed")
    if evaluation["methods"]["cwe_taxonomy_v1"]["agreement_count"] != 186:
        raise ValueError("sealed CWE metric changed")
    if evaluation["paired_profile_comparisons"]["cwe_taxonomy_v1"]["prediction_difference_rows"] != 3:
        raise ValueError("sealed profile-difference count changed")
    required_false = (
        "uses_human_labels",
        "label_is_human",
        "eligible_for_human_gold_claim",
        "eligible_for_absolute_accuracy_claim",
        "eligible_for_confirmatory_gain_claim",
        "eligible_for_temporal_generalization_claim",
        "eligible_for_preregistered_power_claim",
        "candidate_promotion_allowed",
        "production_default_changed",
        "sealed_250_row_evaluation_changed",
        "real_person_review_requirement_reduced",
    )
    if summary.get("uses_any_labels") is not True:
        raise ValueError("summary does not disclose label use")
    if any(summary.get(key) is not False for key in required_false):
        raise ValueError("claim boundary drift")
    print(
        "Verified eligible-universe CWE impact set: "
        f"rows=29 strict={strict_count} candidate={directions['candidate']} "
        f"current={directions['current']} neither={directions['neither']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
