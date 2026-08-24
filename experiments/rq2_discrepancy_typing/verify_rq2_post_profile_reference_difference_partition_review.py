#!/usr/bin/env python3
"""Independently verify the five-row reference partition audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "reference_difference_partition_v2/manifest.sealed.json"
)
DEFAULT_MERGE = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "reference_difference_partition_v2/merge_manifest.json"
)
DEFINITIONS = (
    "underlying_reference_resource_v1",
    "frozen_http_resource_v1",
)
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


def canonical(partition: list[list[str]]) -> tuple[tuple[str, ...], ...]:
    return tuple(sorted(tuple(sorted(group)) for group in partition))


def valid_partition(partition: object, member_ids: set[str]) -> bool:
    if not isinstance(partition, list) or not partition:
        return False
    flattened = [member for group in partition if isinstance(group, list) for member in group]
    return (
        len(flattened) == len(member_ids)
        and len(flattened) == len(set(flattened))
        and set(flattened) == member_ids
        and all(group for group in partition)
    )


def strict_partition(
    left: dict, right: dict, member_ids: set[str]
) -> tuple[bool, list[list[str]] | None]:
    strict = (
        left.get("verdict") == "determinate"
        and right.get("verdict") == "determinate"
        and valid_partition(left.get("partition"), member_ids)
        and valid_partition(right.get("partition"), member_ids)
        and canonical(left["partition"]) == canonical(right["partition"])
        and left.get("confidence") in {"high", "medium"}
        and right.get("confidence") in {"high", "medium"}
        and left.get("needs_additional_review") is False
        and right.get("needs_additional_review") is False
    )
    if not strict:
        return False, None
    return True, [list(group) for group in canonical(left["partition"])]


def derived_status(partition: list[list[str]], mapping: dict) -> str:
    group_by_member = {
        member_id: group_index
        for group_index, group in enumerate(partition)
        for member_id in group
    }
    groups = {"nvd": set(), "ghsa": set()}
    hosts = {"nvd": set(), "ghsa": set()}
    for member in mapping["members"]:
        for side in member["sides"]:
            groups[side].add(group_by_member[member["member_id"]])
            host = urlsplit(member["url"]).netloc.lower()
            if host:
                hosts[side].add(host)
    nvd, ghsa = groups["nvd"], groups["ghsa"]
    if nvd == ghsa:
        return "equivalent"
    if nvd < ghsa or ghsa < nvd:
        return "incomplete"
    if nvd & ghsa or hosts["nvd"] & hosts["ghsa"]:
        return "representation_discrepancy"
    return "factual_conflict"


def exact_p(right: int, left: int) -> float:
    n = right + left
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, value) for value in range(min(right, left) + 1))
    return min(1.0, 2.0 * tail / (2**n))


def pair_metrics(rows: list[dict], definition: str, left: str, right: str) -> dict:
    counts = Counter()
    left_wins = right_wins = differences = 0
    for row in rows:
        lp, rp = row["predictions"][left], row["predictions"][right]
        result = row["definitions"][definition]
        differences += int(lp != rp)
        if not result["strict_consensus"]:
            counts["unresolved"] += 1
        elif lp == rp:
            counts["both_match" if result["consensus_status"] == lp else "both_miss"] += 1
        elif result["consensus_status"] == rp:
            counts["right"] += 1
            right_wins += 1
        elif result["consensus_status"] == lp:
            counts["left"] += 1
            left_wins += 1
        else:
            counts["neither"] += 1
    return {
        "left_profile": left,
        "right_profile": right,
        "common_union_rows": len(rows),
        "prediction_difference_rows": differences,
        "left_direction_rows": counts["left"],
        "right_direction_rows": counts["right"],
        "both_match_rows": counts["both_match"],
        "both_miss_rows": counts["both_miss"],
        "neither_rows": counts["neither"],
        "unresolved_rows": counts["unresolved"],
        "conditional_correctness_discordant_rows": left_wins + right_wins,
        "right_minus_left_agreement_count": right_wins - left_wins,
        "conditional_exact_two_sided_mcnemar_p": exact_p(right_wins, left_wins),
    }


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    merge_path = resolve(args.merge_manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    merge = json.loads(merge_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_reference_difference_partition_manifest_v2":
        raise ValueError("unexpected sealed manifest")
    if merge.get("artifact_type") != "rq2_post_profile_reference_difference_partition_merge_manifest_v2":
        raise ValueError("unexpected merge manifest")
    if merge.get("source_manifest") != {"path": str(manifest_path), "sha256": sha256(manifest_path)}:
        raise ValueError("merge is not bound to sealed manifest")
    input_paths = {
        name: checked(record, f"sealed input {name}")
        for name, record in manifest["inputs"].items()
    }
    mapping_path = checked(manifest["outputs"]["author_mapping"], "author mapping")
    worklist_e = checked(manifest["worklists"]["reviewer_e"], "reviewer E worklist")
    worklist_f = checked(manifest["worklists"]["reviewer_f"], "reviewer F worklist")
    cache_paths = [
        checked(record, f"cache file {index}")
        for index, record in enumerate(manifest["evidence"]["cache_files"], start=1)
    ]
    for name, record in merge["inputs"].items():
        checked(record, f"merge input {name}")
    output_paths = {
        name: checked(record, f"merge output {name}")
        for name, record in merge["outputs"].items()
    }

    differences = [
        row for row in iter_jsonl(input_paths["difference_rows"])
        if row.get("field") == "references"
    ]
    if len(differences) != 5 or len({row["cve_id"] for row in differences}) != 5:
        raise ValueError("reference difference selection drift")
    if sum(row["reference_resource_identity_audited_v1"] != row["current"] for row in differences) != 3:
        raise ValueError("audited difference count drift")
    if sum(row["reference_resource_identity_original_v1"] != row["reference_resource_identity_audited_v1"] for row in differences) != 2:
        raise ValueError("original/audited difference count drift")

    mappings = list(iter_jsonl(mapping_path))
    if len(mappings) != 5 or {row["cve_id"] for row in mappings} != {row["cve_id"] for row in differences}:
        raise ValueError("author mapping does not cover complete reference union")
    rows_e = list(iter_jsonl(worklist_e))
    rows_f = list(iter_jsonl(worklist_f))
    if [row["review_id"] for row in rows_f] != list(reversed([row["review_id"] for row in rows_e])):
        raise ValueError("worklist order is not exact reverse")
    by_worklist = {row["review_id"]: row for row in rows_e}
    all_probe_urls = set()
    for mapping in mappings:
        blind = by_worklist[mapping["review_id"]]
        leaked = recursive_keys(blind) & FORBIDDEN_KEYS
        if leaked:
            raise ValueError(f"blind worklist leaks forbidden keys: {sorted(leaked)}")
        expected = {(member["member_id"], member["url"]) for member in mapping["members"]}
        actual = {(member["member_id"], member["url"]) for member in blind["members"]}
        if actual != expected:
            raise ValueError(f"{mapping['review_id']}: blind member projection drift")
        for member in blind["members"]:
            probe = member["frozen_probe"]
            if probe.get("url") != member["url"] or probe.get("schema_version") != "rq2_reference_probe_v2":
                raise ValueError(f"{mapping['review_id']}: frozen probe identity drift")
            all_probe_urls.add(member["url"])
    cached_urls = {json.loads(path.read_text(encoding="utf-8"))["url"] for path in cache_paths}
    if cached_urls != all_probe_urls or len(cache_paths) != len(all_probe_urls):
        raise ValueError("probe cache does not exactly cover worklist URL union")

    requests_e = list(iter_jsonl(Path(manifest["reviewer_outputs"]["requests_e"])))
    requests_f = list(iter_jsonl(Path(manifest["reviewer_outputs"]["requests_f"])))
    if {row["session_id"] for row in requests_e} & {row["session_id"] for row in requests_f}:
        raise ValueError("reviewer sessions overlap")
    if {row["run_id"] for row in requests_e} & {row["run_id"] for row in requests_f}:
        raise ValueError("reviewer runs overlap")
    if any(row.get("label_is_human") is not False for row in requests_e + requests_f):
        raise ValueError("request log claims human provenance")

    consensus_rows = list(iter_jsonl(output_paths["consensus"]))
    if len(consensus_rows) != 5:
        raise ValueError("consensus row count drift")
    mapping_by_id = {row["review_id"]: row for row in mappings}
    for row in consensus_rows:
        mapping = mapping_by_id[row["review_id"]]
        member_ids = {member["member_id"] for member in mapping["members"]}
        if row["predictions"] != mapping["predictions"]:
            raise ValueError(f"{row['cve_id']}: prediction join drift")
        for definition in DEFINITIONS:
            strict, partition = strict_partition(
                row["reviewer_e"][definition], row["reviewer_f"][definition], member_ids
            )
            result = row["definitions"][definition]
            status = derived_status(partition, mapping) if strict else None
            if result != {
                "strict_consensus": strict,
                "consensus_partition": partition,
                "consensus_status": status,
            }:
                raise ValueError(f"{row['cve_id']}: {definition} merge drift")

    summary = json.loads(output_paths["summary"].read_text(encoding="utf-8"))
    pairs = (
        ("current_vs_original", "current", "original"),
        ("current_vs_audited", "current", "audited"),
        ("original_vs_audited", "original", "audited"),
    )
    for definition in DEFINITIONS:
        strict_rows = [row for row in consensus_rows if row["definitions"][definition]["strict_consensus"]]
        result = summary["definitions"][definition]
        if result["strict_rows"] != len(strict_rows) or result["unresolved_rows"] != 5 - len(strict_rows):
            raise ValueError(f"{definition}: strict-count drift")
        expected_counts = dict(sorted(Counter(row["definitions"][definition]["consensus_status"] for row in strict_rows).items()))
        if result["consensus_status_counts"] != expected_counts:
            raise ValueError(f"{definition}: status-count drift")
        for key, left, right in pairs:
            expected = pair_metrics(consensus_rows, definition, left, right)
            if result["profile_pairs"][key] != expected:
                raise ValueError(f"{definition}: {key} metric drift")

    evaluation = json.loads(input_paths["sealed_profile_evaluation"].read_text(encoding="utf-8"))
    if evaluation["methods"]["current"]["agreement_count"] != 185:
        raise ValueError("sealed current metric changed")
    for profile in (
        "reference_resource_identity_original_v1",
        "reference_resource_identity_audited_v1",
    ):
        if evaluation["paired_profile_comparisons"][profile]["prediction_difference_rows"] != 0:
            raise ValueError("sealed 250-row reference comparison changed")
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
        "Verified reference partitions: "
        + " ".join(
            f"{definition}={summary['definitions'][definition]['strict_rows']}/5"
            for definition in DEFINITIONS
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
