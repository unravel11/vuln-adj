#!/usr/bin/env python3
"""Independently verify v3 post-profile CWE evidence-secondary bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_evidence_secondary_v3"
)
DEFAULT_MERGE_MANIFEST = f"{DEFAULT_DIR}/merge_manifest.json"
STRICT_KEYS = (
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "specific_mapping_verdict",
)
REQUIRED_FALSE = (
    "label_is_human",
    "eligible_for_human_gold_claim",
    "eligible_for_confirmatory_method_gain_claim",
    "strict_event_time_claim_allowed",
    "candidate_promotion_allowed",
    "production_default_changed",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--merge-manifest", default=DEFAULT_MERGE_MANIFEST)
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


def verify_entry(entry: dict, label: str) -> Path:
    path = Path(entry["path"])
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")
    if sha256(path) != entry["sha256"]:
        raise ValueError(f"hash mismatch for {label}: {path}")
    return path


def main() -> int:
    args = parse_args()
    merge_manifest_path = resolve(args.merge_manifest)
    merge_manifest = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if merge_manifest.get("artifact_type") != (
        "rq2_post_profile_cwe_evidence_secondary_merge_manifest_v3"
    ):
        raise ValueError("unexpected merge manifest artifact type")
    source_manifest_path = verify_entry(
        merge_manifest["source_manifest"], "source manifest"
    )
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
    if source_manifest.get("artifact_type") != (
        "rq2_post_profile_cwe_evidence_secondary_manifest_v3"
    ):
        raise ValueError("unexpected source manifest artifact type")
    if source_manifest.get("row_count") != 3:
        raise ValueError("source manifest row count is not three")
    if source_manifest.get("reviewer_outputs_absent_at_seal") is not True:
        raise ValueError("reviewer outputs were not absent at seal")
    selection = source_manifest.get("selection") or {}
    if selection.get("post_selection_profile_differential") is not True:
        raise ValueError("post-selection boundary missing")
    if selection.get("selected_after_a_b_unsealing") is not True:
        raise ValueError("A/B unsealing boundary missing")
    if selection.get("supersedes_failed_v1_contract_attempt") is not True:
        raise ValueError("failed v1 attempt is not disclosed")
    if selection.get("supersedes_failed_v2_path_contract_attempt") is not True:
        raise ValueError("failed v2 attempt is not disclosed")
    if len(selection.get("rows") or []) != 3:
        raise ValueError("selection does not contain three rows")
    for key in REQUIRED_FALSE:
        if source_manifest["claim_boundary"].get(key) is not False:
            raise ValueError(f"claim boundary must be false: {key}")
        if merge_manifest["claim_boundary"].get(key) is not False:
            raise ValueError(f"merge claim boundary must be false: {key}")

    for name, entry in source_manifest["inputs"].items():
        verify_entry(entry, f"sealed input {name}")
    for name, entry in source_manifest["worklists"].items():
        verify_entry(entry, f"sealed worklist {name}")
    review_paths = {
        name: verify_entry(entry, f"review input {name}")
        for name, entry in merge_manifest["review_inputs"].items()
    }
    output_paths = {
        name: verify_entry(entry, f"merge output {name}")
        for name, entry in merge_manifest["outputs"].items()
    }

    request_c = list(iter_jsonl(review_paths["requests_c"]))
    request_d = list(iter_jsonl(review_paths["requests_d"]))
    if len(request_c) != 1 or len(request_d) != 1:
        raise ValueError("each reviewer must have exactly one request record")
    if request_c[0].get("session_id") == request_d[0].get("session_id"):
        raise ValueError("reviewer session IDs are not disjoint")
    if request_c[0].get("run_id") == request_d[0].get("run_id"):
        raise ValueError("reviewer run IDs are not disjoint")
    if request_c[0].get("label_is_human") is not False:
        raise ValueError("reviewer C request violates human-label boundary")
    if request_d[0].get("label_is_human") is not False:
        raise ValueError("reviewer D request violates human-label boundary")

    consensus = list(iter_jsonl(output_paths["consensus"]))
    summary = json.loads(output_paths["summary"].read_text(encoding="utf-8"))
    if len(consensus) != 3 or summary.get("rows") != 3:
        raise ValueError("result does not contain exactly three rows")
    if len({row["review_id"] for row in consensus}) != 3:
        raise ValueError("duplicate consensus review_id")
    if len({row["cve_id"] for row in consensus}) != 3:
        raise ValueError("duplicate consensus cve_id")

    strict_count = 0
    label_counts = Counter()
    direction_counts = Counter()
    prior_non_strict = 0
    resolved_prior_non_strict = 0
    component_counts = Counter()
    for row in consensus:
        if row.get("label_is_human") is not False:
            raise ValueError("consensus row violates human-label boundary")
        if row.get("eligible_for_human_gold_claim") is not False:
            raise ValueError("consensus row permits human-gold claim")
        left, right = row["reviewer_c"], row["reviewer_d"]
        exact = True
        for key in STRICT_KEYS:
            agreement = left[key] == right[key]
            component_counts[key] += int(agreement)
            exact = exact and agreement
        expected_strict = (
            exact
            and left["discrepancy_label"] != "uncertain"
            and not left["needs_additional_review"]
            and not right["needs_additional_review"]
        )
        expected_label = left["discrepancy_label"] if expected_strict else None
        if row["strict_consensus"] != expected_strict:
            raise ValueError(f"strict flag mismatch for {row['review_id']}")
        if row["consensus_label"] != expected_label:
            raise ValueError(f"consensus label mismatch for {row['review_id']}")
        current = row["selection"]["current"]
        candidate = row["selection"]["candidate"]
        if expected_strict and expected_label == candidate:
            expected_direction = "candidate"
        elif expected_strict and expected_label == current:
            expected_direction = "current"
        elif expected_strict:
            expected_direction = "neither"
        else:
            expected_direction = "unresolved"
        if row["profile_direction"] != expected_direction:
            raise ValueError(f"profile direction mismatch for {row['review_id']}")
        strict_count += int(expected_strict)
        if expected_label:
            label_counts[expected_label] += 1
        direction_counts[expected_direction] += 1
        was_non_strict = not row["selection"]["prior_strict_consensus"]
        prior_non_strict += int(was_non_strict)
        resolved_prior_non_strict += int(was_non_strict and expected_strict)

    expected_summary = {
        "strict_rows": strict_count,
        "strict_label_counts": dict(sorted(label_counts.items())),
        "prior_non_strict_rows": prior_non_strict,
        "resolved_prior_non_strict_rows": resolved_prior_non_strict,
        "candidate_direction_strict_rows": direction_counts["candidate"],
        "current_direction_strict_rows": direction_counts["current"],
        "neither_direction_strict_rows": direction_counts["neither"],
        "unresolved_rows": direction_counts["unresolved"],
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            raise ValueError(f"summary mismatch for {key}: {summary.get(key)} != {expected}")
    for key in REQUIRED_FALSE:
        if summary.get(key) is not False:
            raise ValueError(f"summary claim boundary must be false: {key}")
    if summary.get("sealed_250_row_evaluation_changed") is not False:
        raise ValueError("summary claims the sealed evaluation changed")
    if summary.get("post_selection_profile_differential") is not True:
        raise ValueError("summary omits post-selection disclosure")
    if summary.get("reviewer_sessions_disjoint") is not True:
        raise ValueError("summary omits session independence")
    for key in STRICT_KEYS:
        recorded = summary["component_exact_agreement"][key]
        if recorded != {"count": component_counts[key], "rows": 3}:
            raise ValueError(f"component agreement mismatch for {key}")

    print(
        "Verified post-profile CWE evidence-secondary result: "
        f"rows=3 strict={strict_count} candidate={direction_counts['candidate']} "
        f"current={direction_counts['current']} unresolved={direction_counts['unresolved']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
