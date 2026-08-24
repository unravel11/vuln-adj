#!/usr/bin/env python3
"""Merge the dual reference partitions and compare all frozen profiles."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import run_rq2_post_profile_cwe_all50_review as core
import run_rq2_post_profile_reference_difference_partition_review as runner


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "reference_difference_partition_v2"
)
DEFAULT_RESULT = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "reference_difference_partition_v2"
)
REQUEST_TYPE = "rq2_post_profile_reference_difference_partition_review_request_v2"
DEFINITIONS = (
    "underlying_reference_resource_v1",
    "frozen_http_resource_v1",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--result-dir", default=DEFAULT_RESULT)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def exact_two_sided_p(right_wins: int, left_wins: int) -> float:
    n = right_wins + left_wins
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, value) for value in range(min(right_wins, left_wins) + 1))
    return min(1.0, 2.0 * tail / (2**n))


def validate_reviews(path: Path, worklist_path: Path, reviewer_id: str) -> list[dict]:
    worklist = list(core.iter_jsonl(worklist_path))
    reviews = list(core.iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(f"review row count mismatch in {path}")
    expected_keys = runner.ITEM_KEYS | {"reviewer_id", "run_id"}
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != expected_keys:
            raise ValueError(f"review schema mismatch at {path}:{index}")
        if review["reviewer_id"] != reviewer_id or not review["run_id"]:
            raise ValueError(f"review identity mismatch at {path}:{index}")
        runner.validate_model_row(
            {key: review[key] for key in runner.ITEM_KEYS}, source
        )
    return reviews


def validate_requests(
    path: Path,
    reviews: list[dict],
    worklist_path: Path,
    manifest_path: Path,
    reviewer_id: str,
    role: str,
    execution: dict,
    prompt_path: Path,
) -> list[dict]:
    records = list(core.iter_jsonl(path))
    expected_ids = [row["review_id"] for row in reviews]
    actual_ids = []
    run_by_id = {}
    sessions = set()
    runs = set()
    for index, record in enumerate(records, start=1):
        if record.get("artifact_type") != REQUEST_TYPE:
            raise ValueError(f"request artifact type mismatch at {path}:{index}")
        if record.get("request_index") != index:
            raise ValueError(f"request index mismatch at {path}:{index}")
        if record.get("reviewer_id") != reviewer_id or record.get("role") != role:
            raise ValueError(f"request reviewer/role mismatch at {path}:{index}")
        if record.get("label_is_human") is not False:
            raise ValueError(f"request human-label boundary drift at {path}:{index}")
        for key in ("model", "reasoning_effort"):
            if record.get(key) != execution[key]:
                raise ValueError(f"request {key} drift at {path}:{index}")
        if (
            record.get("execution_backend") != execution["backend"]
            or record.get("execution_backend_version") != execution["version"]
            or record.get("execution_backend_path") != execution["path"]
            or record.get("execution_backend_sha256") != execution["sha256"]
        ):
            raise ValueError(f"request execution drift at {path}:{index}")
        for key, expected_path in (
            ("manifest", manifest_path),
            ("prompt", prompt_path),
            ("worklist", worklist_path),
        ):
            entry = record.get(key) or {}
            if entry != {"path": str(expected_path), "sha256": core.sha256(expected_path)}:
                raise ValueError(f"request {key} binding mismatch at {path}:{index}")
        ids = record.get("review_ids") or []
        if record.get("row_count") != len(ids) or not 1 <= len(ids) <= execution["batch_size"]:
            raise ValueError(f"request row count mismatch at {path}:{index}")
        id_set = set(ids)
        batch = [row for row in reviews if row["review_id"] in id_set]
        if [row["review_id"] for row in batch] != ids:
            raise ValueError(f"request/review order mismatch at {path}:{index}")
        if core.canonical_sha256(batch) != record.get("response_rows_sha256"):
            raise ValueError(f"request response hash mismatch at {path}:{index}")
        run_id, session_id = record.get("run_id"), record.get("session_id")
        if not run_id or run_id in runs or not session_id or session_id in sessions:
            raise ValueError(f"request run/session reuse at {path}:{index}")
        runs.add(run_id)
        sessions.add(session_id)
        for review_id_value in ids:
            run_by_id[review_id_value] = run_id
        actual_ids.extend(ids)
    if actual_ids != expected_ids:
        raise ValueError(f"request coverage/order drift: {path}")
    if any(row["run_id"] != run_by_id.get(row["review_id"]) for row in reviews):
        raise ValueError(f"review run IDs differ from request log: {path}")
    return records


def strict_partition(left: dict, right: dict) -> tuple[bool, list[list[str]] | None]:
    strict = (
        left["verdict"] == "determinate"
        and right["verdict"] == "determinate"
        and runner.canonical_partition(left["partition"])
        == runner.canonical_partition(right["partition"])
        and left["confidence"] in {"high", "medium"}
        and right["confidence"] in {"high", "medium"}
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    if not strict:
        return False, None
    return True, [list(group) for group in runner.canonical_partition(left["partition"])]


def status_from_partition(partition: list[list[str]], mapping: dict) -> str:
    group_by_member = {
        member_id: group_index
        for group_index, group in enumerate(partition)
        for member_id in group
    }
    side_groups = {"nvd": set(), "ghsa": set()}
    hosts = {"nvd": set(), "ghsa": set()}
    for member in mapping["members"]:
        for side in member["sides"]:
            side_groups[side].add(group_by_member[member["member_id"]])
            host = urlsplit(member["url"]).netloc.lower()
            if host:
                hosts[side].add(host)
    nvd, ghsa = side_groups["nvd"], side_groups["ghsa"]
    if nvd == ghsa:
        return "equivalent"
    if nvd < ghsa or ghsa < nvd:
        return "incomplete"
    if nvd & ghsa or hosts["nvd"] & hosts["ghsa"]:
        return "representation_discrepancy"
    return "factual_conflict"


def profile_pair_metrics(
    rows: list[dict], definition: str, left: str, right: str
) -> dict:
    counts = Counter()
    right_wins = 0
    left_wins = 0
    difference_rows = 0
    for row in rows:
        left_prediction = row["predictions"][left]
        right_prediction = row["predictions"][right]
        result = row["definitions"][definition]
        if left_prediction != right_prediction:
            difference_rows += 1
        if not result["strict_consensus"]:
            counts["unresolved"] += 1
            continue
        status = result["consensus_status"]
        if left_prediction == right_prediction:
            counts["both_match" if status == left_prediction else "both_miss"] += 1
        elif status == right_prediction:
            counts["right"] += 1
            right_wins += 1
        elif status == left_prediction:
            counts["left"] += 1
            left_wins += 1
        else:
            counts["neither"] += 1
    return {
        "left_profile": left,
        "right_profile": right,
        "common_union_rows": len(rows),
        "prediction_difference_rows": difference_rows,
        "left_direction_rows": counts["left"],
        "right_direction_rows": counts["right"],
        "both_match_rows": counts["both_match"],
        "both_miss_rows": counts["both_miss"],
        "neither_rows": counts["neither"],
        "unresolved_rows": counts["unresolved"],
        "conditional_correctness_discordant_rows": left_wins + right_wins,
        "right_minus_left_agreement_count": right_wins - left_wins,
        "conditional_exact_two_sided_mcnemar_p": exact_two_sided_p(
            right_wins, left_wins
        ),
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ2 Eligible-universe Reference Difference Partition Audit",
        "",
        "> Complete revealed five-row impact union; all decisions are non-human expert candidates.",
        "",
    ]
    for definition, result in summary["definitions"].items():
        lines.extend(
            [
                f"## {definition}",
                "",
                f"- Strict partitions: `{result['strict_rows']}/5`",
                f"- Status counts: `{result['consensus_status_counts']}`",
                f"- Current vs original: `{result['profile_pairs']['current_vs_original']}`",
                f"- Current vs audited: `{result['profile_pairs']['current_vs_audited']}`",
                "",
            ]
        )
    lines.append(
        "This is not human gold, absolute accuracy, temporal confirmation, or a promotion result."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    result_dir = resolve(args.result_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_reference_difference_partition_manifest_v2":
        raise ValueError("unexpected reference partition manifest")
    for entry in manifest["inputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or core.sha256(path) != entry["sha256"]:
            raise ValueError(f"sealed input hash mismatch: {path}")
    for entry in manifest["outputs"].values():
        path = Path(entry["path"])
        if not path.is_file() or core.sha256(path) != entry["sha256"]:
            raise ValueError(f"sealed output hash mismatch: {path}")
    for entry in manifest["evidence"]["cache_files"]:
        path = Path(entry["path"])
        if not path.is_file() or core.sha256(path) != entry["sha256"]:
            raise ValueError(f"evidence cache hash mismatch: {path}")

    worklist_e = Path(manifest["worklists"]["reviewer_e"]["path"])
    worklist_f = Path(manifest["worklists"]["reviewer_f"]["path"])
    reviewer_e_path = Path(manifest["reviewer_outputs"]["reviewer_e"])
    reviewer_f_path = Path(manifest["reviewer_outputs"]["reviewer_f"])
    requests_e_path = Path(manifest["reviewer_outputs"]["requests_e"])
    requests_f_path = Path(manifest["reviewer_outputs"]["requests_f"])
    for path in (reviewer_e_path, reviewer_f_path, requests_e_path, requests_f_path):
        if not path.is_file() or path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"missing or pre-seal review artifact: {path}")
    reviews_e = validate_reviews(worklist_path=worklist_e, path=reviewer_e_path, reviewer_id="codex_reference_partition_v2_e")
    reviews_f = validate_reviews(worklist_path=worklist_f, path=reviewer_f_path, reviewer_id="codex_reference_partition_v2_f")
    prompt_path = Path(manifest["inputs"]["prompt"]["path"])
    requests_e = validate_requests(
        requests_e_path, reviews_e, worklist_e, manifest_path,
        "codex_reference_partition_v2_e", "e", manifest["execution"], prompt_path
    )
    requests_f = validate_requests(
        requests_f_path, reviews_f, worklist_f, manifest_path,
        "codex_reference_partition_v2_f", "f", manifest["execution"], prompt_path
    )
    if (
        {row["session_id"] for row in requests_e} & {row["session_id"] for row in requests_f}
        or {row["run_id"] for row in requests_e} & {row["run_id"] for row in requests_f}
    ):
        raise ValueError("reviewer run/session sets are not disjoint")

    by_id_e = {row["review_id"]: row for row in reviews_e}
    by_id_f = {row["review_id"]: row for row in reviews_f}
    mappings = list(core.iter_jsonl(Path(manifest["outputs"]["author_mapping"]["path"])))
    consensus_rows = []
    for mapping in mappings:
        review_id = mapping["review_id"]
        left, right = by_id_e[review_id], by_id_f[review_id]
        definition_results = {}
        for definition in DEFINITIONS:
            strict, partition = strict_partition(left[definition], right[definition])
            definition_results[definition] = {
                "strict_consensus": strict,
                "consensus_partition": partition,
                "consensus_status": (
                    status_from_partition(partition, mapping) if strict else None
                ),
            }
        consensus_rows.append(
            {
                "review_id": review_id,
                "original_sample_id": mapping["original_sample_id"],
                "cve_id": mapping["cve_id"],
                "field": "references",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "predictions": mapping["predictions"],
                "definitions": definition_results,
                "reviewer_e": left,
                "reviewer_f": right,
            }
        )

    definition_summaries = {}
    for definition in DEFINITIONS:
        strict_rows = [
            row for row in consensus_rows
            if row["definitions"][definition]["strict_consensus"]
        ]
        definition_summaries[definition] = {
            "strict_rows": len(strict_rows),
            "unresolved_rows": len(consensus_rows) - len(strict_rows),
            "partition_exact_agreement_rows": sum(
                by_id_e[row["review_id"]][definition]["verdict"] == "determinate"
                and by_id_f[row["review_id"]][definition]["verdict"] == "determinate"
                and runner.canonical_partition(
                    by_id_e[row["review_id"]][definition]["partition"]
                )
                == runner.canonical_partition(
                    by_id_f[row["review_id"]][definition]["partition"]
                )
                for row in consensus_rows
            ),
            "consensus_status_counts": dict(
                sorted(
                    Counter(
                        row["definitions"][definition]["consensus_status"]
                        for row in strict_rows
                    ).items()
                )
            ),
            "profile_pairs": {
                "current_vs_original": profile_pair_metrics(
                    consensus_rows, definition, "current", "original"
                ),
                "current_vs_audited": profile_pair_metrics(
                    consensus_rows, definition, "current", "audited"
                ),
                "original_vs_audited": profile_pair_metrics(
                    consensus_rows, definition, "original", "audited"
                ),
            },
        }
    summary = {
        "artifact_type": "rq2_post_profile_reference_difference_partition_summary_v2",
        **manifest["claim_boundary"],
        "selected_tier": "snapshot_external_revealed_complete_reference_difference_union",
        "rows": len(consensus_rows),
        "definitions": definition_summaries,
        "reviewer_e_requests": len(requests_e),
        "reviewer_f_requests": len(requests_f),
        "reviewer_sessions_disjoint": True,
        "interpretation": (
            "Profile-independent dual partitions over the complete revealed five-row "
            "reference impact union; not absolute accuracy or human gold."
        ),
    }

    result_dir.mkdir(parents=True, exist_ok=True)
    consensus_path = result_dir / "dual_review_consensus.jsonl"
    summary_path = result_dir / "summary.json"
    markdown_path = result_dir / "summary.md"
    merge_manifest_path = result_dir / "merge_manifest.json"
    for path in (consensus_path, summary_path, markdown_path, merge_manifest_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite merge output: {path}")
    write_jsonl(consensus_path, consensus_rows)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "rq2_post_profile_reference_difference_partition_merge_manifest_v2",
        "source_manifest": {"path": str(manifest_path), "sha256": core.sha256(manifest_path)},
        "inputs": {
            "reviewer_e": {"path": str(reviewer_e_path), "sha256": core.sha256(reviewer_e_path)},
            "reviewer_f": {"path": str(reviewer_f_path), "sha256": core.sha256(reviewer_f_path)},
            "requests_e": {"path": str(requests_e_path), "sha256": core.sha256(requests_e_path)},
            "requests_f": {"path": str(requests_f_path), "sha256": core.sha256(requests_f_path)},
        },
        "outputs": {
            "consensus": {"path": str(consensus_path), "sha256": core.sha256(consensus_path)},
            "summary": {"path": str(summary_path), "sha256": core.sha256(summary_path)},
            "markdown": {"path": str(markdown_path), "sha256": core.sha256(markdown_path)},
        },
        "claim_boundary": manifest["claim_boundary"],
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Merged reference partitions: "
        + " ".join(
            f"{name}={result['strict_rows']}/5"
            for name, result in definition_summaries.items()
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
