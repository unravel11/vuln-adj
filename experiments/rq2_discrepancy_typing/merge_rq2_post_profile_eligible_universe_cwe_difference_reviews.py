#!/usr/bin/env python3
"""Merge the 29-row eligible-universe CWE impact-set evidence reviews."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

import merge_rq2_post_profile_cwe_all50 as core


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = (
    "data/annotations/holdout/rq2_post_profile_snapshot_v1/"
    "cwe_eligible_difference_evidence_v1"
)
DEFAULT_RESULT = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_eligible_difference_evidence_v1"
)
REQUEST_TYPE = (
    "rq2_post_profile_eligible_universe_cwe_difference_review_request_v1"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--result-dir", default=DEFAULT_RESULT)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def exact_two_sided_p(candidate_wins: int, current_wins: int) -> float:
    n = candidate_wins + current_wins
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, value) for value in range(min(candidate_wins, current_wins) + 1))
    return min(1.0, 2.0 * tail / (2**n))


def validate_requests(
    path: Path,
    reviews: list[dict],
    worklist_path: Path,
    manifest_path: Path,
    reviewer_id: str,
    role: str,
    execution: dict,
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
            ("prompt", Path(json.loads(manifest_path.read_text(encoding="utf-8"))["inputs"]["prompt"]["path"])),
            ("worklist", worklist_path),
        ):
            entry = record.get(key) or {}
            if entry.get("path") != str(expected_path) or entry.get("sha256") != core.sha256(expected_path):
                raise ValueError(f"request {key} binding mismatch at {path}:{index}")
        ids = record.get("review_ids") or []
        if record.get("row_count") != len(ids) or not 1 <= len(ids) <= execution["batch_size"]:
            raise ValueError(f"request row count mismatch at {path}:{index}")
        batch = [row for row in reviews if row["review_id"] in set(ids)]
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


def render_markdown(summary: dict) -> str:
    return "\n".join(
        [
            "# RQ2 Eligible-universe CWE Impact-set Evidence Audit",
            "",
            "> Outcome-complete revealed-snapshot diagnostic; all decisions are non-human expert candidates.",
            "",
            f"- Rows: `{summary['rows']}`",
            f"- Strict evidence consensus: `{summary['strict_rows']}/{summary['rows']}`",
            f"- Candidate/current/neither/unresolved: `{summary['candidate_direction_rows']}/{summary['current_direction_rows']}/{summary['neither_direction_rows']}/{summary['unresolved_rows']}`",
            f"- Effective correctness-discordant rows: `{summary['paired_correctness_discordant_rows']}`",
            f"- Conditional exact two-sided McNemar p: `{summary['conditional_exact_two_sided_mcnemar_p']}`",
            f"- Prior all-50 overlap exact stability: `{summary['prior_overlap_exact_stability_rows']}/{summary['prior_overlap_comparable_rows']}`",
            "",
            "This selected-set diagnostic is not human gold, absolute accuracy, temporal confirmation, or a promotion result.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    result_dir = resolve(args.result_dir)
    manifest_path = base_dir / "manifest.sealed.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != (
        "rq2_post_profile_eligible_universe_cwe_difference_evidence_manifest_v1"
    ):
        raise ValueError("unexpected CWE impact-set manifest")
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
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
            raise ValueError(f"review artifact predates seal: {path}")
    reviewer_id_e = "codex_post_profile_cwe_eligible_diff_v1_e"
    reviewer_id_f = "codex_post_profile_cwe_eligible_diff_v1_f"
    reviews_e = core.validate_reviews(reviewer_e_path, worklist_e, reviewer_id_e)
    reviews_f = core.validate_reviews(reviewer_f_path, worklist_f, reviewer_id_f)
    requests_e = validate_requests(
        requests_e_path, reviews_e, worklist_e, manifest_path, reviewer_id_e, "e", manifest["execution"]
    )
    requests_f = validate_requests(
        requests_f_path, reviews_f, worklist_f, manifest_path, reviewer_id_f, "f", manifest["execution"]
    )
    sessions_e = {row["session_id"] for row in requests_e}
    sessions_f = {row["session_id"] for row in requests_f}
    runs_e = {row["run_id"] for row in requests_e}
    runs_f = {row["run_id"] for row in requests_f}
    if sessions_e & sessions_f or runs_e & runs_f:
        raise ValueError("reviewer run/session sets are not disjoint")

    by_id_e = {row["review_id"]: row for row in reviews_e}
    by_id_f = {row["review_id"]: row for row in reviews_f}
    predictions = {
        row["sample_id"]: row
        for row in core.iter_jsonl(Path(manifest["inputs"]["difference_rows"]["path"]))
        if row["field"] == "cwe_ids"
    }
    prior_by_cve = {
        row["cve_id"]: row
        for row in core.iter_jsonl(Path(manifest["inputs"]["prior_all50_consensus"]["path"]))
    }
    consensus_rows = []
    component_agreement = Counter()
    directions = Counter()
    for source in core.iter_jsonl(worklist_e):
        review_id = source["review_id"]
        left, right = by_id_e[review_id], by_id_f[review_id]
        for key in core.STRICT_KEYS:
            component_agreement[key] += int(left[key] == right[key])
        strict, label = core.strict_consensus(left, right)
        prediction = predictions[source["original_sample_id"]]
        if not strict:
            direction = "unresolved"
        elif label == prediction["cwe_taxonomy_v1"]:
            direction = "candidate"
        elif label == prediction["current"]:
            direction = "current"
        else:
            direction = "neither"
        directions[direction] += 1
        prior = prior_by_cve.get(source["cve_id"])
        consensus_rows.append(
            {
                "review_id": review_id,
                "original_sample_id": source["original_sample_id"],
                "cve_id": source["cve_id"],
                "field": "cwe_ids",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": label,
                "profile_direction": direction,
                "current_prediction": prediction["current"],
                "candidate_prediction": prediction["cwe_taxonomy_v1"],
                "prior_all50_overlap": prior is not None,
                "prior_all50_strict_consensus": None if prior is None else prior["strict_consensus"],
                "prior_all50_consensus_label": None if prior is None else prior["consensus_label"],
                "reviewer_e": left,
                "reviewer_f": right,
            }
        )

    strict_rows = 29 - directions["unresolved"]
    discordant = directions["candidate"] + directions["current"]
    overlap = [row for row in consensus_rows if row["prior_all50_overlap"]]
    comparable = [
        row for row in overlap
        if row["strict_consensus"] and row["prior_all50_strict_consensus"]
    ]
    summary = {
        "artifact_type": (
            "rq2_post_profile_eligible_universe_cwe_difference_evidence_summary_v1"
        ),
        **manifest["claim_boundary"],
        "selected_tier": "snapshot_external_revealed_complete_cwe_difference_set",
        "rows": len(consensus_rows),
        "strict_rows": strict_rows,
        "strict_coverage": strict_rows / len(consensus_rows),
        "candidate_direction_rows": directions["candidate"],
        "current_direction_rows": directions["current"],
        "neither_direction_rows": directions["neither"],
        "unresolved_rows": directions["unresolved"],
        "paired_correctness_discordant_rows": discordant,
        "candidate_minus_current_agreement_count": directions["candidate"] - directions["current"],
        "conditional_exact_two_sided_mcnemar_p": exact_two_sided_p(
            directions["candidate"], directions["current"]
        ),
        "strict_label_counts": dict(
            sorted(Counter(row["consensus_label"] for row in consensus_rows if row["strict_consensus"]).items())
        ),
        "component_exact_agreement": {
            key: {"count": component_agreement[key], "rows": len(consensus_rows)}
            for key in core.STRICT_KEYS
        },
        "prior_overlap_rows": len(overlap),
        "prior_overlap_comparable_rows": len(comparable),
        "prior_overlap_exact_stability_rows": sum(
            row["consensus_label"] == row["prior_all50_consensus_label"] for row in comparable
        ),
        "reviewer_e_requests": len(requests_e),
        "reviewer_f_requests": len(requests_f),
        "reviewer_sessions_disjoint": True,
        "interpretation": (
            "Conditional same-model evidence consensus over the complete revealed "
            "CWE profile-impact set; not absolute accuracy or human gold."
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
    core.write_jsonl(consensus_path, consensus_rows)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": (
            "rq2_post_profile_eligible_universe_cwe_difference_merge_manifest_v1"
        ),
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
        "Merged eligible-universe CWE impact set: "
        f"strict={strict_rows}/29 candidate={directions['candidate']} "
        f"current={directions['current']} neither={directions['neither']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
