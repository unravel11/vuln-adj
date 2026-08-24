#!/usr/bin/env python3
"""Validate and merge two isolated AI reviews of reference-normalization changes."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKLIST = (
    "results/rq2_discrepancy_typing/"
    "reference_normalization_changed_cases.review.jsonl"
)
DEFAULT_AGENT_A = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_normalization_agent_a.jsonl"
)
DEFAULT_AGENT_B = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_normalization_agent_b.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"

REQUIRED_KEYS = {
    "cve_id",
    "field",
    "trigger_stage",
    "decision",
    "final_status",
    "rationale",
    "confidence",
    "needs_human_review",
}
DECISION_TO_STATUS = {
    "approve_incomplete": "incomplete",
    "keep_representation_discrepancy": "representation_discrepancy",
    "uncertain": "uncertain",
}
CONFIDENCE = {"high", "medium", "low"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def index_unique(rows: list[dict], path: Path) -> dict[str, dict]:
    indexed = {}
    for row in rows:
        cve_id = str(row.get("cve_id") or "")
        if not cve_id:
            raise ValueError(f"{path}: row missing cve_id")
        if cve_id in indexed:
            raise ValueError(f"{path}: duplicate cve_id={cve_id}")
        indexed[cve_id] = row
    return indexed


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_agent_rows(
    rows: list[dict], path: Path, worklist: dict[str, dict]
) -> dict[str, dict]:
    indexed = index_unique(rows, path)
    missing = sorted(set(worklist) - set(indexed))
    extra = sorted(set(indexed) - set(worklist))
    if missing or extra:
        raise ValueError(f"{path}: missing={missing[:5]}, extra={extra[:5]}")

    for cve_id, row in indexed.items():
        missing_keys = sorted(REQUIRED_KEYS - set(row))
        extra_keys = sorted(set(row) - REQUIRED_KEYS)
        if missing_keys or extra_keys:
            raise ValueError(
                f"{path}:{cve_id}: missing={missing_keys}, extra={extra_keys}"
            )
        if row["field"] != "references":
            raise ValueError(f"{path}:{cve_id}: field must be references")
        if row["trigger_stage"] != worklist[cve_id]["trigger_stage"]:
            raise ValueError(f"{path}:{cve_id}: trigger_stage mismatch")
        expected_status = DECISION_TO_STATUS.get(row["decision"])
        if expected_status is None or row["final_status"] != expected_status:
            raise ValueError(f"{path}:{cve_id}: decision/status mismatch")
        if row["confidence"] not in CONFIDENCE:
            raise ValueError(f"{path}:{cve_id}: invalid confidence")
        if not isinstance(row["needs_human_review"], bool):
            raise ValueError(f"{path}:{cve_id}: needs_human_review must be boolean")
        if not isinstance(row["rationale"], str) or not row["rationale"].strip():
            raise ValueError(f"{path}:{cve_id}: rationale must be non-empty")
        if (
            row["final_status"] == "uncertain" or row["confidence"] == "low"
        ) and not row["needs_human_review"]:
            raise ValueError(f"{path}:{cve_id}: uncertain/low row requires review")
    return indexed


def count_map(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def cohen_kappa(labels_a: list[str], labels_b: list[str]) -> tuple[float | None, str]:
    if len(labels_a) != len(labels_b) or not labels_a:
        raise ValueError("Kappa requires equally sized non-empty label lists")
    observed = sum(a == b for a, b in zip(labels_a, labels_b)) / len(labels_a)
    counts_a = Counter(labels_a)
    counts_b = Counter(labels_b)
    labels = set(counts_a) | set(counts_b)
    expected = sum(
        (counts_a[label] / len(labels_a)) * (counts_b[label] / len(labels_b))
        for label in labels
    )
    if expected == 1.0:
        return None, "undefined_single_class_marginals"
    return (observed - expected) / (1.0 - expected), "defined"


def render_markdown(metrics: dict) -> str:
    lines = [
        "# RQ2 Reference Normalization Dual-AI Review",
        "",
        "> Both passes are AI reviews. This artifact is not human-gold or human inter-annotator agreement.",
        "",
        f"- Rows: {metrics['row_count']}",
        f"- Exact label agreement: {metrics['exact_agreement_count']}/{metrics['row_count']} ({metrics['exact_agreement_rate']:.4f})",
        f"- Cohen's kappa: {metrics['cohen_kappa']} ({metrics['cohen_kappa_status']})",
        f"- Dual approvals: {metrics['dual_approve_incomplete_rows']}",
        f"- Label disagreements: {metrics['label_disagreement_count']}",
        f"- Human-signed rows: {metrics['human_signed_rows']}",
        "",
        "| Trigger stage | Rows | Exact agreement | Consensus labels |",
        "|---|---:|---:|---|",
    ]
    for stage, result in metrics["by_trigger_stage"].items():
        lines.append(
            f"| {stage} | {result['row_count']} | "
            f"{result['agreement_count']}/{result['row_count']} | "
            f"{result['consensus_label_counts']} |"
        )
    lines.extend(
        [
            "",
            "The two passes used the same model family and URL-only context. Unanimous AI approval supports a candidate-backed rule hypothesis but does not authorize a human-gold claim.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist_path = resolve_path(args.worklist)
    agent_a_path = resolve_path(args.agent_a)
    agent_b_path = resolve_path(args.agent_b)
    output_dir = resolve_path(args.output_dir)
    for path in (worklist_path, agent_a_path, agent_b_path):
        if not path.exists():
            raise FileNotFoundError(path)

    worklist_rows = load_jsonl(worklist_path)
    worklist = index_unique(worklist_rows, worklist_path)
    if len(worklist) != 56:
        raise ValueError(f"Expected 56 worklist rows, got {len(worklist)}")
    agent_a = validate_agent_rows(load_jsonl(agent_a_path), agent_a_path, worklist)
    agent_b = validate_agent_rows(load_jsonl(agent_b_path), agent_b_path, worklist)

    merged = []
    for cve_id in sorted(worklist):
        source = worklist[cve_id]
        review_a = agent_a[cve_id]
        review_b = agent_b[cve_id]
        labels_agree = review_a["final_status"] == review_b["final_status"]
        consensus_status = review_a["final_status"] if labels_agree else "uncertain"
        merged.append(
            {
                "schema_version": "rq2_reference_normalization_dual_ai_v1",
                "artifact_type": "dual_ai_expert_adjudicated_candidate",
                "label_is_human": False,
                "candidate_status": (
                    "dual_ai_consensus" if labels_agree else "dual_ai_disagreement"
                ),
                "requires_human_signoff": True,
                "cve_id": cve_id,
                "field": "references",
                "trigger_stage": source["trigger_stage"],
                "current_status": source["current_status"],
                "proposed_status": source["proposed_status"],
                "agent_a": review_a,
                "agent_b": review_b,
                "consensus_status": consensus_status,
                "candidate_needs_additional_review": (
                    not labels_agree
                    or review_a["needs_human_review"]
                    or review_b["needs_human_review"]
                ),
            }
        )

    labels_a = [row["agent_a"]["final_status"] for row in merged]
    labels_b = [row["agent_b"]["final_status"] for row in merged]
    agreement_count = sum(a == b for a, b in zip(labels_a, labels_b))
    kappa, kappa_status = cohen_kappa(labels_a, labels_b)
    rationale_exact_matches = sum(
        row["agent_a"]["rationale"] == row["agent_b"]["rationale"]
        for row in merged
    )
    by_stage = {}
    for stage in sorted({row["trigger_stage"] for row in merged}):
        rows = [row for row in merged if row["trigger_stage"] == stage]
        by_stage[stage] = {
            "row_count": len(rows),
            "agreement_count": sum(
                row["agent_a"]["final_status"] == row["agent_b"]["final_status"]
                for row in rows
            ),
            "consensus_label_counts": count_map(
                [row["consensus_status"] for row in rows]
            ),
        }

    metrics = {
        "artifact_type": "rq2_reference_normalization_dual_ai_review",
        "label_is_human": False,
        "independent_human_annotators": False,
        "same_model_family_separate_passes": True,
        "row_count": len(merged),
        "exact_agreement_count": agreement_count,
        "exact_agreement_rate": agreement_count / len(merged),
        "cohen_kappa": kappa,
        "cohen_kappa_status": kappa_status,
        "agent_a_label_counts": count_map(labels_a),
        "agent_b_label_counts": count_map(labels_b),
        "consensus_label_counts": count_map(
            [row["consensus_status"] for row in merged]
        ),
        "dual_approve_incomplete_rows": sum(
            row["agent_a"]["decision"] == "approve_incomplete"
            and row["agent_b"]["decision"] == "approve_incomplete"
            for row in merged
        ),
        "label_disagreement_count": len(merged) - agreement_count,
        "rationale_exact_match_count": rationale_exact_matches,
        "candidate_needs_additional_review_rows": sum(
            row["candidate_needs_additional_review"] for row in merged
        ),
        "human_signed_rows": 0,
        "by_trigger_stage": by_stage,
        "input_paths": {
            "worklist": str(worklist_path),
            "agent_a": str(agent_a_path),
            "agent_b": str(agent_b_path),
        },
        "input_sha256": {
            "worklist": sha256(worklist_path),
            "agent_a": sha256(agent_a_path),
            "agent_b": sha256(agent_b_path),
        },
        "cautions": [
            "Both reviews were generated by separate passes of the same AI model family.",
            "The reviewers used URL strings only and did not verify live redirects or page content.",
            "The reviewed set was selected because the proposed rule changes its baseline label.",
            "Human annotator, independent reviewer, and author sign-off remain required for human-gold.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "reference_normalization_dual_ai_candidate.jsonl"
    metrics_path = output_dir / "reference_normalization_dual_ai_review.json"
    markdown_path = output_dir / "reference_normalization_dual_ai_review.md"
    with merged_path.open("w", encoding="utf-8") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    metrics_path.write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(metrics), encoding="utf-8")
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    print(f"Wrote {merged_path}")
    print(f"Wrote {metrics_path}")
    print(f"Wrote {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
