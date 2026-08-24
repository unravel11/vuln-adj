#!/usr/bin/env python3
"""Validate and merge two blinded CWE taxonomy reviews."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = "results/rq2_discrepancy_typing/cwe_taxonomy"
DEFAULT_WORKLIST = f"{DEFAULT_DIR}/cwe_taxonomy_dual_review_worklist.blind.jsonl"
DEFAULT_CHANGED = f"{DEFAULT_DIR}/cwe_taxonomy_changed_cases.jsonl"
DEFAULT_PRIMARY_SOURCE = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_PRIMARY_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_primary.jsonl"
DEFAULT_REVIEW_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_review.jsonl"
DEFAULT_AGENT_A = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_dual_review_agent_a.jsonl"
)
DEFAULT_AGENT_B = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_dual_review_agent_b.jsonl"
)
OUTPUT_KEYS = {
    "review_id",
    "sample_id",
    "cve_id",
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "confidence",
    "needs_additional_review",
    "rationale",
    "supporting_cwe_paths",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--changed-cases", default=DEFAULT_CHANGED)
    parser.add_argument("--primary-source", default=DEFAULT_PRIMARY_SOURCE)
    parser.add_argument("--primary-candidate", default=DEFAULT_PRIMARY_CANDIDATE)
    parser.add_argument("--review-candidate", default=DEFAULT_REVIEW_CANDIDATE)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {error}") from error


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"Duplicate {key} in {path}: {value}")
        rows[value] = row
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def allowed_paths(source: dict) -> set[str]:
    result = set()
    for relation in source["official_cross_source_ancestor_descendant_paths"]:
        path = relation["path"]
        result.add(">".join(item["cwe_id"] for item in path))
        result.add(">".join(item["cwe_id"] for item in reversed(path)))
    return result


def validate_reviews(path: Path, worklist: list[dict]) -> list[dict]:
    reviews = list(iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(
            f"Review row count mismatch for {path}: {len(reviews)} != {len(worklist)}"
        )
    seen = set()
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != OUTPUT_KEYS:
            missing = sorted(OUTPUT_KEYS - set(review))
            extra = sorted(set(review) - OUTPUT_KEYS)
            raise ValueError(
                f"Schema mismatch at {path}:{index}; missing={missing}, extra={extra}"
            )
        for key in ("review_id", "sample_id", "cve_id"):
            if review[key] != source[key]:
                raise ValueError(f"Identity mismatch at {path}:{index} for {key}")
        if review["review_id"] in seen:
            raise ValueError(f"Duplicate review_id in {path}: {review['review_id']}")
        seen.add(review["review_id"])
        contract = source["review_contract"]
        for key in (
            "set_relation",
            "discrepancy_label",
            "taxonomy_support_verdict",
            "confidence",
        ):
            if review[key] not in contract[key]:
                raise ValueError(f"Invalid {key} at {path}:{index}: {review[key]!r}")
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(f"needs_additional_review must be boolean at {path}:{index}")
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"Low-confidence row must request review at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(review["rationale"].strip()) < 40:
            raise ValueError(f"Rationale too short at {path}:{index}")
        paths = review["supporting_cwe_paths"]
        if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
            raise ValueError(f"supporting_cwe_paths must be a string list at {path}:{index}")
        if len(paths) != len(set(paths)):
            raise ValueError(f"Duplicate supporting path at {path}:{index}")
        unknown = set(paths) - allowed_paths(source)
        if unknown:
            raise ValueError(f"Unknown supporting paths at {path}:{index}: {sorted(unknown)}")
        if (
            review["taxonomy_support_verdict"] == "supports_granularity_only"
            and not paths
        ):
            raise ValueError(f"Granularity support requires an official path at {path}:{index}")
    return reviews


def cohen_kappa(left: list[object], right: list[object]) -> tuple[float | None, str]:
    if len(left) != len(right) or not left:
        raise ValueError("Kappa inputs must have the same non-zero length")
    labels = set(left) | set(right)
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    expected = sum(
        (left_counts[label] / len(left)) * (right_counts[label] / len(right))
        for label in labels
    )
    if expected == 1.0:
        return None, "undefined_single_class_marginals"
    return (observed - expected) / (1.0 - expected), "defined"


def agreement_summary(agent_a: list[dict], agent_b: list[dict], key: str) -> dict:
    left = [row[key] for row in agent_a]
    right = [row[key] for row in agent_b]
    agreement = sum(a == b for a, b in zip(left, right))
    kappa, status = cohen_kappa(left, right)
    return {
        "agreement_count": agreement,
        "agreement_rate": agreement / len(left),
        "cohen_kappa": kappa,
        "cohen_kappa_status": status,
        "agent_a_counts": dict(sorted(Counter(left).items())),
        "agent_b_counts": dict(sorted(Counter(right).items())),
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# CWE Taxonomy Dual-AI Review",
        "",
        "This is a blinded dual-AI candidate review grounded in CWE 4.20, not human-gold or independent human annotation.",
        "",
        "| Component | Agreement | Rate | Kappa |",
        "| --- | ---: | ---: | ---: |",
    ]
    for key, values in summary["component_agreement"].items():
        kappa = "undefined" if values["cohen_kappa"] is None else f"{values['cohen_kappa']:.4f}"
        lines.append(
            f"| {key} | {values['agreement_count']}/{summary['row_count']} | "
            f"{values['agreement_rate']:.4f} | {kappa} |"
        )
    comparison = summary["consensus_label_comparison"]
    coverage = summary["taxonomy_v1_changed_row_review_coverage"]
    selection = summary["method_selection"]
    lines.extend(
        [
            "",
            f"Full three-component consensus: {summary['full_decision_consensus_count']}/{summary['row_count']}.",
            f"Consensus-label rows: {comparison['consensus_label_rows']}; current agreement: {comparison['current_agreement_count']}; taxonomy_v1 agreement: {comparison['taxonomy_v1_agreement_count']}; prior primary candidate agreement: {comparison['primary_candidate_agreement_count']}; available prior review agreement: {comparison['review_candidate_agreement_count']}/{comparison['review_candidate_rows']}.",
            f"taxonomy_v1 changed-row coverage in this blind batch: {coverage['reviewed_changed_rows']}/{coverage['total_changed_rows']}; reviewed changed rows with a consensus label: {coverage['reviewed_changed_rows_with_consensus_label']}.",
            f"Method selection: {selection['status']}; production default changed: {str(selection['production_default_changed']).lower()}; eligible for final paper claim: {str(selection['eligible_for_final_paper_claim']).lower()}.",
            "",
            "The rows were selected from candidate or repeatability disagreements. These counts are targeted diagnostics and must not be generalized to the full corpus.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist_path = resolve_path(args.worklist)
    changed_path = resolve_path(args.changed_cases)
    primary_source_path = resolve_path(args.primary_source)
    primary_candidate_path = resolve_path(args.primary_candidate)
    review_candidate_path = resolve_path(args.review_candidate)
    agent_a_path = resolve_path(args.agent_a)
    agent_b_path = resolve_path(args.agent_b)
    output_dir = resolve_path(args.output_dir)

    worklist = list(iter_jsonl(worklist_path))
    if len(worklist) != 15:
        raise ValueError(f"Expected 15 worklist rows, found {len(worklist)}")
    agent_a = validate_reviews(agent_a_path, worklist)
    agent_b = validate_reviews(agent_b_path, worklist)
    changed = load_unique(changed_path, "cve_id")
    primary_source = load_unique(primary_source_path, "sample_id")
    primary_candidate = load_unique(primary_candidate_path, "sample_id")
    review_candidate_rows = load_unique(review_candidate_path, "sample_id")
    review_by_original = {
        row["original_sample_id"]: row for row in review_candidate_rows.values()
    }

    merged = []
    full_consensus = 0
    for source, left, right in zip(worklist, agent_a, agent_b):
        sample_id = source["sample_id"]
        source_row = primary_source[sample_id]
        current = source_row["baseline_status"]
        taxonomy_v1 = changed.get(source["cve_id"], {}).get(
            "taxonomy_v1_status", current
        )
        consensus = {
            key: left[key] if left[key] == right[key] else None
            for key in (
                "set_relation",
                "discrepancy_label",
                "taxonomy_support_verdict",
            )
        }
        decision_consensus = all(value is not None for value in consensus.values())
        full_consensus += decision_consensus
        review_row = review_by_original.get(sample_id)
        merged.append(
            {
                "review_id": source["review_id"],
                "sample_id": sample_id,
                "cve_id": source["cve_id"],
                "label_is_human": False,
                "independent_human_review": False,
                "requires_human_signoff": True,
                "candidate_status": (
                    "dual_ai_consensus" if decision_consensus else "dual_ai_disagreement"
                ),
                "decision_consensus": decision_consensus,
                "consensus": consensus,
                "agent_a": left,
                "agent_b": right,
                "consensus_label": consensus["discrepancy_label"],
                "current_prediction": current,
                "taxonomy_v1_prediction": taxonomy_v1,
                "primary_candidate_label": primary_candidate[sample_id]["annotation"][
                    "discrepancy_label"
                ],
                "review_candidate_label": (
                    review_row["annotation"]["discrepancy_label"]
                    if review_row
                    else None
                ),
            }
        )

    consensus_rows = [row for row in merged if row["consensus_label"] is not None]
    changed_review_rows = [
        row for row in merged if row["cve_id"] in changed
    ]
    changed_review_consensus_rows = [
        row for row in changed_review_rows if row["consensus_label"] is not None
    ]
    review_rows = [
        row
        for row in consensus_rows
        if row["review_candidate_label"] is not None
    ]
    comparison = {
        "consensus_label_rows": len(consensus_rows),
        "current_agreement_count": sum(
            row["consensus_label"] == row["current_prediction"]
            for row in consensus_rows
        ),
        "taxonomy_v1_agreement_count": sum(
            row["consensus_label"] == row["taxonomy_v1_prediction"]
            for row in consensus_rows
        ),
        "primary_candidate_agreement_count": sum(
            row["consensus_label"] == row["primary_candidate_label"]
            for row in consensus_rows
        ),
        "review_candidate_rows": len(review_rows),
        "review_candidate_agreement_count": sum(
            row["consensus_label"] == row["review_candidate_label"]
            for row in review_rows
        ),
    }
    component_keys = (
        "set_relation",
        "discrepancy_label",
        "taxonomy_support_verdict",
        "confidence",
        "needs_additional_review",
    )
    summary = {
        "artifact_type": "cwe_taxonomy_dual_ai_review",
        "label_is_human": False,
        "independent_human_annotators": False,
        "same_model_family_separate_passes": True,
        "blinded_until_reviews_completed": True,
        "selected_disagreement_set": True,
        "cwe_catalog_version": "4.20",
        "row_count": len(merged),
        "component_agreement": {
            key: agreement_summary(agent_a, agent_b, key) for key in component_keys
        },
        "full_decision_consensus_count": full_consensus,
        "full_decision_consensus_rate": full_consensus / len(merged),
        "rows_requiring_additional_review_either_agent": sum(
            left["needs_additional_review"] or right["needs_additional_review"]
            for left, right in zip(agent_a, agent_b)
        ),
        "human_signed_rows": 0,
        "consensus_label_comparison": comparison,
        "taxonomy_v1_changed_row_review_coverage": {
            "total_changed_rows": len(changed),
            "reviewed_changed_rows": len(changed_review_rows),
            "reviewed_changed_rows_with_consensus_label": len(
                changed_review_consensus_rows
            ),
            "taxonomy_v1_agreement_count": sum(
                row["consensus_label"] == row["taxonomy_v1_prediction"]
                for row in changed_review_consensus_rows
            ),
            "current_agreement_count": sum(
                row["consensus_label"] == row["current_prediction"]
                for row in changed_review_consensus_rows
            ),
        },
        "method_selection": {
            "status": "unresolved_candidate_diagnostic_only",
            "production_default_changed": False,
            "eligible_for_final_paper_claim": False,
            "reason": (
                "The blinded targeted batch covers only one of seventeen "
                "taxonomy_v1 changes. Its consensus supports taxonomy_v1 for that "
                "row, but the remaining changed rows have no independent review "
                "and the primary/review candidate diagnostics move in opposite "
                "directions."
            ),
        },
        "input_paths": {
            "worklist": str(worklist_path),
            "agent_a": str(agent_a_path),
            "agent_b": str(agent_b_path),
            "changed_cases": str(changed_path),
        },
        "input_sha256": {
            "worklist": sha256(worklist_path),
            "agent_a": sha256(agent_a_path),
            "agent_b": sha256(agent_b_path),
            "changed_cases": sha256(changed_path),
        },
        "cautions": [
            "Both reviewers are separate passes of the same AI model family.",
            "The fifteen rows were selected from candidate or repeatability disagreements.",
            "Official CWE ancestry supports taxonomy compatibility, not CVE-specific correctness.",
            "Human annotator, independent reviewer, and author sign-off remain required for human-gold.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "cwe_taxonomy_dual_ai_candidate.jsonl"
    with merged_path.open("w", encoding="utf-8") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    json_path = output_dir / "cwe_taxonomy_dual_ai_review.json"
    md_path = output_dir / "cwe_taxonomy_dual_ai_review.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {merged_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
