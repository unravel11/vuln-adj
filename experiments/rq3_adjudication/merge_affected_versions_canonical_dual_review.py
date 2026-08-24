#!/usr/bin/env python3
"""Validate and merge two blinded affected-version canonical-match reviews."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW_DIR = (
    "results/rq3_adjudication/affected_versions_canonical_dual_review"
)
DEFAULT_WORKLIST = f"{DEFAULT_REVIEW_DIR}/worklist.blind.jsonl"
DEFAULT_AGENT_A = (
    "data/annotations/expert_candidate/batches/"
    "rq3_affected_canonical_dual_review_agent_a.jsonl"
)
DEFAULT_AGENT_B = (
    "data/annotations/expert_candidate/batches/"
    "rq3_affected_canonical_dual_review_agent_b.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_CANDIDATE = "data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl"
RAW_METHOD = "version_token_support_baseline"
CANONICAL_METHOD = "canonical_version_token_support_baseline"
CONTEXTUAL_RAW_METHOD = "contextual_version_claim_baseline"
CONTEXTUAL_CANONICAL_METHOD = "contextual_canonical_version_claim_baseline"
PACKAGE_CONTEXTUAL_RAW_METHOD = "package_gated_contextual_version_claim_baseline"
PACKAGE_CONTEXTUAL_CANONICAL_METHOD = (
    "package_gated_contextual_canonical_version_claim_baseline"
)
OUTPUT_KEYS = {
    "review_id",
    "sample_id",
    "cve_id",
    "discrepancy_label",
    "adjudicated_source",
    "canonical_match_verdict",
    "recommended_match_policy",
    "confidence",
    "needs_additional_review",
    "rationale",
    "evidence_urls",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--candidate", default=DEFAULT_CANDIDATE)
    parser.add_argument("--output-dir", default=DEFAULT_REVIEW_DIR)
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def urls_in(value: object) -> set[str]:
    found = set()
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        found.add(value)
    elif isinstance(value, dict):
        for child in value.values():
            found.update(urls_in(child))
    elif isinstance(value, list):
        for child in value:
            found.update(urls_in(child))
    return found


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
        for identity_key in ("review_id", "sample_id", "cve_id"):
            if review[identity_key] != source[identity_key]:
                raise ValueError(
                    f"Identity mismatch at {path}:{index} for {identity_key}"
                )
        if review["review_id"] in seen:
            raise ValueError(f"Duplicate review_id in {path}: {review['review_id']}")
        seen.add(review["review_id"])
        contract = source["review_contract"]
        for key in (
            "discrepancy_label",
            "adjudicated_source",
            "canonical_match_verdict",
            "recommended_match_policy",
            "confidence",
        ):
            if review[key] not in contract[key]:
                raise ValueError(
                    f"Invalid {key} at {path}:{index}: {review[key]!r}"
                )
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(f"needs_additional_review must be boolean at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(review["rationale"].strip()) < 40:
            raise ValueError(f"Rationale too short at {path}:{index}")
        evidence_urls = review["evidence_urls"]
        if not isinstance(evidence_urls, list) or any(
            not isinstance(url, str) for url in evidence_urls
        ):
            raise ValueError(f"evidence_urls must be a string list at {path}:{index}")
        if len(evidence_urls) != len(set(evidence_urls)):
            raise ValueError(f"Duplicate evidence URL at {path}:{index}")
        unknown_urls = set(evidence_urls) - urls_in(source)
        if unknown_urls:
            raise ValueError(
                f"Untraceable evidence URLs at {path}:{index}: {sorted(unknown_urls)}"
            )
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"Low-confidence row must request review at {path}:{index}")
    return reviews


def load_predictions(path: Path) -> dict[tuple[str, str], dict]:
    rows = {}
    for row in iter_jsonl(path):
        if row.get("method") not in {
            RAW_METHOD,
            CANONICAL_METHOD,
            CONTEXTUAL_RAW_METHOD,
            CONTEXTUAL_CANONICAL_METHOD,
            PACKAGE_CONTEXTUAL_RAW_METHOD,
            PACKAGE_CONTEXTUAL_CANONICAL_METHOD,
        }:
            continue
        key = (row["sample_id"], row["method"])
        if key in rows:
            raise ValueError(f"Duplicate prediction: {key}")
        rows[key] = row
    return rows


def load_candidates(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate candidate: {sample_id}")
        rows[sample_id] = row["annotation"]
    return rows


def cohen_kappa(left: list[str], right: list[str]) -> tuple[float | None, str]:
    if len(left) != len(right) or not left:
        raise ValueError("Kappa inputs must have the same non-zero length")
    labels = sorted(set(left) | set(right))
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


def count_match(rows: list[dict], target_key: str, comparison_key: str) -> int:
    return sum(
        row[target_key] is not None and row[target_key] == row[comparison_key]
        for row in rows
    )


def render_markdown(summary: dict) -> str:
    lines = [
        "# Affected Versions Canonical Dual-AI Review",
        "",
        "This is a blinded dual-AI candidate review, not human-gold or independent human annotation.",
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
    comparisons = summary["consensus_source_comparison"]
    lines.extend(
        [
            "",
            f"Full four-component consensus: {summary['full_decision_consensus_count']}/{summary['row_count']}.",
            f"Consensus-source rows: {comparisons['consensus_source_rows']}; raw agreement: {comparisons['raw_agreement_count']}; canonical agreement: {comparisons['canonical_agreement_count']}; contextual raw agreement: {comparisons['contextual_raw_agreement_count']}; contextual canonical agreement: {comparisons['contextual_canonical_agreement_count']}; package-contextual raw agreement: {comparisons['package_contextual_raw_agreement_count']}; package-contextual canonical agreement: {comparisons['package_contextual_canonical_agreement_count']}; prior candidate agreement: {comparisons['prior_candidate_agreement_count']}; silver agreement: {comparisons['silver_agreement_count']}.",
            "",
            "The reviewed rows were selected because raw and canonical predictions differ. These counts are paired diagnostics on a deliberately selected set and must not be generalized to all 100 samples.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist_path = resolve_path(args.worklist)
    agent_a_path = resolve_path(args.agent_a)
    agent_b_path = resolve_path(args.agent_b)
    predictions_path = resolve_path(args.predictions)
    candidate_path = resolve_path(args.candidate)
    output_dir = resolve_path(args.output_dir)

    worklist = list(iter_jsonl(worklist_path))
    if len(worklist) != 10:
        raise ValueError(f"Expected 10 worklist rows, found {len(worklist)}")
    agent_a = validate_reviews(agent_a_path, worklist)
    agent_b = validate_reviews(agent_b_path, worklist)
    predictions = load_predictions(predictions_path)
    candidates = load_candidates(candidate_path)

    merged = []
    full_consensus = 0
    for source, left, right in zip(worklist, agent_a, agent_b):
        sample_id = source["sample_id"]
        consensus = {
            key: left[key] if left[key] == right[key] else None
            for key in (
                "discrepancy_label",
                "adjudicated_source",
                "canonical_match_verdict",
                "recommended_match_policy",
            )
        }
        decision_consensus = all(value is not None for value in consensus.values())
        full_consensus += decision_consensus
        raw = predictions[(sample_id, RAW_METHOD)]
        canonical = predictions[(sample_id, CANONICAL_METHOD)]
        contextual_raw = predictions[(sample_id, CONTEXTUAL_RAW_METHOD)]
        contextual_canonical = predictions[(sample_id, CONTEXTUAL_CANONICAL_METHOD)]
        package_contextual_raw = predictions[(sample_id, PACKAGE_CONTEXTUAL_RAW_METHOD)]
        package_contextual_canonical = predictions[
            (sample_id, PACKAGE_CONTEXTUAL_CANONICAL_METHOD)
        ]
        candidate = candidates[sample_id]
        if raw["silver_source"] != canonical["silver_source"]:
            raise ValueError(f"Silver target mismatch for {sample_id}")
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
                "comparison_unblinded_after_review": {
                    "raw_prediction": raw["predicted_source"],
                    "canonical_prediction": canonical["predicted_source"],
                    "contextual_raw_prediction": contextual_raw["predicted_source"],
                    "contextual_canonical_prediction": contextual_canonical[
                        "predicted_source"
                    ],
                    "package_contextual_raw_prediction": package_contextual_raw[
                        "predicted_source"
                    ],
                    "package_contextual_canonical_prediction": package_contextual_canonical[
                        "predicted_source"
                    ],
                    "prior_candidate_source": candidate["adjudicated_source"],
                    "silver_source": raw["silver_source"],
                },
            }
        )

    # Flatten comparison fields only after both blinded reviews are loaded.
    for row in merged:
        row["consensus_source"] = row["consensus"]["adjudicated_source"]
        row.update(row.pop("comparison_unblinded_after_review"))

    consensus_source_rows = sum(
        row["consensus"]["adjudicated_source"] is not None for row in merged
    )
    comparison = {
        "consensus_source_rows": consensus_source_rows,
        "raw_agreement_count": count_match(
            merged, "consensus_source", "raw_prediction"
        ),
        "canonical_agreement_count": count_match(
            merged, "consensus_source", "canonical_prediction"
        ),
        "contextual_raw_agreement_count": count_match(
            merged, "consensus_source", "contextual_raw_prediction"
        ),
        "contextual_canonical_agreement_count": count_match(
            merged, "consensus_source", "contextual_canonical_prediction"
        ),
        "package_contextual_raw_agreement_count": count_match(
            merged, "consensus_source", "package_contextual_raw_prediction"
        ),
        "package_contextual_canonical_agreement_count": count_match(
            merged, "consensus_source", "package_contextual_canonical_prediction"
        ),
        "prior_candidate_agreement_count": count_match(
            merged, "consensus_source", "prior_candidate_source"
        ),
        "silver_agreement_count": count_match(
            merged, "consensus_source", "silver_source"
        ),
    }

    component_keys = (
        "discrepancy_label",
        "adjudicated_source",
        "canonical_match_verdict",
        "recommended_match_policy",
        "confidence",
        "needs_additional_review",
    )
    summary = {
        "artifact_type": "affected_versions_canonical_dual_ai_review",
        "label_is_human": False,
        "independent_human_annotators": False,
        "same_model_family_separate_passes": True,
        "blinded_until_reviews_completed": True,
        "selected_method_disagreement_set": True,
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
        "consensus_source_comparison": comparison,
        "input_paths": {
            "worklist": str(worklist_path),
            "agent_a": str(agent_a_path),
            "agent_b": str(agent_b_path),
            "predictions": str(predictions_path),
            "candidate": str(candidate_path),
        },
        "input_sha256": {
            "worklist": sha256(worklist_path),
            "agent_a": sha256(agent_a_path),
            "agent_b": sha256(agent_b_path),
            "predictions": sha256(predictions_path),
            "candidate": sha256(candidate_path),
        },
        "cautions": [
            "Both reviewers are separate passes of the same AI model family.",
            "The ten rows were selected because raw and canonical method decisions differ.",
            "Reviewers used cached evidence only and did not verify live pages.",
            "Human annotator, independent reviewer, and author sign-off remain required for human-gold.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "dual_ai_candidate.jsonl"
    with merged_path.open("w", encoding="utf-8") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    json_path = output_dir / "dual_ai_review.json"
    md_path = output_dir / "dual_ai_review.md"
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
