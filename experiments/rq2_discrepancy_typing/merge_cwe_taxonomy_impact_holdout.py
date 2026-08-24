#!/usr/bin/env python3
"""Validate dual Codex reviews and evaluate the sealed CWE impact holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = "results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout"
DEFAULT_MANIFEST = f"{DEFAULT_DIR}/cwe_taxonomy_impact_manifest.sealed.json"
DEFAULT_AGENT_A = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_impact_agent_a.jsonl"
)
DEFAULT_AGENT_B = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_impact_agent_b.jsonl"
)
OUTPUT_KEYS = {
    "reviewer_id",
    "run_id",
    "review_id",
    "cve_id",
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "confidence",
    "needs_additional_review",
    "rationale",
    "supporting_cwe_paths",
}
BOOTSTRAP_REPEATS = 10_000
BOOTSTRAP_SEED = 20260715


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
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


def allowed_paths(source: dict) -> set[str]:
    result = set()
    for relation in source["official_cross_source_ancestor_descendant_paths"]:
        path = relation["path"]
        forward = ">".join(item["cwe_id"] for item in path)
        reverse = ">".join(item["cwe_id"] for item in reversed(path))
        result.update((forward, reverse))
    return result


def validate_reviews(
    path: Path,
    worklist: list[dict],
    expected_reviewer_id: str,
) -> list[dict]:
    reviews = list(iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(f"review row count mismatch: {len(reviews)} != {len(worklist)}")
    run_ids = set()
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != OUTPUT_KEYS:
            raise ValueError(
                f"schema mismatch at {path}:{index}; "
                f"missing={sorted(OUTPUT_KEYS - set(review))}, "
                f"extra={sorted(set(review) - OUTPUT_KEYS)}"
            )
        if review["reviewer_id"] != expected_reviewer_id:
            raise ValueError(f"reviewer identity mismatch at {path}:{index}")
        if not isinstance(review["run_id"], str) or not review["run_id"].strip():
            raise ValueError(f"blank run_id at {path}:{index}")
        run_ids.add(review["run_id"])
        for key in ("review_id", "cve_id"):
            if review[key] != source[key]:
                raise ValueError(f"identity mismatch at {path}:{index} for {key}")
        contract = source["review_contract"]
        for key in (
            "set_relation",
            "discrepancy_label",
            "taxonomy_support_verdict",
            "confidence",
        ):
            if review[key] not in contract[key]:
                raise ValueError(f"invalid {key} at {path}:{index}")
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(f"needs_additional_review must be boolean at {path}:{index}")
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"low-confidence row must request review at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(review["rationale"].strip()) < 80:
            raise ValueError(f"rationale too short at {path}:{index}")
        paths = review["supporting_cwe_paths"]
        if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
            raise ValueError(f"supporting_cwe_paths must be a string list at {path}:{index}")
        if len(paths) != len(set(paths)):
            raise ValueError(f"duplicate supporting path at {path}:{index}")
        unknown_paths = set(paths) - allowed_paths(source)
        if unknown_paths:
            raise ValueError(f"unknown supporting paths at {path}:{index}: {sorted(unknown_paths)}")
        if (
            review["taxonomy_support_verdict"] == "supports_granularity_only"
            and not paths
        ):
            raise ValueError(f"granularity support requires a path at {path}:{index}")
    if len(run_ids) != 1:
        raise ValueError(f"expected one run_id in {path}, found {sorted(run_ids)}")
    return reviews


def cohen_kappa(left: list[object], right: list[object]) -> float | None:
    if len(left) != len(right) or not left:
        raise ValueError("kappa inputs must have equal non-zero length")
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    labels = set(left) | set(right)
    expected = sum(
        (left_counts[label] / len(left)) * (right_counts[label] / len(right))
        for label in labels
    )
    return None if expected == 1.0 else (observed - expected) / (1.0 - expected)


def component_summary(left: list[dict], right: list[dict], key: str) -> dict:
    left_values = [row[key] for row in left]
    right_values = [row[key] for row in right]
    agreement = sum(a == b for a, b in zip(left_values, right_values))
    return {
        "agreement_count": agreement,
        "agreement_rate": agreement / len(left_values),
        "cohen_kappa": cohen_kappa(left_values, right_values),
        "agent_a_counts": dict(sorted(Counter(left_values).items())),
        "agent_b_counts": dict(sorted(Counter(right_values).items())),
    }


def method_metrics(rows: list[dict], key: str) -> dict:
    correct = sum(row["consensus_label"] == row[key] for row in rows)
    return {
        "rows": len(rows),
        "correct": correct,
        "accuracy": correct / len(rows) if rows else None,
        "prediction_counts": dict(sorted(Counter(row[key] for row in rows).items())),
    }


def evaluate_subset(rows: list[dict]) -> dict:
    current = method_metrics(rows, "current_prediction")
    taxonomy = method_metrics(rows, "taxonomy_v1_prediction")
    return {
        "rows": len(rows),
        "consensus_label_counts": dict(
            sorted(Counter(row["consensus_label"] for row in rows).items())
        ),
        "current": current,
        "taxonomy_v1": taxonomy,
        "taxonomy_minus_current_accuracy": (
            taxonomy["accuracy"] - current["accuracy"] if rows else None
        ),
        "paired_diagnostic": paired_diagnostic(rows),
    }


def paired_diagnostic(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    differences = [
        int(row["consensus_label"] == row["taxonomy_v1_prediction"])
        - int(row["consensus_label"] == row["current_prediction"])
        for row in rows
    ]
    wins = sum(value > 0 for value in differences)
    losses = sum(value < 0 for value in differences)
    ties = sum(value == 0 for value in differences)
    rng = random.Random(BOOTSTRAP_SEED)
    bootstrap = sorted(
        sum(rng.choice(differences) for _ in differences) / len(differences)
        for _ in range(BOOTSTRAP_REPEATS)
    )
    lower = bootstrap[int(0.025 * (BOOTSTRAP_REPEATS - 1))]
    upper = bootstrap[int(0.975 * (BOOTSTRAP_REPEATS - 1))]
    non_ties = wins + losses
    if non_ties:
        tail = sum(
            math.comb(non_ties, index)
            for index in range(min(wins, losses) + 1)
        ) / (2**non_ties)
        exact_two_sided = min(1.0, 2 * tail)
    else:
        exact_two_sided = 1.0
    return {
        "taxonomy_wins": wins,
        "current_wins": losses,
        "ties": ties,
        "bootstrap_repeats": BOOTSTRAP_REPEATS,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "accuracy_delta_percentile_95_interval": [lower, upper],
        "exact_two_sided_sign_test_p": exact_two_sided,
        "interpretation": "post_hoc_nonhuman_sample_internal_diagnostic",
    }


def priority_reason(row: dict) -> str | None:
    left = row["agent_a"]["discrepancy_label"]
    right = row["agent_b"]["discrepancy_label"]
    if left != right or left == "uncertain":
        return "dual_codex_label_unresolved"
    if (
        row["strict_consensus"]
        and row["consensus_label"] == row["current_prediction"]
        and row["consensus_label"] != row["taxonomy_v1_prediction"]
    ):
        return "candidate_regression_on_strict_consensus"
    return None


def render_markdown(summary: dict) -> str:
    strict = summary["strict_consensus_evaluation"]
    disjoint = summary["primary_seed_disjoint_evaluation"]
    lines = [
        "# CWE Taxonomy Full-Impact Dual-Codex Audit",
        "",
        "This is a sealed, blind, non-human candidate audit. It is not human gold or independent-human validation.",
        "",
        f"Strict decision consensus: {summary['strict_consensus_rows']}/{summary['row_count']}.",
        "",
        "| Subset | Method | Correct/rows | Accuracy |",
        "|---|---|---:|---:|",
    ]
    for name, values in (("all strict", strict), ("primary-seed disjoint", disjoint)):
        for method in ("current", "taxonomy_v1"):
            metric = values[method]
            accuracy = "-" if metric["accuracy"] is None else f"{metric['accuracy']:.4f}"
            lines.append(
                f"| {name} | {method} | {metric['correct']}/{metric['rows']} | {accuracy} |"
            )
    lines.extend(
        [
            "",
            f"Primary-seed-disjoint paired delta: {disjoint['taxonomy_minus_current_accuracy']:.4f}; "
            f"95% row-bootstrap interval: {disjoint['paired_diagnostic']['accuracy_delta_percentile_95_interval']}; "
            f"exact sign diagnostic p={disjoint['paired_diagnostic']['exact_two_sided_sign_test_p']:.4f}.",
            "",
            f"Method status: `{summary['method_selection']['status']}`. Production default changed: `false`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    agent_a_path = resolve(args.agent_a)
    agent_b_path = resolve(args.agent_b)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["row_count"] != 17 or not manifest["reviewer_outputs_absent_at_seal"]:
        raise ValueError("invalid sealed manifest")

    worklist_path = Path(manifest["worklist"]["path"])
    predictions_path = Path(manifest["predictions"]["path"])
    if sha256(worklist_path) != manifest["worklist"]["sha256"]:
        raise ValueError("worklist hash mismatch")
    if sha256(predictions_path) != manifest["predictions"]["sha256"]:
        raise ValueError("prediction hash mismatch")
    for item in manifest["inputs"].values():
        if sha256(Path(item["path"])) != item["sha256"]:
            raise ValueError(f"sealed input hash mismatch: {item['path']}")
    if sha256(Path(manifest["code"]["path"])) != manifest["code"]["sha256"]:
        raise ValueError("builder code hash mismatch")
    if agent_a_path.resolve() == agent_b_path.resolve():
        raise ValueError("reviewer paths must differ")
    if not agent_a_path.exists() or not agent_b_path.exists():
        raise ValueError("both reviewer outputs are required")
    if agent_a_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent A output predates seal")
    if agent_b_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent B output predates seal")
    if sha256(agent_a_path) == sha256(agent_b_path):
        raise ValueError("reviewer outputs must not be identical")

    worklist = list(iter_jsonl(worklist_path))
    predictions = list(iter_jsonl(predictions_path))
    if len(worklist) != 17 or len(predictions) != 17:
        raise ValueError("sealed row count mismatch")
    agent_a = validate_reviews(agent_a_path, worklist, "codex_cwe_impact_a")
    agent_b = validate_reviews(agent_b_path, worklist, "codex_cwe_impact_b")
    if agent_a[0]["run_id"] == agent_b[0]["run_id"]:
        raise ValueError("reviewer run IDs must differ")

    primary_overlap = set(manifest["primary_seed_overlap_cves"])
    merged = []
    for source, prediction, left, right in zip(
        worklist, predictions, agent_a, agent_b
    ):
        for key in ("review_id", "cve_id"):
            if prediction[key] != source[key]:
                raise ValueError(f"prediction identity mismatch for {key}")
        consensus = {
            key: left[key] if left[key] == right[key] else None
            for key in (
                "set_relation",
                "discrepancy_label",
                "taxonomy_support_verdict",
            )
        }
        strict = (
            all(value is not None for value in consensus.values())
            and not left["needs_additional_review"]
            and not right["needs_additional_review"]
        )
        merged.append(
            {
                "review_id": source["review_id"],
                "cve_id": source["cve_id"],
                "label_is_human": False,
                "independent_human_review": False,
                "requires_human_signoff": True,
                "strict_consensus": strict,
                "consensus": consensus,
                "consensus_label": consensus["discrepancy_label"],
                "primary_seed_overlap": source["cve_id"] in primary_overlap,
                "current_prediction": prediction["current_prediction"],
                "taxonomy_v1_prediction": prediction["taxonomy_v1_prediction"],
                "agent_a": left,
                "agent_b": right,
            }
        )

    strict_rows = [row for row in merged if row["strict_consensus"]]
    disjoint_rows = [row for row in strict_rows if not row["primary_seed_overlap"]]
    strict_eval = evaluate_subset(strict_rows)
    disjoint_eval = evaluate_subset(disjoint_rows)
    delta = disjoint_eval["taxonomy_minus_current_accuracy"]
    if delta is not None and delta > 0:
        method_status = "supported_on_nonhuman_primary_seed_disjoint_impact_rows"
    elif delta == 0:
        method_status = "no_gain_on_nonhuman_primary_seed_disjoint_impact_rows"
    else:
        method_status = "worse_on_nonhuman_primary_seed_disjoint_impact_rows"

    summary = {
        "artifact_type": "rq2_cwe_taxonomy_impact_dual_codex_audit",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "sealed_before_reviews": True,
        "same_model_family_separate_runs": True,
        "row_count": len(merged),
        "primary_seed_overlap_rows": len(primary_overlap),
        "strict_consensus_rows": len(strict_rows),
        "strict_consensus_coverage": len(strict_rows) / len(merged),
        "component_agreement": {
            key: component_summary(agent_a, agent_b, key)
            for key in (
                "set_relation",
                "discrepancy_label",
                "taxonomy_support_verdict",
                "confidence",
                "needs_additional_review",
            )
        },
        "strict_consensus_evaluation": strict_eval,
        "primary_seed_disjoint_evaluation": disjoint_eval,
        "method_selection": {
            "status": method_status,
            "production_default_changed": False,
            "requires_human_signoff": True,
            "reason": (
                "The audit is sealed and mostly primary-seed disjoint, but both "
                "reviewers are Codex runs and official taxonomy ancestry does not "
                "establish CVE-specific human gold."
            ),
        },
        "human_signed_rows": 0,
        "human_priority_rows": sum(
            priority_reason(row) is not None for row in merged
        ),
        "human_priority_reason_counts": dict(
            sorted(
                Counter(
                    reason
                    for row in merged
                    if (reason := priority_reason(row)) is not None
                ).items()
            )
        ),
        "inputs": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "agent_a": str(agent_a_path),
            "agent_a_sha256": sha256(agent_a_path),
            "agent_b": str(agent_b_path),
            "agent_b_sha256": sha256(agent_b_path),
        },
        "cautions": [
            "The 17 rows are the complete changed-row impact set, not a representative corpus sample.",
            "Both reviewers are isolated runs of the same Codex model family.",
            "Strict consensus remains a non-human expert candidate requiring real human signoff.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "cwe_taxonomy_impact_dual_codex_candidate.jsonl"
    with merged_path.open("w", encoding="utf-8") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    worklist_by_id = {row["review_id"]: row for row in worklist}
    priority_path = output_dir / "cwe_taxonomy_human_priority_worklist.blind.jsonl"
    with priority_path.open("w", encoding="utf-8") as handle:
        rank = 0
        for row in merged:
            reason = priority_reason(row)
            if reason is None:
                continue
            rank += 1
            blind = worklist_by_id[row["review_id"]]
            handle.write(
                json.dumps(
                    {
                        "priority_rank": rank,
                        "selection_reason": "priority_audit",
                        **blind,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    json_path = output_dir / "cwe_taxonomy_impact_dual_codex_audit.json"
    md_path = output_dir / "cwe_taxonomy_impact_dual_codex_audit.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {merged_path}")
    print(f"Wrote {priority_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
