#!/usr/bin/env python3
"""Evaluate sealed RQ2 profiles against selective dual-Codex consensus."""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from merge_rq2_typing_holdout_reviews import load_unique, sha256  # noqa: E402


DEFAULT_BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_REVIEW = "results/holdout/rq2_post_profile_snapshot_v1/review"
METHODS = (
    "current",
    "reference_resource_identity_original_v1",
    "reference_resource_identity_audited_v1",
    "cwe_taxonomy_v1",
    "combined_original_v1",
    "combined_audited_v1",
)
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--review-dir", default=DEFAULT_REVIEW)
    parser.add_argument("--bootstrap-replicates", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260719)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def percentile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * probability)]


def macro_f1(records: list[dict], method: str) -> float:
    scores = []
    for label in LABELS:
        support = sum(row["target"] == label for row in records)
        if not support:
            continue
        tp = sum(row["target"] == label and row[method] == label for row in records)
        fp = sum(row["target"] != label and row[method] == label for row in records)
        fn = sum(row["target"] == label and row[method] != label for row in records)
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        scores.append(safe_divide(2 * precision * recall, precision + recall))
    return safe_divide(sum(scores), len(scores))


def method_metrics(records: list[dict], method: str) -> dict:
    strict = [row for row in records if row["strict"]]
    correct = [row for row in strict if row[method] == row["target"]]
    all_weight = sum(row["weight"] for row in records)
    strict_weight = sum(row["weight"] for row in strict)
    correct_weight = sum(row["weight"] for row in correct)
    per_field = {}
    for field in sorted({row["field"] for row in records}):
        subset = [row for row in records if row["field"] == field]
        field_strict = [row for row in subset if row["strict"]]
        field_correct = [row for row in field_strict if row[method] == row["target"]]
        per_field[field] = {
            "rows": len(subset),
            "strict_consensus_rows": len(field_strict),
            "strict_consensus_coverage": safe_divide(len(field_strict), len(subset)),
            "agreement_count": len(field_correct),
            "agreement": safe_divide(len(field_correct), len(field_strict)),
        }
    return {
        "rows": len(records),
        "strict_consensus_rows": len(strict),
        "strict_consensus_coverage": safe_divide(len(strict), len(records)),
        "agreement_count": len(correct),
        "strict_consensus_agreement": safe_divide(len(correct), len(strict)),
        "strict_consensus_macro_f1": macro_f1(strict, method),
        "full_cohort_lower_bound_agreement": safe_divide(len(correct), len(records)),
        "corpus_reweighted_strict_coverage": safe_divide(strict_weight, all_weight),
        "corpus_reweighted_strict_agreement": safe_divide(correct_weight, strict_weight),
        "per_field": per_field,
        "confusion_matrix": [
            {"consensus": target, "prediction": prediction, "count": count}
            for (target, prediction), count in sorted(
                Counter((row["target"], row[method]) for row in strict).items()
            )
        ],
    }


def reviewer_agreement(records: list[dict], reviewer: str, method: str) -> dict:
    eligible = [
        row
        for row in records
        if row[f"{reviewer}_label"] != "uncertain"
        and row[f"{reviewer}_confidence"] != "low"
        and row[f"{reviewer}_needs_review"] is False
    ]
    matched = sum(row[method] == row[f"{reviewer}_label"] for row in eligible)
    return {
        "eligible_rows": len(eligible),
        "coverage": safe_divide(len(eligible), len(records)),
        "agreement_count": matched,
        "agreement": safe_divide(matched, len(eligible)),
    }


def cluster_bootstrap(
    records: list[dict], method: str, replicates: int, seed: int
) -> dict:
    if replicates < 1:
        raise ValueError("bootstrap_replicates must be positive")
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for row in records:
        by_cve[row["cve_id"]].append(row)
    cves = sorted(by_cve)
    rng = random.Random(seed)
    strict_agreement = []
    full_lower_bound = []
    weighted_agreement = []
    for _ in range(replicates):
        multiplicities = Counter(rng.choice(cves) for _ in cves)
        strict_total = strict_matches = all_total = 0
        strict_weight = matched_weight = 0.0
        for cve_id, multiplicity in multiplicities.items():
            for row in by_cve[cve_id]:
                all_total += multiplicity
                if not row["strict"]:
                    continue
                strict_total += multiplicity
                weight = row["weight"] * multiplicity
                strict_weight += weight
                if row[method] == row["target"]:
                    strict_matches += multiplicity
                    matched_weight += weight
        if strict_total:
            strict_agreement.append(strict_matches / strict_total)
        full_lower_bound.append(strict_matches / all_total)
        if strict_weight:
            weighted_agreement.append(matched_weight / strict_weight)
    return {
        "unit": "cve_cluster",
        "unique_cves": len(cves),
        "replicates": replicates,
        "seed": seed,
        "strict_consensus_agreement_95_interval": [
            percentile(strict_agreement, 0.025),
            percentile(strict_agreement, 0.975),
        ],
        "full_cohort_lower_bound_agreement_95_interval": [
            percentile(full_lower_bound, 0.025),
            percentile(full_lower_bound, 0.975),
        ],
        "corpus_reweighted_strict_agreement_95_interval": [
            percentile(weighted_agreement, 0.025),
            percentile(weighted_agreement, 0.975),
        ],
    }


def build_records(
    source: dict[str, dict],
    predictions: dict[str, dict],
    consensus: dict[str, dict],
) -> list[dict]:
    if set(source) != set(predictions) or set(source) != set(consensus):
        raise ValueError("source, prediction, and consensus sample sets differ")
    records = []
    for sample_id, source_row in source.items():
        prediction = predictions[sample_id]
        review = consensus[sample_id]
        if (
            source_row["cve_id"] != prediction["cve_id"]
            or source_row["cve_id"] != review["cve_id"]
            or source_row["field"] != prediction["field"]
            or source_row["field"] != review["field"]
        ):
            raise ValueError(f"{sample_id}: identity mismatch")
        row = {
            "sample_id": sample_id,
            "cve_id": source_row["cve_id"],
            "field": source_row["field"],
            "weight": float(source_row["sampling_stratum"]["design_weight"]),
            "strict": review["strict_consensus"] is True,
            "target": review["consensus_label"],
            "reviewer_a_label": review["reviewer_a"]["discrepancy_label"],
            "reviewer_a_confidence": review["reviewer_a"]["confidence"],
            "reviewer_a_needs_review": review["reviewer_a"]["needs_human_review"],
            "reviewer_b_label": review["reviewer_b"]["discrepancy_label"],
            "reviewer_b_confidence": review["reviewer_b"]["confidence"],
            "reviewer_b_needs_review": review["reviewer_b"]["needs_human_review"],
        }
        for method in METHODS:
            row[method] = prediction[method]
        if row["strict"] and row["target"] not in LABELS:
            raise ValueError(f"{sample_id}: strict row lacks a valid consensus label")
        if not row["strict"] and row["target"] is not None:
            raise ValueError(f"{sample_id}: unresolved row contains a consensus label")
        records.append(row)
    return records


def paired_profile_comparison(records: list[dict], method: str) -> dict:
    differential = [row for row in records if row[method] != row["current"]]
    strict = [row for row in differential if row["strict"]]
    current_matches = sum(row["current"] == row["target"] for row in strict)
    method_matches = sum(row[method] == row["target"] for row in strict)
    return {
        "prediction_difference_rows": len(differential),
        "strict_consensus_difference_rows": len(strict),
        "current_agreement_count": current_matches,
        "candidate_agreement_count": method_matches,
        "candidate_minus_current_agreement_count": method_matches - current_matches,
        "rows": [
            {
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "field": row["field"],
                "strict_consensus": row["strict"],
                "consensus_label": row["target"],
                "current": row["current"],
                "candidate": row[method],
            }
            for row in differential
        ],
    }


def render_markdown(result: dict) -> str:
    lines = [
        "# RQ2 Snapshot-External Profile Evaluation",
        "",
        "> Selective dual-Codex expert-candidate consensus on a development-only snapshot-external cohort; not human gold or event-time confirmation.",
        "",
        f"Strict consensus coverage: `{result['strict_consensus_rows']}/{result['rows']}` (`{result['strict_consensus_coverage']:.4f}`).",
        f"Candidate-profile prediction differences: `{result['candidate_profile_prediction_difference_rows']}` rows.",
        "",
        "| Method | Strict matches | Agreement | Macro-F1 | Full lower bound | Reweighted agreement |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in METHODS:
        values = result["methods"][method]
        lines.append(
            f"| {method} | {values['agreement_count']}/{values['strict_consensus_rows']} | "
            f"{values['strict_consensus_agreement']:.4f} | "
            f"{values['strict_consensus_macro_f1']:.4f} | "
            f"{values['full_cohort_lower_bound_agreement']:.4f} | "
            f"{values['corpus_reweighted_strict_agreement']:.4f} |"
        )
    lines.extend(
        [
            "",
            "Only three naturally sampled rows distinguish the CWE candidate from current. Any observed paired difference is descriptive and cannot justify a production switch.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    review_dir = resolve(args.review_dir)
    sealed_manifest_path = base_dir / "manifest.sealed.json"
    merge_manifest_path = review_dir / "merge_manifest.json"
    sealed = json.loads(sealed_manifest_path.read_text(encoding="utf-8"))
    merged = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected sealed cohort manifest")
    if merged.get("artifact_type") != "rq2_post_profile_snapshot_merge_manifest":
        raise ValueError("unexpected merge manifest")
    for manifest in (sealed, merged):
        for section in ("inputs", "outputs"):
            for item in manifest.get(section, {}).values():
                path = Path(item["path"])
                if not path.is_file() or sha256(path) != item["sha256"]:
                    raise ValueError(f"manifest hash mismatch: {path}")

    source_path = Path(sealed["outputs"]["source_rows"]["path"])
    prediction_path = Path(sealed["outputs"]["predictions"]["path"])
    consensus_path = Path(merged["outputs"]["consensus"]["path"])
    records = build_records(
        load_unique(source_path),
        load_unique(prediction_path),
        load_unique(consensus_path),
    )
    if len(records) != sealed["selected_rows"] or len(records) != 250:
        raise ValueError(f"expected 250 evaluation rows, found {len(records)}")
    difference_rows = sum(len({row[method] for method in METHODS}) > 1 for row in records)
    if difference_rows != sealed["candidate_profile_prediction_difference_rows"]:
        raise ValueError("candidate profile difference count differs from seal")

    methods = {}
    for index, method in enumerate(METHODS):
        methods[method] = {
            **method_metrics(records, method),
            "reviewer_a_determinate_agreement": reviewer_agreement(records, "reviewer_a", method),
            "reviewer_b_determinate_agreement": reviewer_agreement(records, "reviewer_b", method),
            "cve_cluster_bootstrap": cluster_bootstrap(
                records,
                method,
                args.bootstrap_replicates,
                args.bootstrap_seed + index,
            ),
        }
    result = {
        "artifact_type": "rq2_post_profile_snapshot_profile_evaluation",
        "selected_tier": "snapshot_external",
        "snapshot_external_is_time_confirmatory": False,
        "label_source": "selective_strict_dual_codex_expert_candidate_consensus",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_method_gain_claim": False,
        "production_default_changed": False,
        "rows": len(records),
        "unique_cves": len({row["cve_id"] for row in records}),
        "strict_consensus_rows": sum(row["strict"] for row in records),
        "strict_consensus_coverage": safe_divide(sum(row["strict"] for row in records), len(records)),
        "candidate_profile_comparison_identifiable": difference_rows > 0,
        "candidate_profile_prediction_difference_rows": difference_rows,
        "methods": methods,
        "paired_profile_comparisons": {
            method: paired_profile_comparison(records, method)
            for method in METHODS[1:]
        },
        "source_manifests": {
            "sealed_cohort": {"path": str(sealed_manifest_path), "sha256": sha256(sealed_manifest_path)},
            "dual_review_merge": {"path": str(merge_manifest_path), "sha256": sha256(merge_manifest_path)},
        },
        "claim_boundary": (
            "The cohort was collected after profile sealing but is snapshot-external rather "
            "than strict event-time. Targets are selective agreement from two isolated Codex "
            "passes, not human labels. Only three sampled rows distinguish candidate profiles, "
            "so paired differences are descriptive and production switching is disallowed."
        ),
    }
    json_path = review_dir / "profile_evaluation.json"
    markdown_path = review_dir / "profile_evaluation.md"
    evaluation_manifest_path = review_dir / "evaluation_manifest.json"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    evaluation_manifest = {
        "artifact_type": "rq2_post_profile_snapshot_evaluation_manifest",
        "label_is_human": False,
        "inputs": result["source_manifests"],
        "outputs": {
            "json": {"path": str(json_path), "sha256": sha256(json_path)},
            "markdown": {"path": str(markdown_path), "sha256": sha256(markdown_path)},
        },
    }
    evaluation_manifest_path.write_text(
        json.dumps(evaluation_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
