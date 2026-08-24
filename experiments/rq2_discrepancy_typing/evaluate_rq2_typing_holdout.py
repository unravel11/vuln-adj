#!/usr/bin/env python3
"""Evaluate sealed RQ2 predictions against strict dual-Codex holdout consensus."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE = "data/annotations/holdout/rq2_typing_v1"
DEFAULT_REVIEW_DIR = "results/holdout/rq2_typing_v1"
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
    parser.add_argument("--review-dir", default=DEFAULT_REVIEW_DIR)
    parser.add_argument("--bootstrap-replicates", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260715)
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


def load_unique(path: Path) -> dict[str, dict]:
    result = {}
    for row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        if not sample_id or sample_id in result:
            raise ValueError(f"{path}: missing or duplicate sample_id={sample_id}")
        result[sample_id] = row
    return result


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def percentile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * probability)
    return ordered[index]


def macro_f1(records: list[dict], method: str) -> float:
    scores = []
    for label in LABELS:
        support = sum(row["gold"] == label for row in records)
        if not support:
            continue
        tp = sum(row["gold"] == label and row[method] == label for row in records)
        fp = sum(row["gold"] != label and row[method] == label for row in records)
        fn = sum(row["gold"] == label and row[method] != label for row in records)
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        scores.append(safe_divide(2 * precision * recall, precision + recall))
    return safe_divide(sum(scores), len(scores))


def method_metrics(records: list[dict], method: str) -> dict:
    strict = [row for row in records if row["strict"]]
    correct = [row for row in strict if row[method] == row["gold"]]
    all_weight = sum(row["weight"] for row in records)
    strict_weight = sum(row["weight"] for row in strict)
    correct_weight = sum(row["weight"] for row in correct)
    per_field = {}
    for field in sorted({row["field"] for row in records}):
        subset = [row for row in records if row["field"] == field]
        field_strict = [row for row in subset if row["strict"]]
        field_correct = [row for row in field_strict if row[method] == row["gold"]]
        per_field[field] = {
            "rows": len(subset),
            "strict_rows": len(field_strict),
            "strict_coverage": safe_divide(len(field_strict), len(subset)),
            "strict_correct": len(field_correct),
            "strict_accuracy": safe_divide(len(field_correct), len(field_strict)),
            "full_cohort_lower_bound_accuracy": safe_divide(len(field_correct), len(subset)),
        }
    return {
        "rows": len(records),
        "strict_rows": len(strict),
        "strict_coverage": safe_divide(len(strict), len(records)),
        "strict_correct": len(correct),
        "strict_accuracy": safe_divide(len(correct), len(strict)),
        "strict_macro_f1": macro_f1(strict, method),
        "full_cohort_lower_bound_accuracy": safe_divide(len(correct), len(records)),
        "corpus_reweighted_strict_coverage": safe_divide(strict_weight, all_weight),
        "corpus_reweighted_strict_accuracy": safe_divide(correct_weight, strict_weight),
        "per_field": per_field,
        "confusion_matrix": [
            {"gold": gold, "prediction": prediction, "count": count}
            for (gold, prediction), count in sorted(
                Counter((row["gold"], row[method]) for row in strict).items()
            )
        ],
    }


def reviewer_agreement(records: list[dict], reviewer: str, method: str) -> dict:
    eligible = [
        row
        for row in records
        if row[f"{reviewer}_label"] != "uncertain"
        and row[f"{reviewer}_confidence"] != "low"
    ]
    correct = sum(row[method] == row[f"{reviewer}_label"] for row in eligible)
    return {
        "eligible_rows": len(eligible),
        "coverage": safe_divide(len(eligible), len(records)),
        "agreement_count": correct,
        "agreement": safe_divide(correct, len(eligible)),
    }


def cluster_bootstrap(
    records: list[dict],
    method: str,
    replicates: int,
    seed: int,
) -> dict:
    if replicates < 1:
        raise ValueError("bootstrap_replicates must be positive")
    by_cve: dict[str, list[dict]] = defaultdict(list)
    for row in records:
        by_cve[row["cve_id"]].append(row)
    cves = sorted(by_cve)
    rng = random.Random(seed)
    strict_accuracy = []
    full_lower_bound = []
    weighted_strict_accuracy = []
    for _ in range(replicates):
        sampled = [rng.choice(cves) for _ in cves]
        counts = Counter(sampled)
        strict_total = strict_correct = 0
        all_total = 0
        strict_weight = correct_weight = 0.0
        for cve_id, multiplicity in counts.items():
            for row in by_cve[cve_id]:
                all_total += multiplicity
                if not row["strict"]:
                    continue
                strict_total += multiplicity
                weighted = row["weight"] * multiplicity
                strict_weight += weighted
                if row[method] == row["gold"]:
                    strict_correct += multiplicity
                    correct_weight += weighted
        if strict_total:
            strict_accuracy.append(strict_correct / strict_total)
        full_lower_bound.append(strict_correct / all_total)
        if strict_weight:
            weighted_strict_accuracy.append(correct_weight / strict_weight)
    return {
        "unit": "cve_cluster",
        "unique_cves": len(cves),
        "replicates": replicates,
        "seed": seed,
        "strict_accuracy_95_interval": [
            percentile(strict_accuracy, 0.025),
            percentile(strict_accuracy, 0.975),
        ],
        "full_cohort_lower_bound_accuracy_95_interval": [
            percentile(full_lower_bound, 0.025),
            percentile(full_lower_bound, 0.975),
        ],
        "corpus_reweighted_strict_accuracy_95_interval": [
            percentile(weighted_strict_accuracy, 0.025),
            percentile(weighted_strict_accuracy, 0.975),
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
            "gold": review["consensus_label"],
            "reviewer_a_label": review["reviewer_a"]["discrepancy_label"],
            "reviewer_a_confidence": review["reviewer_a"]["confidence"],
            "reviewer_b_label": review["reviewer_b"]["discrepancy_label"],
            "reviewer_b_confidence": review["reviewer_b"]["confidence"],
        }
        for method in METHODS:
            row[method] = prediction[method]
        if row["strict"] and row["gold"] not in LABELS:
            raise ValueError(f"{sample_id}: strict row lacks a valid consensus label")
        if not row["strict"] and row["gold"] is not None:
            raise ValueError(f"{sample_id}: unresolved row contains a consensus label")
        records.append(row)
    return records


def render_markdown(result: dict) -> str:
    lines = [
        "# RQ2 Typing Holdout Evaluation",
        "",
        "> Development-CVE-disjoint, prediction-sealed, dual-Codex diagnostic; not human gold.",
        "",
        f"Strict consensus coverage: `{result['strict_consensus_rows']}/{result['rows']}` (`{result['strict_consensus_coverage']:.4f}`).",
        "",
        "| Method | Strict correct | Strict accuracy | Macro-F1 | Full-cohort lower bound | Reweighted strict accuracy |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method in METHODS:
        values = result["methods"][method]
        lines.append(
            f"| {method} | {values['strict_correct']}/{values['strict_rows']} | "
            f"{values['strict_accuracy']:.4f} | {values['strict_macro_f1']:.4f} | "
            f"{values['full_cohort_lower_bound_accuracy']:.4f} | "
            f"{values['corpus_reweighted_strict_accuracy']:.4f} |"
        )
    lines.extend(
        [
            "",
            "All six method columns are identical on this holdout because every known reference/CWE development-impact CVE was excluded. The holdout estimates fresh-CVE typing stability, not candidate-profile impact.",
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
    merged_manifest = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    for section in ("inputs", "outputs"):
        for item in sealed.get(section, {}).values():
            if sha256(Path(item["path"])) != item["sha256"]:
                raise ValueError(f"sealed manifest hash mismatch: {item['path']}")
    for section in ("inputs", "outputs"):
        for item in merged_manifest.get(section, {}).values():
            if sha256(Path(item["path"])) != item["sha256"]:
                raise ValueError(f"merge manifest hash mismatch: {item['path']}")
    if sealed.get("candidate_profile_comparison_identifiable") is not False:
        raise ValueError("holdout candidate-profile boundary changed")

    source_path = Path(sealed["outputs"]["source_rows"]["path"])
    prediction_path = Path(sealed["outputs"]["predictions"]["path"])
    consensus_path = Path(merged_manifest["outputs"]["consensus"]["path"])
    records = build_records(
        load_unique(source_path),
        load_unique(prediction_path),
        load_unique(consensus_path),
    )
    if len(records) != sealed.get("selected_rows") or len(records) != 1250:
        raise ValueError(f"expected 1250 evaluation rows, found {len(records)}")
    profile_differences = sum(
        len({row[method] for method in METHODS}) > 1 for row in records
    )
    if profile_differences != 0:
        raise ValueError("candidate profiles differ despite the sealed non-identifiable boundary")

    strict_rows = sum(row["strict"] for row in records)
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
        "artifact_type": "rq2_typing_holdout_evaluation",
        "label_source": "strict_dual_codex_consensus",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_method_gain_claim": False,
        "production_default_changed": False,
        "rows": len(records),
        "unique_cves": len({row["cve_id"] for row in records}),
        "strict_consensus_rows": strict_rows,
        "strict_consensus_coverage": strict_rows / len(records),
        "candidate_profile_comparison_identifiable": False,
        "candidate_profile_prediction_differences": profile_differences,
        "methods": methods,
        "source_manifests": {
            "sealed_holdout": {"path": str(sealed_manifest_path), "sha256": sha256(sealed_manifest_path)},
            "dual_review_merge": {"path": str(merge_manifest_path), "sha256": sha256(merge_manifest_path)},
        },
        "claim_boundary": (
            "The result measures agreement with selective strict consensus from two related "
            "Codex runs on a current-status-stratified sample. It is not human-gold performance, "
            "and the excluded development-impact sets make candidate-profile gain unidentifiable."
        ),
    }
    json_path = review_dir / "typing_holdout_evaluation.json"
    md_path = review_dir / "typing_holdout_evaluation.md"
    evaluation_manifest_path = review_dir / "evaluation_manifest.json"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(result), encoding="utf-8")
    evaluation_manifest = {
        "artifact_type": "rq2_typing_holdout_evaluation_manifest",
        "label_is_human": False,
        "inputs": result["source_manifests"],
        "outputs": {
            "json": {"path": str(json_path), "sha256": sha256(json_path)},
            "markdown": {"path": str(md_path), "sha256": sha256(md_path)},
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
