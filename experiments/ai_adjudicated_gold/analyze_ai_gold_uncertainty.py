#!/usr/bin/env python3
"""Quantify paired uncertainty for AI-gold diagnostic method comparisons."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RQ2_LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
SOURCE_LABELS = ("nvd", "ghsa", "both", "neither")
RQ2_PAIRS = (
    ("current", "reference_resource_identity_v1"),
    ("current", "cwe_taxonomy_v1"),
    ("current", "combined_candidate_v1"),
)
RQ3_PAIRS = {
    "severity": (("prefer_nvd", "evidence_score_baseline"),),
    "affected_versions": (
        ("version_token_support_baseline", "canonical_version_token_support_baseline"),
        ("version_token_support_baseline", "contextual_canonical_version_claim_baseline"),
        ("version_token_support_baseline", "package_gated_token_baseline"),
        (
            "package_gated_token_baseline",
            "repository_crosswalk_package_gated_token_baseline",
        ),
        (
            "package_gated_canonical_token_baseline",
            "repository_crosswalk_package_gated_canonical_token_baseline",
        ),
        (
            "repository_crosswalk_package_gated_token_baseline",
            "repository_crosswalk_package_gated_canonical_token_baseline",
        ),
        ("package_gated_token_baseline", "package_range_evidence_baseline"),
    ),
}
RQ3_INPUTS = {
    "severity": {
        "gold": "data/annotations/ai_adjudicated_gold/rq3_severity.jsonl",
        "predictions": "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
        "expected_rows": 80,
    },
    "affected_versions": {
        "gold": "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl",
        "predictions": "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl",
        "expected_rows": 100,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-replicates", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260715)
    parser.add_argument(
        "--output-dir", default="results/ai_adjudicated_gold/uncertainty"
    )
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            yield row


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row.get(key)
        if not value or value in rows:
            raise ValueError(f"{path}: missing or duplicate {key}={value}")
        rows[value] = row
    if not rows:
        raise ValueError(f"{path}: no rows")
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def macro_f1(gold: list[str], predicted: list[str], labels: tuple[str, ...]) -> float:
    values = []
    for label in labels:
        support = sum(value == label for value in gold)
        if not support:
            continue
        tp = sum(g == label and p == label for g, p in zip(gold, predicted))
        fp = sum(g != label and p == label for g, p in zip(gold, predicted))
        fn = sum(g == label and p != label for g, p in zip(gold, predicted))
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        values.append(safe_divide(2 * precision * recall, precision + recall))
    return safe_divide(sum(values), len(values))


def method_metrics(
    records: list[dict],
    method: str,
    labels: tuple[str, ...],
    indices: list[int] | None = None,
) -> dict:
    selected = records if indices is None else [records[index] for index in indices]
    gold = [row["gold"] for row in selected]
    predicted = [row["predictions"][method] for row in selected]
    correct = sum(left == right for left, right in zip(gold, predicted))
    covered = [
        (left, right)
        for left, right in zip(gold, predicted)
        if right != "abstain"
    ]
    covered_correct = sum(left == right for left, right in covered)
    return {
        "accuracy": safe_divide(correct, len(selected)),
        "macro_f1": macro_f1(gold, predicted, labels),
        "prediction_coverage": safe_divide(len(covered), len(selected)),
        "selective_accuracy": safe_divide(covered_correct, len(covered)),
    }


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def interval(values: list[float]) -> list[float]:
    return [percentile(values, 0.025), percentile(values, 0.975)]


def stratified_indices(records: list[dict], rng: random.Random) -> list[int]:
    groups = defaultdict(list)
    for index, row in enumerate(records):
        groups[row["stratum"]].append(index)
    sampled = []
    for stratum in sorted(groups):
        members = groups[stratum]
        sampled.extend(rng.choice(members) for _ in members)
    return sampled


def exact_mcnemar_p(candidate_only: int, baseline_only: int) -> float:
    discordant = candidate_only + baseline_only
    if not discordant:
        return 1.0
    tail = min(candidate_only, baseline_only)
    probability = sum(
        math.comb(discordant, value) for value in range(tail + 1)
    ) / (2**discordant)
    return min(1.0, 2.0 * probability)


def paired_comparison(
    records: list[dict],
    baseline: str,
    candidate: str,
    labels: tuple[str, ...],
    *,
    replicates: int,
    seed: int,
) -> dict:
    baseline_point = method_metrics(records, baseline, labels)
    candidate_point = method_metrics(records, candidate, labels)
    outcomes = Counter()
    for row in records:
        baseline_correct = row["predictions"][baseline] == row["gold"]
        candidate_correct = row["predictions"][candidate] == row["gold"]
        if baseline_correct and candidate_correct:
            outcomes["both_correct"] += 1
        elif baseline_correct:
            outcomes["baseline_only_correct"] += 1
        elif candidate_correct:
            outcomes["candidate_only_correct"] += 1
        else:
            outcomes["both_wrong"] += 1

    rng = random.Random(seed)
    bootstrap = defaultdict(list)
    for _ in range(replicates):
        indices = stratified_indices(records, rng)
        baseline_values = method_metrics(records, baseline, labels, indices)
        candidate_values = method_metrics(records, candidate, labels, indices)
        for metric in (
            "accuracy",
            "macro_f1",
            "prediction_coverage",
            "selective_accuracy",
        ):
            bootstrap[f"baseline_{metric}"].append(baseline_values[metric])
            bootstrap[f"candidate_{metric}"].append(candidate_values[metric])
            bootstrap[f"delta_{metric}"].append(
                candidate_values[metric] - baseline_values[metric]
            )

    return {
        "baseline_method": baseline,
        "candidate_method": candidate,
        "row_count": len(records),
        "baseline": baseline_point,
        "candidate": candidate_point,
        "delta": {
            key: candidate_point[key] - baseline_point[key]
            for key in baseline_point
        },
        "paired_outcomes": dict(sorted(outcomes.items())),
        "exact_mcnemar_two_sided_p_descriptive_only": exact_mcnemar_p(
            outcomes["candidate_only_correct"], outcomes["baseline_only_correct"]
        ),
        "bootstrap_95_percent_intervals": {
            key: interval(values) for key, values in sorted(bootstrap.items())
        },
    }


def load_change_map(path: Path, value_key: str) -> dict[str, str]:
    rows = {}
    for row in iter_jsonl(path):
        cve_id = row.get("cve_id")
        if not cve_id or cve_id in rows:
            raise ValueError(f"{path}: missing or duplicate cve_id={cve_id}")
        rows[cve_id] = row[value_key]
    return rows


def rq2_records() -> tuple[list[dict], dict]:
    gold_path = resolve("data/annotations/ai_adjudicated_gold/rq2_primary.jsonl")
    source_path = resolve("data/annotations/rq2/discrepancy_typing_seed.jsonl")
    reference_path = resolve(
        "results/rq2_discrepancy_typing/reference_normalization_changed_cases.review.jsonl"
    )
    cwe_path = resolve(
        "results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_changed_cases.jsonl"
    )
    gold = load_unique(gold_path, "sample_id")
    source = load_unique(source_path, "sample_id")
    if len(gold) != 300 or set(gold) != set(source):
        raise ValueError("RQ2 requires complete aligned 300-row inputs")
    reference_changes = load_change_map(reference_path, "proposed_status")
    cwe_changes = load_change_map(cwe_path, "taxonomy_v1_status")
    records = []
    for sample_id, gold_row in gold.items():
        if gold_row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: AI gold incorrectly claims human provenance")
        label = gold_row["annotation"]["discrepancy_label"]
        if label == "uncertain":
            continue
        source_row = source[sample_id]
        current = source_row["baseline_status"]
        reference = (
            reference_changes.get(source_row["cve_id"], current)
            if source_row["field"] == "references"
            else current
        )
        cwe = (
            cwe_changes.get(source_row["cve_id"], current)
            if source_row["field"] == "cwe_ids"
            else current
        )
        combined = reference if source_row["field"] == "references" else cwe
        predictions = {
            "current": current,
            "reference_resource_identity_v1": reference,
            "cwe_taxonomy_v1": cwe,
            "combined_candidate_v1": combined,
        }
        if any(value not in RQ2_LABELS for value in predictions.values()):
            raise ValueError(f"{sample_id}: invalid RQ2 method prediction")
        records.append(
            {
                "sample_id": sample_id,
                "field": source_row["field"],
                "gold": label,
                "stratum": f"{source_row['field']}|{label}",
                "predictions": predictions,
            }
        )
    if len(records) != 282:
        raise ValueError(f"RQ2 expected 282 determinate rows, found {len(records)}")
    return records, {
        "gold_input": str(gold_path),
        "gold_sha256": sha256(gold_path),
        "source_input": str(source_path),
        "source_sha256": sha256(source_path),
        "reference_changes_input": str(reference_path),
        "reference_changes_sha256": sha256(reference_path),
        "cwe_changes_input": str(cwe_path),
        "cwe_changes_sha256": sha256(cwe_path),
    }


def rq3_records(field: str) -> tuple[list[dict], dict]:
    spec = RQ3_INPUTS[field]
    gold_path = resolve(spec["gold"])
    prediction_path = resolve(spec["predictions"])
    gold = load_unique(gold_path, "sample_id")
    if len(gold) != spec["expected_rows"]:
        raise ValueError(f"{field}: incomplete AI gold")
    predictions_by_method = defaultdict(dict)
    for row in iter_jsonl(prediction_path):
        method = row.get("method")
        sample_id = row.get("sample_id")
        predicted_source = row.get("predicted_source")
        if sample_id not in gold or not method:
            raise ValueError(f"{prediction_path}: malformed prediction identity")
        if predicted_source not in (*SOURCE_LABELS, "abstain"):
            raise ValueError(f"{prediction_path}: invalid source prediction")
        if sample_id in predictions_by_method[method]:
            raise ValueError(f"{prediction_path}: duplicate method/sample prediction")
        predictions_by_method[method][sample_id] = predicted_source
    for method, rows in predictions_by_method.items():
        if set(rows) != set(gold):
            raise ValueError(f"{prediction_path}: {method} has incomplete predictions")

    records = []
    for sample_id, gold_row in gold.items():
        if gold_row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: AI gold incorrectly claims human provenance")
        if gold_row.get("ai_gold_status") != "final_determinate":
            continue
        gold_source = gold_row["annotation"]["adjudicated_source"]
        if gold_source not in SOURCE_LABELS:
            raise ValueError(f"{sample_id}: invalid determinate source {gold_source}")
        records.append(
            {
                "sample_id": sample_id,
                "gold": gold_source,
                "stratum": gold_source,
                "predictions": {
                    method: rows[sample_id]
                    for method, rows in predictions_by_method.items()
                },
            }
        )
    return records, {
        "gold_input": str(gold_path),
        "gold_sha256": sha256(gold_path),
        "prediction_input": str(prediction_path),
        "prediction_sha256": sha256(prediction_path),
        "input_rows": len(gold),
        "determinate_rows": len(records),
        "gold_determinate_coverage": safe_divide(len(records), len(gold)),
    }


def all_method_points(records: list[dict], labels: tuple[str, ...]) -> dict:
    methods = sorted(records[0]["predictions"])
    return {method: method_metrics(records, method, labels) for method in methods}


def render_markdown(result: dict) -> str:
    lines = [
        "# AI-Gold Paired Uncertainty Diagnostic",
        "",
        "All intervals and exact tests are descriptive diagnostics over AI-adjudicated gold with `label_is_human=false`; they do not establish human-gold generalization.",
        "",
        "## RQ2",
        "",
        "| Baseline | Candidate | Base acc. | Cand. acc. | Delta (pp) | 95% bootstrap delta (pp) | Cand.-only | Base-only | Exact p* |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for comparison in result["rq2"]["comparisons"]:
        bounds = comparison["bootstrap_95_percent_intervals"]["delta_accuracy"]
        outcomes = comparison["paired_outcomes"]
        lines.append(
            f"| {comparison['baseline_method']} | {comparison['candidate_method']} | "
            f"{comparison['baseline']['accuracy']:.4f} | {comparison['candidate']['accuracy']:.4f} | "
            f"{comparison['delta']['accuracy'] * 100:.2f} | "
            f"[{bounds[0] * 100:.2f}, {bounds[1] * 100:.2f}] | "
            f"{outcomes.get('candidate_only_correct', 0)} | {outcomes.get('baseline_only_correct', 0)} | "
            f"{comparison['exact_mcnemar_two_sided_p_descriptive_only']:.6f} |"
        )
    for field, field_result in result["rq3"].items():
        lines.extend(
            [
                "",
                f"## RQ3 {field}",
                "",
                "| Baseline | Candidate | Base acc. | Cand. acc. | Delta (pp) | 95% bootstrap delta (pp) | Coverage delta (pp) | Selective delta (pp) |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for comparison in field_result["comparisons"]:
            bounds = comparison["bootstrap_95_percent_intervals"]["delta_accuracy"]
            lines.append(
                f"| {comparison['baseline_method']} | {comparison['candidate_method']} | "
                f"{comparison['baseline']['accuracy']:.4f} | {comparison['candidate']['accuracy']:.4f} | "
                f"{comparison['delta']['accuracy'] * 100:.2f} | "
                f"[{bounds[0] * 100:.2f}, {bounds[1] * 100:.2f}] | "
                f"{comparison['delta']['prediction_coverage'] * 100:.2f} | "
                f"{comparison['delta']['selective_accuracy'] * 100:.2f} |"
            )
    lines.extend(
        [
            "",
            "`*` The exact paired p-value is reported only as a within-sample diagnostic. Candidate rules and risk adjudication were informed by the same data, so inferential assumptions for an independent confirmatory test are not satisfied.",
            "",
            "Production defaults remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    if args.bootstrap_replicates < 100:
        raise ValueError("bootstrap-replicates must be at least 100")
    output_dir = resolve(args.output_dir)

    rq2, rq2_inputs = rq2_records()
    rq2_result = {
        "inputs": rq2_inputs,
        "determinate_rows": len(rq2),
        "gold_coverage": safe_divide(len(rq2), 300),
        "stratification": "field|ai_gold_discrepancy_label",
        "method_points": all_method_points(rq2, RQ2_LABELS),
        "comparisons": [
            paired_comparison(
                rq2,
                baseline,
                candidate,
                RQ2_LABELS,
                replicates=args.bootstrap_replicates,
                seed=args.seed,
            )
            for baseline, candidate in RQ2_PAIRS
        ],
    }

    rq3_result = {}
    for field in ("severity", "affected_versions"):
        records, inputs = rq3_records(field)
        rq3_result[field] = {
            "inputs": inputs,
            "stratification": "ai_gold_adjudicated_source",
            "method_points": all_method_points(records, SOURCE_LABELS),
            "comparisons": [
                paired_comparison(
                    records,
                    baseline,
                    candidate,
                    SOURCE_LABELS,
                    replicates=args.bootstrap_replicates,
                    seed=args.seed,
                )
                for baseline, candidate in RQ3_PAIRS[field]
            ],
        }

    result = {
        "artifact_type": "ai_gold_paired_uncertainty_diagnostic",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "production_default_changed": False,
        "bootstrap": {
            "replicates": args.bootstrap_replicates,
            "seed": args.seed,
            "interval": "stratified paired percentile bootstrap, 2.5% to 97.5%",
            "population_inference_supported": False,
        },
        "rq2": rq2_result,
        "rq3": rq3_result,
        "cautions": [
            "AI-adjudicated gold is not human-gold.",
            "The intervals condition on the observed AI-gold class composition and do not quantify annotation-model uncertainty.",
            "RQ2 reference/CWE candidates were designed after candidate error inspection, so exact tests are descriptive rather than confirmatory.",
            "RQ3 candidate creation, risk adjudication, and method evaluation share evidence inputs and are not independent.",
            "Affected-version results condition on only 40 final_determinate rows out of 100.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "ai_gold_paired_uncertainty.json"
    md_path = output_dir / "ai_gold_paired_uncertainty.md"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
