#!/usr/bin/env python3
"""Leave-one-cohort-out structured baselines for affected-version tasks."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

import evaluate_affected_versions_silver_v2 as baseline
from affected_versions_authority_graph import (
    classify_evidence_authority,
    predict_authority_filtered_source,
)
from affected_versions_branch_graph import extract_branch_graph_features
from affected_versions_semantic_baseline import (
    range_relation,
    repository_crosswalk_package_profile,
)
from affected_versions_task_separated import structured_range_set_relation
from analyze_affected_versions_task_separated_v2_development import (
    DEFAULT_PHASE_D,
    DEFAULT_PHASE_D_GOLD,
    DEFAULT_V1,
    DEFAULT_V1_GOLD,
    DEFAULT_V2,
    DEFAULT_V2_GOLD,
    LEGACY_NON_CONFLICT,
    load_jsonl,
    phase_d_targets,
    resolve,
    v1_targets,
    v2_targets,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/affected_versions_leave_one_cohort_out"
SEED = 20260715
THRESHOLDS = (0.0, 0.6, 0.75)
SOURCE_LABELS = {"nvd", "ghsa", "neither"}
FORBIDDEN_FEATURE_KEYS = {
    "gold",
    "gold_label",
    "sample_id",
    "cve_id",
    "discrepancy_label",
    "adjudicated_source",
    "annotation",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase-d", default=DEFAULT_PHASE_D)
    parser.add_argument("--phase-d-gold", default=DEFAULT_PHASE_D_GOLD)
    parser.add_argument("--v1", default=DEFAULT_V1)
    parser.add_argument("--v1-gold", default=DEFAULT_V1_GOLD)
    parser.add_argument("--v2", default=DEFAULT_V2)
    parser.add_argument("--v2-gold", default=DEFAULT_V2_GOLD)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def legacy_type(row: dict, package: dict, legacy: dict) -> str:
    return (
        "representation_discrepancy"
        if package["comparable"] and legacy["relation"] in LEGACY_NON_CONFLICT
        else "factual_conflict"
    )


def evidence_authority_counts(row: dict) -> Counter:
    counts = Counter()
    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
            continue
        authority_class, _ = classify_evidence_authority(
            str(record.get("url") or "")
        )
        counts[authority_class] += 1
    return counts


def validate_feature_keys(features: dict) -> None:
    forbidden = [key for key in features if key.lower() in FORBIDDEN_FEATURE_KEYS]
    if forbidden:
        raise ValueError(f"features contain identity or label keys: {sorted(forbidden)}")


def extract_features(row: dict) -> tuple[dict, dict]:
    package = repository_crosswalk_package_profile(row)
    legacy = range_relation(row)
    structured = structured_range_set_relation(row)
    branch = extract_branch_graph_features(row)
    authority = predict_authority_filtered_source(row)
    contextual = baseline.predict_contextual_canonical_version_claim_support(row)
    latest = baseline.predict_latest_published(row)
    direct = package["direct_package_profile"]
    authority_counts = evidence_authority_counts(row)
    nvd_profile = branch["source_profiles"]["nvd"]
    ghsa_profile = branch["source_profiles"]["ghsa"]

    features: dict[str, object] = {
        "package_comparable": package["comparable"],
        "package_category": package["category"],
        "legacy_relation": legacy["relation"],
        "structured_relation": structured["relation"],
        "nvd_span_count": structured["nvd_span_count"],
        "ghsa_span_count": structured["ghsa_span_count"],
        "nvd_package_count": len(direct["nvd_package_names"]),
        "ghsa_package_count": len(direct["ghsa_package_names"]),
        "exact_package_overlap_count": len(direct["exact_overlap"]),
        "canonical_package_overlap_count": len(direct["canonical_overlap"]),
        "leaf_package_overlap_count": len(direct["leaf_overlap"]),
        "branch_prediction": branch["predicted_source"],
        "branch_nvd_support_count": len(nvd_profile["support_events"]),
        "branch_ghsa_support_count": len(ghsa_profile["support_events"]),
        "branch_nvd_contradiction_count": len(nvd_profile["contradiction_events"]),
        "branch_ghsa_contradiction_count": len(ghsa_profile["contradiction_events"]),
        "authority_prediction": authority["predicted_source"],
        "authority_selected_tier": authority["authority_profile"][
            "selected_authority_tier"
        ]
        or 0,
        "contextual_prediction": contextual["predicted_source"],
        "latest_prediction": latest["predicted_source"],
        "ok_evidence_record_count": sum(authority_counts.values()),
    }
    for flag in branch["capability_flags"]:
        features[f"branch_flag={flag}"] = True
    for authority_class, count in authority_counts.items():
        features[f"authority_count={authority_class}"] = count
    validate_feature_keys(features)
    baselines = {
        "all_fc_candidate_miner": "factual_conflict",
        "legacy_structural_type": legacy_type(row, package, legacy),
        "prefer_nvd": "nvd",
        "prefer_ghsa": "ghsa",
        "branch_release_graph": branch["predicted_source"],
        "contextual_canonical_version_claim_baseline": contextual[
            "predicted_source"
        ],
        "authority_filtered_branch_graph": authority["predicted_source"],
        "latest_published": latest["predicted_source"],
    }
    return features, baselines


def build_examples(
    cohort: str, rows: list[dict], targets: dict[str, dict]
) -> tuple[list[dict], list[dict]]:
    type_examples = []
    source_examples = []
    for row in rows:
        target = targets.get(row["sample_id"])
        if target is None:
            continue
        features, baselines = extract_features(row)
        gold_type = target["discrepancy_label"]
        common = {
            "cohort": cohort,
            "sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "features": features,
            "baselines": baselines,
        }
        if gold_type != "uncertain":
            type_examples.append({**common, "gold": gold_type})
        gold_source = target.get("adjudicated_source")
        if gold_type == "factual_conflict" and gold_source in SOURCE_LABELS:
            source_examples.append({**common, "gold": gold_source})
    return type_examples, source_examples


def make_models() -> dict:
    return {
        "balanced_logistic": make_pipeline(
            DictVectorizer(sparse=True),
            StandardScaler(with_mean=False),
            LogisticRegression(
                class_weight="balanced",
                max_iter=2000,
                random_state=SEED,
            ),
        ),
        "shallow_decision_tree": make_pipeline(
            DictVectorizer(sparse=True),
            DecisionTreeClassifier(
                class_weight="balanced",
                max_depth=4,
                min_samples_leaf=4,
                random_state=SEED,
            ),
        ),
    }


def threshold_predictions(
    labels: list[str], probabilities: list[float], threshold: float
) -> list[str]:
    return [
        label if probability >= threshold else "abstain"
        for label, probability in zip(labels, probabilities)
    ]


def metrics(gold: list[str], predicted: list[str]) -> dict:
    if len(gold) != len(predicted):
        raise ValueError("gold/prediction length mismatch")
    determinate = [value != "abstain" for value in predicted]
    correct = [covered and left == right for left, right, covered in zip(gold, predicted, determinate)]
    covered = sum(determinate)
    labels = sorted(set(gold))
    return {
        "rows": len(gold),
        "correct": sum(correct),
        "full_accuracy": sum(correct) / len(gold) if gold else None,
        "prediction_coverage": covered / len(gold) if gold else None,
        "selective_accuracy": sum(correct) / covered if covered else None,
        "macro_f1_over_gold_labels": (
            f1_score(gold, predicted, labels=labels, average="macro", zero_division=0)
            if gold
            else None
        ),
        "gold_counts": dict(sorted(Counter(gold).items())),
        "prediction_counts": dict(sorted(Counter(predicted).items())),
    }


def leave_one_cohort_out(examples: list[dict], baseline_methods: list[str]) -> dict:
    cohorts = sorted({row["cohort"] for row in examples})
    out_of_fold: dict[str, dict[str, list[str]]] = {}
    splits = []
    for held_out in cohorts:
        train = [row for row in examples if row["cohort"] != held_out]
        test = [row for row in examples if row["cohort"] == held_out]
        if not train or not test:
            raise ValueError("leave-one-cohort-out split is empty")
        split = {
            "held_out_cohort": held_out,
            "train_rows": len(train),
            "test_rows": len(test),
            "train_cves": len({row["cve_id"] for row in train}),
            "test_cves": len({row["cve_id"] for row in test}),
            "cve_overlap": len(
                {row["cve_id"] for row in train} & {row["cve_id"] for row in test}
            ),
            "baselines": baseline_metrics(test, baseline_methods),
            "models": {},
        }
        train_features = [row["features"] for row in train]
        train_gold = [row["gold"] for row in train]
        test_features = [row["features"] for row in test]
        test_gold = [row["gold"] for row in test]
        for model_name, model in make_models().items():
            model.fit(train_features, train_gold)
            labels = list(model.predict(test_features))
            probabilities = model.predict_proba(test_features).max(axis=1).tolist()
            split["models"][model_name] = {}
            for threshold in THRESHOLDS:
                key = f"threshold_{threshold:.2f}"
                predicted = threshold_predictions(labels, probabilities, threshold)
                split["models"][model_name][key] = metrics(test_gold, predicted)
                bucket = out_of_fold.setdefault(model_name, {}).setdefault(
                    key, {"gold": [], "predicted": []}
                )
                bucket["gold"].extend(test_gold)
                bucket["predicted"].extend(predicted)
        splits.append(split)
    aggregate = {
        model_name: {
            key: metrics(values["gold"], values["predicted"])
            for key, values in thresholds.items()
        }
        for model_name, thresholds in out_of_fold.items()
    }
    return {"splits": splits, "out_of_fold": aggregate}


def baseline_metrics(examples: list[dict], methods: list[str]) -> dict:
    gold = [row["gold"] for row in examples]
    return {
        method: metrics(
            gold,
            [
                (
                    row["baselines"][method]
                    if row["baselines"][method] not in {"both", "not_applicable"}
                    else "abstain"
                )
                for row in examples
            ],
        )
        for method in methods
    }


def stable_improvement_gate(
    leave_out: dict, baseline_methods: list[str]
) -> dict:
    candidates = []
    first_split = leave_out["splits"][0]
    for model_name, thresholds in first_split["models"].items():
        for threshold in thresholds:
            cohort_checks = []
            for split in leave_out["splits"]:
                candidate = split["models"][model_name][threshold]
                comparator_correct = max(
                    split["baselines"][method]["correct"]
                    for method in baseline_methods
                )
                cohort_checks.append(
                    {
                        "held_out_cohort": split["held_out_cohort"],
                        "candidate_correct": candidate["correct"],
                        "best_comparator_correct": comparator_correct,
                        "strict_improvement": candidate["correct"]
                        > comparator_correct,
                    }
                )
            candidates.append(
                {
                    "model": model_name,
                    "threshold": threshold,
                    "passes_all_cohorts": all(
                        check["strict_improvement"] for check in cohort_checks
                    ),
                    "cohort_checks": cohort_checks,
                }
            )
    return {
        "criterion": "strictly more correct predictions than the best named comparator on every held-out cohort",
        "comparators": baseline_methods,
        "passing_candidates": [
            {"model": row["model"], "threshold": row["threshold"]}
            for row in candidates
            if row["passes_all_cohorts"]
        ],
        "advance_to_new_sealed_cohort": any(
            row["passes_all_cohorts"] for row in candidates
        ),
        "candidates": candidates,
    }


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Versions Leave-One-Cohort-Out Diagnostic",
        "",
        "This is a post-hoc non-human diagnostic. Each prediction is made by a model trained on the other two CVE-disjoint cohorts.",
        "",
    ]
    for task in ("type", "source"):
        lines.extend(
            [
                f"## {task.title()} endpoint",
                "",
                "| Model | Threshold | Correct/rows | Coverage | Selective accuracy |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for model, thresholds in artifact[task]["leave_one_cohort_out"][
            "out_of_fold"
        ].items():
            for threshold, result in thresholds.items():
                selective = result["selective_accuracy"]
                lines.append(
                    f"| {model} | {threshold} | {result['correct']}/{result['rows']} | "
                    f"{result['prediction_coverage']:.4f} | "
                    f"{selective:.4f} |"
                    if selective is not None
                    else f"| {model} | {threshold} | {result['correct']}/{result['rows']} | {result['prediction_coverage']:.4f} | - |"
                )
        lines.extend(
            [
                "",
                "Fixed baselines over the same pooled rows:",
                "",
                "| Baseline | Correct/rows | Coverage | Selective accuracy |",
                "|---|---:|---:|---:|",
            ]
        )
        for method, result in artifact[task]["baselines"].items():
            selective = result["selective_accuracy"]
            lines.append(
                f"| {method} | {result['correct']}/{result['rows']} | "
                f"{result['prediction_coverage']:.4f} | {selective:.4f} |"
                if selective is not None
                else f"| {method} | {result['correct']}/{result['rows']} | {result['prediction_coverage']:.4f} | - |"
            )
        lines.append("")
        gate = artifact[task]["stable_improvement_gate"]
        lines.extend(
            [
                f"Stable-improvement gate: **{'pass' if gate['advance_to_new_sealed_cohort'] else 'fail'}**.",
                "",
                f"Criterion: {gate['criterion']}.",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        "phase_d": resolve(args.phase_d),
        "phase_d_gold": resolve(args.phase_d_gold),
        "v1": resolve(args.v1),
        "v1_gold": resolve(args.v1_gold),
        "v2": resolve(args.v2),
        "v2_gold": resolve(args.v2_gold),
    }
    cohort_specs = [
        ("phase_d", paths["phase_d"], phase_d_targets(paths["phase_d_gold"])),
        ("v1", paths["v1"], v1_targets(paths["v1_gold"])),
        ("v2", paths["v2"], v2_targets(paths["v2_gold"])),
    ]
    type_examples = []
    source_examples = []
    for name, input_path, targets in cohort_specs:
        typed, sourced = build_examples(name, load_jsonl(input_path), targets)
        type_examples.extend(typed)
        source_examples.extend(sourced)
    if len({row["cve_id"] for row in type_examples}) != len(type_examples):
        raise ValueError("type examples are not CVE-disjoint")
    if len({row["cve_id"] for row in source_examples}) != len(source_examples):
        raise ValueError("source examples are not CVE-disjoint")

    type_baseline_methods = ["all_fc_candidate_miner", "legacy_structural_type"]
    source_baseline_methods = [
        "prefer_nvd",
        "prefer_ghsa",
        "latest_published",
        "branch_release_graph",
        "contextual_canonical_version_claim_baseline",
        "authority_filtered_branch_graph",
    ]
    type_leave_out = leave_one_cohort_out(type_examples, type_baseline_methods)
    source_leave_out = leave_one_cohort_out(source_examples, source_baseline_methods)
    artifact = {
        "artifact_type": "affected_versions_leave_one_cohort_out_diagnostic",
        "analysis_is_posthoc": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "dependency_versions": {"scikit_learn": "1.7.2"},
        "type": {
            "rows": len(type_examples),
            "leave_one_cohort_out": type_leave_out,
            "baselines": baseline_metrics(type_examples, type_baseline_methods),
            "stable_improvement_gate": stable_improvement_gate(
                type_leave_out, type_baseline_methods
            ),
        },
        "source": {
            "rows": len(source_examples),
            "leave_one_cohort_out": source_leave_out,
            "baselines": baseline_metrics(source_examples, source_baseline_methods),
            "stable_improvement_gate": stable_improvement_gate(
                source_leave_out, source_baseline_methods
            ),
        },
        "inputs": {
            name: {"path": str(path), "sha256": sha256(path)}
            for name, path in paths.items()
        },
        "code": {
            "path": str(Path(__file__)),
            "sha256": sha256(Path(__file__)),
        },
        "cautions": [
            "All labels are AI/Codex candidates rather than human gold.",
            "The feature set and model family were selected after v2 unsealing.",
            "Cohort leave-out reduces row leakage but does not remove shared candidate-miner or model-family dependence.",
            "Model selection from these results requires a new untouched cohort.",
        ],
    }
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "leave_one_cohort_out.json"
    md_path = output_dir / "leave_one_cohort_out.md"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
