#!/usr/bin/env python3
"""Evaluate affected-version methods on the dual-agent source-gold overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_RELEASE = (
    "results/rq3_adjudication/release_boundary/"
    "affected_versions_release_boundary_features.jsonl"
)
DEFAULT_BRANCH = (
    "results/rq3_adjudication/branch_graph/"
    "affected_versions_branch_graph_features.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit"
FALLBACK_METHOD = "repository_crosswalk_package_gated_canonical_token_baseline"
REFERENCE_METHOD = "canonical_version_token_support_baseline"
SOURCE_LABELS = ("nvd", "ghsa", "both", "neither")
BOOTSTRAP_REPLICATES = 10000
BOOTSTRAP_SEED = 20260715


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--release-features", default=DEFAULT_RELEASE)
    parser.add_argument("--branch-features", default=DEFAULT_BRANCH)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(
                    f"{path}:{line_number}: missing or duplicate sample_id"
                )
            rows[sample_id] = row
    return rows


def load_method_predictions(path: Path, sample_ids: set[str]) -> dict[str, dict[str, str]]:
    methods: dict[str, dict[str, str]] = defaultdict(dict)
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            method = row.get("method")
            prediction = row.get("predicted_source")
            if sample_id not in sample_ids or not method:
                raise ValueError(f"{path}:{line_number}: malformed identity")
            if sample_id in methods[method]:
                raise ValueError(f"{path}:{line_number}: duplicate method/sample")
            if prediction not in (*SOURCE_LABELS, "abstain"):
                raise ValueError(f"{path}:{line_number}: invalid prediction")
            methods[method][sample_id] = prediction
    for method, values in methods.items():
        if set(values) != sample_ids:
            raise ValueError(f"{method}: prediction coverage mismatch")
    return dict(methods)


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def metrics(rows: list[dict], method: str) -> dict:
    covered = [row for row in rows if row["predictions"][method] != "abstain"]
    correct = [
        row for row in rows if row["predictions"][method] == row["gold_source"]
    ]
    covered_correct = [
        row for row in covered if row["predictions"][method] == row["gold_source"]
    ]
    confusion = Counter(
        (row["gold_source"], row["predictions"][method]) for row in rows
    )
    gold_counts = Counter(row["gold_source"] for row in rows)
    f1_values = []
    for label in SOURCE_LABELS:
        if not gold_counts[label]:
            continue
        tp = confusion[(label, label)]
        fp = sum(
            confusion[(other, label)] for other in SOURCE_LABELS if other != label
        )
        fn = sum(
            confusion[(label, other)]
            for other in (*SOURCE_LABELS, "abstain")
            if other != label
        )
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1_values.append(safe_divide(2 * precision * recall, precision + recall))
    return {
        "rows": len(rows),
        "correct": len(correct),
        "accuracy": safe_divide(len(correct), len(rows)),
        "macro_f1_over_supported_labels": safe_divide(
            sum(f1_values), len(f1_values)
        ),
        "non_abstain": len(covered),
        "prediction_coverage": safe_divide(len(covered), len(rows)),
        "selective_accuracy": safe_divide(len(covered_correct), len(covered)),
        "prediction_counts": dict(
            sorted(Counter(row["predictions"][method] for row in rows).items())
        ),
        "gold_counts": dict(sorted(gold_counts.items())),
    }


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def exact_paired_pvalue(improvements: int, regressions: int) -> float:
    discordant = improvements + regressions
    if discordant == 0:
        return 1.0
    tail = min(improvements, regressions)
    probability = sum(math.comb(discordant, k) for k in range(tail + 1)) / (
        2**discordant
    )
    return min(1.0, 2.0 * probability)


def paired_comparison(
    rows: list[dict], candidate: str, reference: str, comparison: str
) -> dict:
    if not rows:
        return {
            "comparison": comparison,
            "rows": 0,
            "status": "not_computable_empty_cohort",
        }
    improvements = sum(
        row["predictions"][candidate] == row["gold_source"]
        and row["predictions"][reference] != row["gold_source"]
        for row in rows
    )
    regressions = sum(
        row["predictions"][candidate] != row["gold_source"]
        and row["predictions"][reference] == row["gold_source"]
        for row in rows
    )
    observed = sum(
        (row["predictions"][candidate] == row["gold_source"])
        - (row["predictions"][reference] == row["gold_source"])
        for row in rows
    ) / len(rows)
    strata: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        strata[row["gold_source"]].append(index)
    rng = random.Random(BOOTSTRAP_SEED)
    deltas = []
    for _ in range(BOOTSTRAP_REPLICATES):
        selected = []
        for indices in strata.values():
            selected.extend(rng.choice(indices) for _ in indices)
        deltas.append(
            sum(
                (
                    rows[index]["predictions"][candidate]
                    == rows[index]["gold_source"]
                )
                - (
                    rows[index]["predictions"][reference]
                    == rows[index]["gold_source"]
                )
                for index in selected
            )
            / len(selected)
        )
    return {
        "comparison": comparison,
        "rows": len(rows),
        "status": "exploratory",
        "observed_accuracy_delta": observed,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": BOOTSTRAP_SEED,
        "stratification": "source_gold_label",
        "percentile_95_interval": [
            percentile(deltas, 0.025),
            percentile(deltas, 0.975),
        ],
        "improvements": improvements,
        "regressions": regressions,
        "exact_paired_two_sided_pvalue": exact_paired_pvalue(
            improvements, regressions
        ),
        "confirmatory_inference_supported": False,
    }


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected_versions source-overlay diagnostic",
        "",
        "This artifact uses a non-human, dual-Codex source-label overlay. It is not human-gold or final-paper performance.",
    ]
    selected_methods = (
        REFERENCE_METHOD,
        "release_boundary",
        "release_boundary_then_crosswalk_canonical",
        "branch_release_graph",
        "branch_graph_then_crosswalk_canonical",
    )
    for cohort_name in ("original_base", "strict_reaudit_added", "combined"):
        cohort = artifact["cohorts"][cohort_name]
        lines.extend(
            [
                "",
                f"## {cohort_name}",
                "",
                f"Rows: `{cohort['rows']}`.",
                "",
                "| Method | Correct | Accuracy | Coverage | Selective accuracy |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for method in selected_methods:
            value = cohort["methods"][method]
            lines.append(
                f"| `{method}` | {value['correct']}/{value['rows']} | "
                f"{value['accuracy']:.4f} | {value['prediction_coverage']:.4f} | "
                f"{value['selective_accuracy']:.4f} |"
            )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "The added cohort is selected from prior uncertain rows and contains only exact non-abstain agreement between two Codex reviewers under a strict evidence contract. The original 40 rows were not rerun under that contract, and all results remain AI-provenance diagnostics.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    overlay_path = resolve(args.overlay)
    prediction_path = resolve(args.predictions)
    release_path = resolve(args.release_features)
    branch_path = resolve(args.branch_features)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    overlay = load_jsonl(overlay_path)
    release = load_jsonl(release_path)
    branch = load_jsonl(branch_path)
    if len(overlay) != 100 or set(overlay) != set(release) or set(overlay) != set(branch):
        raise ValueError("overlay and feature artifacts must cover the same 100 rows")
    if any(row.get("label_is_human") is not False for row in overlay.values()):
        raise ValueError("source overlay must preserve non-human provenance")
    methods = load_method_predictions(prediction_path, set(overlay))
    if FALLBACK_METHOD not in methods or REFERENCE_METHOD not in methods:
        raise ValueError("required fallback/reference method is missing")

    methods["release_boundary"] = {
        sample_id: row["predicted_source"] for sample_id, row in release.items()
    }
    methods["release_boundary_then_crosswalk_canonical"] = {
        sample_id: (
            release[sample_id]["predicted_source"]
            if release[sample_id]["predicted_source"] != "abstain"
            else methods[FALLBACK_METHOD][sample_id]
        )
        for sample_id in overlay
    }
    methods["branch_release_graph"] = {
        sample_id: row["predicted_source"] for sample_id, row in branch.items()
    }
    methods["branch_graph_then_crosswalk_canonical"] = {
        sample_id: (
            branch[sample_id]["predicted_source"]
            if branch[sample_id]["predicted_source"] != "abstain"
            else methods[FALLBACK_METHOD][sample_id]
        )
        for sample_id in overlay
    }

    rows = []
    for sample_id, gold in overlay.items():
        if gold["source_gold_status"] != "final_determinate":
            continue
        source = gold["source_gold_label"]
        if source not in SOURCE_LABELS:
            raise ValueError(f"{sample_id}: invalid determinate source {source}")
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold.get("cve_id"),
                "gold_source": source,
                "origin": gold["source_decision_origin"],
                "predictions": {
                    method: values[sample_id] for method, values in methods.items()
                },
            }
        )
    cohorts = {
        "original_base": [
            row
            for row in rows
            if row["origin"] == "existing_ai_gold_final_determinate"
        ],
        "strict_reaudit_added": [
            row
            for row in rows
            if row["origin"] == "dual_agent_strict_source_reaudit"
        ],
        "combined": rows,
    }
    cohort_artifacts = {}
    for name, cohort_rows in cohorts.items():
        method_results = {
            method: metrics(cohort_rows, method) for method in sorted(methods)
        }
        cohort_artifacts[name] = {
            "rows": len(cohort_rows),
            "gold_source_counts": dict(
                sorted(Counter(row["gold_source"] for row in cohort_rows).items())
            ),
            "methods": method_results,
            "best_accuracy_methods": sorted(
                method
                for method, value in method_results.items()
                if value["accuracy"]
                == max(result["accuracy"] for result in method_results.values())
            ),
            "paired_branch_hybrid_vs_canonical": paired_comparison(
                cohort_rows,
                "branch_graph_then_crosswalk_canonical",
                REFERENCE_METHOD,
                "branch_graph_then_crosswalk_canonical - canonical_version_token_support_baseline",
            ),
        }

    artifact = {
        "artifact_type": "affected_versions_source_overlay_diagnostic",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "production_default_changed": False,
        "inputs": {
            "source_overlay": {
                "path": str(overlay_path),
                "sha256": sha256(overlay_path),
            },
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
            "release_features": {
                "path": str(release_path),
                "sha256": sha256(release_path),
            },
            "branch_features": {
                "path": str(branch_path),
                "sha256": sha256(branch_path),
            },
        },
        "source_gold_coverage": {
            "determinate": len(rows),
            "total": len(overlay),
            "rate": len(rows) / len(overlay),
        },
        "cohorts": cohort_artifacts,
        "cautions": [
            "The source overlay and both re-audit decisions are AI-generated, not human-gold.",
            "The added cohort is selected from prior uncertain rows with prior non-abstain source values.",
            "The original 40 rows were not rerun under the stricter dual-agent source contract.",
            "Branch/release-graph rules were developed on errors in the original 40-row cohort, not on labels from the added cohort.",
            "Paired intervals and exact tests are descriptive and not confirmatory inference.",
        ],
    }
    json_path = output_dir / "affected_versions_source_overlay_diagnostic.json"
    md_path = output_dir / "affected_versions_source_overlay_diagnostic.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
