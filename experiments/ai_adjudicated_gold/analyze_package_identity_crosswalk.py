#!/usr/bin/env python3
"""Audit a repository-anchored package crosswalk against AI-adjudicated gold."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "experiments" / "rq3_adjudication"))

from affected_versions_semantic_baseline import (  # noqa: E402
    package_profile,
    repository_crosswalk_package_profile,
)


EVIDENCE_INPUT = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
GOLD_INPUT = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
PREDICTIONS_INPUT = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
SILVER_METRICS_INPUT = (
    "results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json"
)
EXPECTED_ROWS = 100
METHODS = (
    "package_gated_token_baseline",
    "repository_crosswalk_package_gated_token_baseline",
    "package_gated_canonical_token_baseline",
    "repository_crosswalk_package_gated_canonical_token_baseline",
)
METHOD_PAIRS = (
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
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="results/ai_adjudicated_gold/package_identity_crosswalk",
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
    return rows


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected an object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def load_predictions(path: Path, sample_ids: set[str]) -> dict[str, dict[str, str]]:
    predictions: dict[str, dict[str, str]] = defaultdict(dict)
    identities = set()
    for row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        method = row.get("method")
        if sample_id not in sample_ids or method not in METHODS:
            continue
        identity = (sample_id, method)
        if identity in identities:
            raise ValueError(f"{path}: duplicate prediction={identity}")
        identities.add(identity)
        predictions[sample_id][method] = row.get("predicted_source")
    for sample_id in sorted(sample_ids):
        missing = sorted(set(METHODS) - set(predictions[sample_id]))
        if missing:
            raise ValueError(f"{path}: {sample_id} missing methods={missing}")
    return dict(predictions)


def method_metrics(rows: list[dict], method: str) -> dict:
    correct = sum(row["predictions"][method] == row["gold_source"] for row in rows)
    covered = [row for row in rows if row["predictions"][method] != "abstain"]
    covered_correct = sum(
        row["predictions"][method] == row["gold_source"] for row in covered
    )
    return {
        "rows": len(rows),
        "correct": correct,
        "accuracy": safe_divide(correct, len(rows)),
        "non_abstain": len(covered),
        "prediction_coverage": safe_divide(len(covered), len(rows)),
        "selective_accuracy": safe_divide(covered_correct, len(covered)),
        "prediction_counts": dict(
            sorted(Counter(row["predictions"][method] for row in rows).items())
        ),
    }


def paired_outcomes(rows: list[dict], baseline: str, candidate: str) -> dict:
    outcomes = Counter()
    changed_rows = []
    for row in rows:
        baseline_prediction = row["predictions"][baseline]
        candidate_prediction = row["predictions"][candidate]
        baseline_correct = baseline_prediction == row["gold_source"]
        candidate_correct = candidate_prediction == row["gold_source"]
        if baseline_correct and candidate_correct:
            outcome = "both_correct"
        elif baseline_correct:
            outcome = "baseline_only_correct"
        elif candidate_correct:
            outcome = "candidate_only_correct"
        else:
            outcome = "both_wrong"
        outcomes[outcome] += 1
        if baseline_prediction != candidate_prediction:
            changed_rows.append(
                {
                    "sample_id": row["sample_id"],
                    "cve_id": row["cve_id"],
                    "gold_source": row["gold_source"],
                    "reasoning_type": row["reasoning_type"],
                    "baseline_prediction": baseline_prediction,
                    "candidate_prediction": candidate_prediction,
                    "outcome": outcome,
                }
            )
    return {
        "baseline_method": baseline,
        "candidate_method": candidate,
        "paired_outcomes": dict(sorted(outcomes.items())),
        "changed_prediction_rows": changed_rows,
    }


def silver_points(metrics: dict) -> dict:
    result = {}
    methods = metrics.get("methods", {})
    for method in METHODS:
        values = methods.get(method)
        if not isinstance(values, dict):
            raise ValueError(f"silver metrics missing method={method}")
        result[method] = {
            "accuracy_against_silver": values.get("accuracy"),
            "prediction_coverage": values.get("coverage_non_abstain"),
            "selective_accuracy_against_silver": values.get(
                "accuracy_when_non_abstain"
            ),
        }
    return result


def format_counts(values: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in values.items()) or "none"


def render_markdown(result: dict) -> str:
    crosswalk = result["crosswalk_profile"]
    methods = result["ai_gold_determinate_method_points"]
    lines = [
        "# Package-Identity Crosswalk AI-Gold Diagnostic",
        "",
        "The crosswalk feature uses only source package identifiers and source reference URLs. AI-gold fields are joined afterward for diagnostic evaluation. This artifact has `label_is_human=false` and is not eligible for a final paper claim.",
        "",
        "## Crosswalk Coverage",
        "",
        f"Direct package-name profiles consider `{crosswalk['direct_comparable_rows']}/{result['input_rows']}` rows comparable. The repository crosswalk adds `{crosswalk['newly_comparable_rows']}` rows, producing `{crosswalk['crosswalk_comparable_rows']}/{result['input_rows']}` comparable rows.",
        "",
        f"Crosswalk categories: {format_counts(crosswalk['crosswalk_package_category_counts'])}.",
        "",
        "| Sample | CVE | AI-gold status | Reasoning tag | Accepted repository |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in crosswalk["newly_comparable_row_details"]:
        lines.append(
            f"| {row['sample_id']} | {row['cve_id']} | {row['ai_gold_status']} | "
            f"{row['reasoning_type']} | {', '.join(row['accepted_repositories'])} |"
        )

    lines.extend(
        [
            "",
            "## AI-Gold Determinate Points",
            "",
            "| Method | Correct | Accuracy | Coverage | Selective accuracy |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for method in METHODS:
        values = methods[method]
        lines.append(
            f"| {method} | {values['correct']}/{values['rows']} | "
            f"{values['accuracy']:.4f} | {values['prediction_coverage']:.4f} | "
            f"{values['selective_accuracy']:.4f} |"
        )

    lines.extend(
        [
            "",
            "## Paired Outcomes",
            "",
            "| Baseline | Candidate | Outcomes | Changed predictions |",
            "| --- | --- | --- | ---: |",
        ]
    )
    for comparison in result["ai_gold_determinate_paired_outcomes"]:
        lines.append(
            f"| {comparison['baseline_method']} | {comparison['candidate_method']} | "
            f"{format_counts(comparison['paired_outcomes'])} | "
            f"{len(comparison['changed_prediction_rows'])} |"
        )

    lines.extend(
        [
            "",
            "## Silver Diagnostic",
            "",
            "| Method | Accuracy | Coverage | Selective accuracy |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for method, values in result["silver_method_points"].items():
        lines.append(
            f"| {method} | {values['accuracy_against_silver']:.4f} | "
            f"{values['prediction_coverage']:.4f} | "
            f"{values['selective_accuracy_against_silver']:.4f} |"
        )

    raw_direct = methods["package_gated_token_baseline"]
    raw_crosswalk = methods["repository_crosswalk_package_gated_token_baseline"]
    canonical_crosswalk = methods[
        "repository_crosswalk_package_gated_canonical_token_baseline"
    ]
    lines.extend(
        [
            "",
            "## Bounded Interpretation",
            "",
            f"The raw crosswalk increases determinate prediction coverage from `{raw_direct['prediction_coverage']:.4f}` to `{raw_crosswalk['prediction_coverage']:.4f}`, while accuracy changes from `{raw_direct['accuracy']:.4f}` to `{raw_crosswalk['accuracy']:.4f}` and selective accuracy changes from `{raw_direct['selective_accuracy']:.4f}` to `{raw_crosswalk['selective_accuracy']:.4f}`.",
            "",
            f"Adding canonical token matching after the crosswalk reaches accuracy `{canonical_crosswalk['accuracy']:.4f}`. These points separate package comparability from version-source adjudication; a successful repository bridge does not establish which range is supported.",
            "",
            "The candidate family was motivated by prior AI-gold error analysis, and all evaluation labels remain AI generated. Production defaults remain unchanged.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    evidence_path = resolve(EVIDENCE_INPUT)
    gold_path = resolve(GOLD_INPUT)
    predictions_path = resolve(PREDICTIONS_INPUT)
    silver_metrics_path = resolve(SILVER_METRICS_INPUT)
    output_dir = resolve(args.output_dir)

    evidence = load_unique(evidence_path, "sample_id")
    gold = load_unique(gold_path, "sample_id")
    if len(evidence) != EXPECTED_ROWS or len(gold) != EXPECTED_ROWS:
        raise ValueError(
            f"expected {EXPECTED_ROWS} evidence/gold rows, found {len(evidence)}/{len(gold)}"
        )
    if set(evidence) != set(gold):
        raise ValueError("evidence and gold sample_id sets differ")
    predictions = load_predictions(predictions_path, set(evidence))

    rows = []
    for sample_id in sorted(evidence):
        evidence_row = evidence[sample_id]
        gold_row = gold[sample_id]
        if gold_row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: label_is_human must be false")
        if gold_row.get("eligible_for_human_gold_claim") is not False:
            raise ValueError(f"{sample_id}: human-gold claim must be false")
        direct = package_profile(evidence_row)
        crosswalk = repository_crosswalk_package_profile(evidence_row)
        annotation = gold_row["annotation"]
        rows.append(
            {
                "sample_id": sample_id,
                "cve_id": evidence_row.get("cve_id"),
                "ai_gold_status": gold_row.get("ai_gold_status"),
                "gold_source": (
                    annotation.get("adjudicated_source")
                    if gold_row.get("ai_gold_status") == "final_determinate"
                    else None
                ),
                "reasoning_type": annotation.get("version_reasoning_type"),
                "direct_package_category": direct["category"],
                "crosswalk_package_category": crosswalk["category"],
                "crosswalk_comparable": crosswalk["comparable"],
                "accepted_repositories": crosswalk[
                    "repository_crosswalk_profile"
                ]["accepted_repositories"],
                "direct_package_profile": direct,
                "repository_crosswalk_profile": crosswalk[
                    "repository_crosswalk_profile"
                ],
                "predictions": predictions[sample_id],
            }
        )

    direct_comparable = [
        row
        for row in rows
        if row["direct_package_category"]
        in {"exact_or_canonical_package_overlap", "leaf_package_overlap_only"}
    ]
    crosswalk_comparable = [row for row in rows if row["crosswalk_comparable"]]
    newly_comparable = [
        row
        for row in rows
        if row["crosswalk_package_category"] == "repository_crosswalk_overlap"
    ]
    determinate = [row for row in rows if row["ai_gold_status"] == "final_determinate"]
    final_abstain = [row for row in rows if row["ai_gold_status"] == "final_abstain"]
    silver_metrics = load_json(silver_metrics_path)
    result = {
        "artifact_type": "package_identity_crosswalk_ai_gold_diagnostic",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "production_default_changed": False,
        "crosswalk_built_from_gold": False,
        "candidate_family_motivated_by_ai_gold_error_analysis": True,
        "crosswalk_feature_dependencies": [
            "nvd_context.package_names",
            "ghsa_context.package_names",
            "nvd_context.references",
            "ghsa_context.references",
        ],
        "gold_fields_used_by_crosswalk": [],
        "input_rows": len(rows),
        "inputs": {
            "evidence": {"path": str(evidence_path), "sha256": sha256(evidence_path)},
            "gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
            "predictions": {
                "path": str(predictions_path),
                "sha256": sha256(predictions_path),
            },
            "silver_metrics": {
                "path": str(silver_metrics_path),
                "sha256": sha256(silver_metrics_path),
            },
        },
        "crosswalk_profile": {
            "direct_comparable_rows": len(direct_comparable),
            "crosswalk_comparable_rows": len(crosswalk_comparable),
            "newly_comparable_rows": len(newly_comparable),
            "direct_package_category_counts": dict(
                sorted(Counter(row["direct_package_category"] for row in rows).items())
            ),
            "crosswalk_package_category_counts": dict(
                sorted(
                    Counter(row["crosswalk_package_category"] for row in rows).items()
                )
            ),
            "repository_profile_counts": dict(
                sorted(
                    Counter(
                        row["repository_crosswalk_profile"]["category"]
                        for row in rows
                    ).items()
                )
            ),
            "newly_comparable_status_counts": dict(
                sorted(Counter(row["ai_gold_status"] for row in newly_comparable).items())
            ),
            "newly_comparable_reasoning_counts": dict(
                sorted(Counter(row["reasoning_type"] for row in newly_comparable).items())
            ),
            "newly_comparable_row_details": [
                {
                    "sample_id": row["sample_id"],
                    "cve_id": row["cve_id"],
                    "ai_gold_status": row["ai_gold_status"],
                    "reasoning_type": row["reasoning_type"],
                    "accepted_repositories": row["accepted_repositories"],
                    "direct_package_profile": row["direct_package_profile"],
                    "repository_crosswalk_profile": row[
                        "repository_crosswalk_profile"
                    ],
                }
                for row in newly_comparable
            ],
        },
        "ai_gold_determinate_rows": len(determinate),
        "ai_gold_final_abstain_rows": len(final_abstain),
        "ai_gold_determinate_method_points": {
            method: method_metrics(determinate, method) for method in METHODS
        },
        "ai_gold_determinate_paired_outcomes": [
            paired_outcomes(determinate, baseline, candidate)
            for baseline, candidate in METHOD_PAIRS
        ],
        "final_abstain_method_behavior": {
            method: {
                "rows": len(final_abstain),
                "non_abstain_outputs": sum(
                    row["predictions"][method] != "abstain" for row in final_abstain
                ),
            }
            for method in METHODS
        },
        "silver_method_points": silver_points(silver_metrics),
        "row_diagnostics": rows,
        "cautions": [
            "AI-adjudicated gold is not human-gold.",
            "The candidate family was motivated by prior AI-gold error analysis.",
            "A shared repository supports package comparability only under the stated alias and conflict guards; it does not prove version-range equivalence.",
            "Silver labels and AI-gold labels are not independent human references.",
            "Final-abstain rows have no accuracy target.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "package_identity_crosswalk_diagnostic.json"
    markdown_path = output_dir / "package_identity_crosswalk_diagnostic.md"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
