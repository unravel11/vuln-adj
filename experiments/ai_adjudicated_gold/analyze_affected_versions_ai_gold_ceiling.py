#!/usr/bin/env python3
"""Diagnose affected-version bottlenecks against AI-adjudicated gold."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RQ3_DIR = PROJECT_ROOT / "experiments" / "rq3_adjudication"
sys.path.insert(0, str(RQ3_DIR))

from affected_versions_semantic_baseline import package_profile, range_relation  # noqa: E402


GOLD_INPUT = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
EVIDENCE_INPUT = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
PREDICTIONS_INPUT = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
UNCERTAINTY_INPUT = (
    "results/ai_adjudicated_gold/uncertainty/ai_gold_paired_uncertainty.json"
)
EXPECTED_ROWS = 100
SOURCE_LABELS = ("nvd", "ghsa", "both", "neither")
METHODS = (
    "version_token_support_baseline",
    "canonical_version_token_support_baseline",
    "contextual_canonical_version_claim_baseline",
    "package_gated_token_baseline",
    "repository_crosswalk_package_gated_token_baseline",
    "repository_crosswalk_package_gated_canonical_token_baseline",
    "package_range_evidence_baseline",
)
METHOD_DISPLAY = {
    "version_token_support_baseline": "Raw token",
    "canonical_version_token_support_baseline": "Canonical token",
    "contextual_canonical_version_claim_baseline": "Contextual canonical",
    "package_gated_token_baseline": "Package-gated raw",
    "repository_crosswalk_package_gated_token_baseline": "Crosswalk raw",
    "repository_crosswalk_package_gated_canonical_token_baseline": "Crosswalk canonical",
    "package_range_evidence_baseline": "Package-range",
}
CAPABILITY_REQUIREMENTS = {
    "package_identity": (
        "independently validated package-to-release mapping beyond repository identity"
    ),
    "range_semantic": (
        "release-graph and semantic interval comparison backed by release or advisory evidence"
    ),
    "insufficient_evidence": (
        "higher-coverage evidence retrieval with explicit provenance"
    ),
    "token_support": "CVE-local claim extraction beyond version-token presence",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", default="results/ai_adjudicated_gold/affected_versions_ceiling"
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


def category(value: object) -> str:
    if value is None:
        return "missing"
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def count_values(rows: list[dict], key: str) -> dict[str, int]:
    return dict(sorted(Counter(category(row.get(key)) for row in rows).items()))


def fetch_profile(row: dict) -> dict:
    records = row.get("evidence_context", {}).get("records", [])
    if not isinstance(records, list):
        raise ValueError(f"{row.get('sample_id')}: evidence records must be a list")
    status_counts = Counter(category(record.get("fetch_status")) for record in records)
    text_records = [
        record
        for record in records
        if record.get("fetch_status") == "ok"
        and str(record.get("text_snippet") or "").strip()
    ]
    nvd_records = [
        record for record in text_records if record.get("host") == "nvd.nist.gov"
    ]
    non_nvd_records = [
        record for record in text_records if record.get("host") != "nvd.nist.gov"
    ]
    if not records:
        profile_category = "no_candidate_records"
    elif not text_records:
        profile_category = "no_fetched_text"
    elif non_nvd_records:
        profile_category = "has_non_nvd_fetched_text"
    elif nvd_records:
        profile_category = "nvd_only_fetched_text"
    else:
        profile_category = "other_fetched_text_only"
    return {
        "category": profile_category,
        "candidate_record_count": len(records),
        "status_counts": dict(sorted(status_counts.items())),
        "ok_text_record_count": len(text_records),
        "nvd_ok_text_record_count": len(nvd_records),
        "non_nvd_ok_text_record_count": len(non_nvd_records),
    }


def load_predictions(path: Path, sample_ids: set[str]) -> tuple[dict[str, dict], list[str]]:
    selected: dict[str, dict] = defaultdict(dict)
    all_methods = set()
    identities = set()
    for row in iter_jsonl(path):
        sample_id = row.get("sample_id")
        method = row.get("method")
        predicted = row.get("predicted_source")
        if sample_id not in sample_ids:
            raise ValueError(f"{path}: unknown sample_id={sample_id}")
        if not method or predicted not in (*SOURCE_LABELS, "abstain"):
            raise ValueError(f"{path}: malformed prediction for {sample_id}")
        identity = (sample_id, method)
        if identity in identities:
            raise ValueError(f"{path}: duplicate prediction {identity}")
        identities.add(identity)
        all_methods.add(method)
        if method in METHODS:
            selected[sample_id][method] = row
    for sample_id in sorted(sample_ids):
        missing = sorted(set(METHODS) - set(selected[sample_id]))
        if missing:
            raise ValueError(f"{path}: {sample_id} missing methods {missing}")
    return dict(selected), sorted(all_methods)


def error_category(gold: str, predicted: str) -> str:
    if predicted == gold:
        return "correct"
    if predicted == "abstain":
        return "abstain_on_determinate"
    if gold == "both" and predicted in {"nvd", "ghsa"}:
        return "one_sided_when_gold_both"
    if predicted == "both" and gold in {"nvd", "ghsa"}:
        return "both_when_gold_one_sided"
    if gold == "neither":
        return "source_claim_when_gold_neither"
    if predicted == "neither":
        return "neither_when_gold_source_supported"
    if gold in {"nvd", "ghsa"} and predicted in {"nvd", "ghsa"}:
        return "wrong_one_sided_source"
    return "other_wrong"


def metric_block(rows: list[dict], method: str) -> dict:
    correct = [row for row in rows if row["predictions"][method] == row["gold_source"]]
    covered = [row for row in rows if row["predictions"][method] != "abstain"]
    covered_correct = [
        row for row in covered if row["predictions"][method] == row["gold_source"]
    ]
    predictions = Counter(row["predictions"][method] for row in rows)
    errors = Counter(
        error_category(row["gold_source"], row["predictions"][method])
        for row in rows
    )
    return {
        "rows": len(rows),
        "correct": len(correct),
        "accuracy": safe_divide(len(correct), len(rows)),
        "non_abstain": len(covered),
        "prediction_coverage": safe_divide(len(covered), len(rows)),
        "selective_accuracy": safe_divide(len(covered_correct), len(covered)),
        "predicted_source_counts": dict(sorted(predictions.items())),
        "outcome_counts": dict(sorted(errors.items())),
    }


def stratified_metrics(rows: list[dict], method: str, key: str) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[category(row.get(key))].append(row)
    return {
        group: metric_block(group_rows, method)
        for group, group_rows in sorted(groups.items())
    }


def cohort_summary(rows: list[dict]) -> dict:
    return {
        "rows": len(rows),
        "recorded_source_counts": count_values(rows, "recorded_source"),
        "discrepancy_label_counts": count_values(rows, "discrepancy_label"),
        "reasoning_type_counts": count_values(rows, "reasoning_type"),
        "confidence_counts": count_values(rows, "confidence"),
        "needs_human_review_counts": count_values(rows, "needs_human_review"),
        "package_profile_counts": count_values(rows, "package_category"),
        "range_relation_counts": count_values(rows, "range_relation"),
        "fetch_profile_counts": count_values(rows, "fetch_category"),
    }


def method_analysis(determinate: list[dict]) -> dict:
    result = {}
    for method in METHODS:
        values = metric_block(determinate, method)
        values["by_reasoning_type"] = stratified_metrics(
            determinate, method, "reasoning_type"
        )
        values["by_package_profile"] = stratified_metrics(
            determinate, method, "package_category"
        )
        values["by_range_relation"] = stratified_metrics(
            determinate, method, "range_relation"
        )
        values["by_fetch_profile"] = stratified_metrics(
            determinate, method, "fetch_category"
        )
        values["by_gold_source"] = stratified_metrics(
            determinate, method, "gold_source"
        )
        result[method] = values
    return result


def oracle_analysis(determinate: list[dict], methods: dict) -> dict:
    row_results = []
    only_method_correct = Counter()
    correct_method_count = Counter()
    for row in determinate:
        correct_methods = [
            method
            for method in METHODS
            if row["predictions"][method] == row["gold_source"]
        ]
        correct_method_count[len(correct_methods)] += 1
        if len(correct_methods) == 1:
            only_method_correct[correct_methods[0]] += 1
        row_results.append({**row, "correct_methods": correct_methods})

    covered = [row for row in row_results if row["correct_methods"]]
    missed = [row for row in row_results if not row["correct_methods"]]
    best_accuracy = max(methods[method]["accuracy"] for method in METHODS)
    best_methods = [
        method for method in METHODS if methods[method]["accuracy"] == best_accuracy
    ]
    return {
        "methods": list(METHODS),
        "oracle_is_deployable": False,
        "interpretation": (
            "post-hoc union coverage of the selected affected-version methods; "
            "it is not a learned selector or an evaluation result for a deployable method"
        ),
        "best_single_method_accuracy": best_accuracy,
        "best_single_methods": best_methods,
        "rows_correct_by_any_method": len(covered),
        "union_oracle_accuracy": safe_divide(len(covered), len(determinate)),
        "rows_correct_by_no_method": len(missed),
        "correct_method_count_distribution": {
            str(key): value for key, value in sorted(correct_method_count.items())
        },
        "only_method_correct_counts": dict(sorted(only_method_correct.items())),
        "no_method_correct_breakdown": {
            "gold_source": count_values(missed, "gold_source"),
            "reasoning_type": count_values(missed, "reasoning_type"),
            "package_profile": count_values(missed, "package_category"),
            "range_relation": count_values(missed, "range_relation"),
            "fetch_profile": count_values(missed, "fetch_category"),
        },
        "no_method_correct_rows": [
            {
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "gold_source": row["gold_source"],
                "reasoning_type": row["reasoning_type"],
                "package_category": row["package_category"],
                "range_relation": row["range_relation"],
                "fetch_category": row["fetch_category"],
                "predictions": row["predictions"],
            }
            for row in missed
        ],
    }


def unresolved_behavior(rows: list[dict]) -> dict:
    result = {}
    for method in METHODS:
        non_abstain = [row for row in rows if row["predictions"][method] != "abstain"]
        by_reasoning = {}
        groups: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            groups[row["reasoning_type"]].append(row)
        for reasoning_type, group_rows in sorted(groups.items()):
            emitted = sum(
                row["predictions"][method] != "abstain" for row in group_rows
            )
            by_reasoning[reasoning_type] = {
                "rows": len(group_rows),
                "non_abstain_outputs": emitted,
                "non_abstain_rate": safe_divide(emitted, len(group_rows)),
            }
        result[method] = {
            "rows": len(rows),
            "non_abstain_outputs": len(non_abstain),
            "non_abstain_rate": safe_divide(len(non_abstain), len(rows)),
            "predicted_source_counts": dict(
                sorted(Counter(row["predictions"][method] for row in rows).items())
            ),
            "by_reasoning_type": by_reasoning,
            "accuracy_available": False,
        }
    return result


def reasoning_requirements(rows: list[dict]) -> dict:
    status_groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        status_groups[row["ai_gold_status"]].append(row)
    reasoning_types = sorted({row["reasoning_type"] for row in rows})
    return {
        reasoning_type: {
            "explicit_review_tag": reasoning_type,
            "all_rows": sum(
                row["reasoning_type"] == reasoning_type for row in rows
            ),
            "final_determinate_rows": sum(
                row["reasoning_type"] == reasoning_type
                for row in status_groups["final_determinate"]
            ),
            "final_abstain_rows": sum(
                row["reasoning_type"] == reasoning_type
                for row in status_groups["final_abstain"]
            ),
            "required_capability": CAPABILITY_REQUIREMENTS.get(
                reasoning_type, "manual review of an unrecognized reasoning tag"
            ),
        }
        for reasoning_type in reasoning_types
    }


def uncertainty_context(path: Path, determinate_rows: int) -> dict:
    artifact = load_json(path)
    if artifact.get("label_is_human") is not False:
        raise ValueError(f"{path}: uncertainty artifact must not claim human labels")
    try:
        comparisons = artifact["rq3"]["affected_versions"]["comparisons"]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"{path}: missing affected_versions comparisons") from exc
    stable_positive = []
    summaries = []
    for comparison in comparisons:
        if comparison.get("row_count") != determinate_rows:
            raise ValueError(
                f"{path}: comparison row_count differs from determinate cohort"
            )
        interval = comparison.get("bootstrap_95_percent_intervals", {}).get(
            "delta_accuracy"
        )
        if not isinstance(interval, list) or len(interval) != 2:
            raise ValueError(f"{path}: missing delta_accuracy interval")
        delta = comparison.get("delta", {}).get("accuracy")
        candidate = comparison.get("candidate_method")
        if not isinstance(delta, (int, float)) or not candidate:
            raise ValueError(f"{path}: malformed comparison")
        if delta > 0 and interval[0] > 0:
            stable_positive.append(candidate)
        summaries.append(
            {
                "baseline_method": comparison.get("baseline_method"),
                "candidate_method": candidate,
                "accuracy_delta": delta,
                "bootstrap_95_percent_delta_accuracy": interval,
            }
        )
    return {
        "path": str(path),
        "sha256": sha256(path),
        "comparison_count": len(summaries),
        "comparisons": summaries,
        "candidates_with_positive_delta_and_interval_excluding_zero": stable_positive,
    }


def format_counts(values: dict[str, int]) -> str:
    return ", ".join(f"{key}={value}" for key, value in values.items()) or "none"


def render_markdown(result: dict) -> str:
    cohorts = result["cohorts"]
    determinate = cohorts["final_determinate"]
    abstain = cohorts["final_abstain"]
    methods = result["method_performance_on_determinate"]
    oracle = result["tested_method_union_oracle"]
    requirements = result["explicit_reasoning_requirements"]
    uncertainty = result["paired_uncertainty_context"]
    lines = [
        "# Affected-Versions AI-Gold Ceiling Diagnostic",
        "",
        "This is a descriptive analysis of AI-adjudicated gold with `label_is_human=false`. It is not human-gold validation and is not eligible for a final paper claim.",
        "",
        "## Cohorts",
        "",
        f"The input contains `{result['input_rows']}` rows: `{determinate['rows']}` final-determinate rows and `{abstain['rows']}` final-abstain rows.",
        "",
        "| Explicit reasoning tag | Determinate | Final abstain | All | Capability required before promotion |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for reasoning_type, values in requirements.items():
        lines.append(
            f"| {reasoning_type} | {values['final_determinate_rows']} | "
            f"{values['final_abstain_rows']} | {values['all_rows']} | "
            f"{values['required_capability']} |"
        )

    lines.extend(
        [
            "",
            "The counts above use the structured `version_reasoning_type` field; no cause was inferred from rationale free text.",
            "",
            "### Observable strata",
            "",
            "| Cohort | Package profile | Range relation | Fetch profile |",
            "| --- | --- | --- | --- |",
            f"| final_determinate | {format_counts(determinate['package_profile_counts'])} | {format_counts(determinate['range_relation_counts'])} | {format_counts(determinate['fetch_profile_counts'])} |",
            f"| final_abstain | {format_counts(abstain['package_profile_counts'])} | {format_counts(abstain['range_relation_counts'])} | {format_counts(abstain['fetch_profile_counts'])} |",
            "",
            "## Determinate Performance",
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

    reasoning_types = sorted(determinate["reasoning_type_counts"])
    lines.extend(
        [
            "",
            "### Accuracy by explicit reasoning tag",
            "",
            "| Reasoning tag | Rows | "
            + " | ".join(METHOD_DISPLAY[method] for method in METHODS)
            + " |",
            "| --- | ---: | " + " | ".join("---:" for _ in METHODS) + " |",
        ]
    )
    for reasoning_type in reasoning_types:
        row_count = determinate["reasoning_type_counts"][reasoning_type]
        values = [
            methods[method]["by_reasoning_type"][reasoning_type]["accuracy"]
            for method in METHODS
        ]
        lines.append(
            f"| {reasoning_type} | {row_count} | "
            + " | ".join(f"{value:.4f}" for value in values)
            + " |"
        )

    lines.extend(
        [
            "",
            "### Error modes",
            "",
            "| Method | Outcome counts on 40 determinate rows |",
            "| --- | --- |",
        ]
    )
    for method in METHODS:
        lines.append(
            f"| {method} | {format_counts(methods[method]['outcome_counts'])} |"
        )

    lines.extend(
        [
            "",
            "## Tested-Method Union Oracle",
            "",
            f"A post-hoc selector that chooses a correct prediction whenever any of the `{len(METHODS)}` selected methods is correct would cover `{oracle['rows_correct_by_any_method']}/{determinate['rows']}` rows (`{oracle['union_oracle_accuracy']:.4f}`). The best single method reaches `{oracle['best_single_method_accuracy']:.4f}`. This oracle is not deployable and only measures complementarity within the tested rule set.",
            "",
            f"`{oracle['rows_correct_by_no_method']}` determinate rows are missed by every selected method. Their explicit reasoning tags are: {format_counts(oracle['no_method_correct_breakdown']['reasoning_type'])}.",
            "",
            "## Behavior on Final-Abstain Rows",
            "",
            "These rows have no determinate target, so non-abstain outputs are reported as behavior, not as errors or correct predictions.",
            "",
            "| Method | Non-abstain outputs | Rate |",
            "| --- | ---: | ---: |",
        ]
    )
    for method in METHODS:
        values = result["method_behavior_on_final_abstain"][method]
        lines.append(
            f"| {method} | {values['non_abstain_outputs']}/{values['rows']} | "
            f"{values['non_abstain_rate']:.4f} |"
        )

    dominant = max(
        requirements.items(), key=lambda item: item[1]["final_abstain_rows"]
    )
    direct_package = methods["package_gated_token_baseline"]
    crosswalk_package = methods[
        "repository_crosswalk_package_gated_token_baseline"
    ]
    lines.extend(
        [
            "",
            "## Bounded Interpretation",
            "",
            f"The largest explicit unresolved category is `{dominant[0]}` with `{dominant[1]['final_abstain_rows']}/{abstain['rows']}` final-abstain rows. Within this artifact, that points to `{dominant[1]['required_capability']}` as the highest-volume next requirement.",
            "",
            f"The repository crosswalk raises determinate prediction coverage from `{direct_package['prediction_coverage']:.4f}` to `{crosswalk_package['prediction_coverage']:.4f}` but leaves accuracy at `{crosswalk_package['accuracy']:.4f}` and lowers selective accuracy from `{direct_package['selective_accuracy']:.4f}` to `{crosswalk_package['selective_accuracy']:.4f}`. Repository identity therefore improves comparability without resolving range-source support.",
            "",
            f"The paired uncertainty diagnostic reports `{len(uncertainty['candidates_with_positive_delta_and_interval_excluding_zero'])}` candidate comparisons with a positive accuracy delta whose 95% bootstrap interval excludes zero. Together with the union-oracle misses, this supports stopping further lexical token tuning as the immediate next step. It does not establish a population-level method ceiling.",
            "",
            "Next experiment: freeze and independently validate the repository crosswalk, then add release-graph and release-boundary evidence features on a separate development split. Production defaults remain unchanged.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    gold_path = resolve(GOLD_INPUT)
    evidence_path = resolve(EVIDENCE_INPUT)
    predictions_path = resolve(PREDICTIONS_INPUT)
    uncertainty_path = resolve(UNCERTAINTY_INPUT)
    output_dir = resolve(args.output_dir)

    gold = load_unique(gold_path, "sample_id")
    evidence = load_unique(evidence_path, "sample_id")
    if len(gold) != EXPECTED_ROWS or len(evidence) != EXPECTED_ROWS:
        raise ValueError(
            f"expected {EXPECTED_ROWS} gold/evidence rows; found {len(gold)}/{len(evidence)}"
        )
    if set(gold) != set(evidence):
        raise ValueError("gold and evidence sample_id sets differ")
    predictions, all_methods = load_predictions(predictions_path, set(gold))

    rows = []
    for sample_id in sorted(gold):
        gold_row = gold[sample_id]
        annotation = gold_row.get("annotation")
        if gold_row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: label_is_human must be false")
        if gold_row.get("eligible_for_human_gold_claim") is not False:
            raise ValueError(
                f"{sample_id}: eligible_for_human_gold_claim must be false"
            )
        if not isinstance(annotation, dict):
            raise ValueError(f"{sample_id}: missing annotation")
        status = gold_row.get("ai_gold_status")
        recorded_source = annotation.get("adjudicated_source")
        if status == "final_determinate" and recorded_source not in SOURCE_LABELS:
            raise ValueError(
                f"{sample_id}: determinate row has invalid source={recorded_source}"
            )
        if status not in {"final_determinate", "final_abstain"}:
            raise ValueError(f"{sample_id}: invalid ai_gold_status={status}")

        evidence_row = evidence[sample_id]
        packages = package_profile(evidence_row)
        ranges = range_relation(evidence_row)
        fetched = fetch_profile(evidence_row)
        row = {
            "sample_id": sample_id,
            "cve_id": gold_row.get("cve_id"),
            "ai_gold_status": status,
            "gold_source": recorded_source if status == "final_determinate" else None,
            "recorded_source": recorded_source,
            "discrepancy_label": annotation.get("discrepancy_label"),
            "reasoning_type": annotation.get("version_reasoning_type"),
            "confidence": annotation.get("confidence"),
            "needs_human_review": annotation.get("needs_human_review"),
            "package_category": packages["category"],
            "range_relation": ranges["relation"],
            "fetch_category": fetched["category"],
            "package_profile": packages,
            "range_profile": ranges,
            "fetch_profile": fetched,
            "predictions": {
                method: predictions[sample_id][method]["predicted_source"]
                for method in METHODS
            },
        }
        rows.append(row)

    determinate = [row for row in rows if row["ai_gold_status"] == "final_determinate"]
    final_abstain = [row for row in rows if row["ai_gold_status"] == "final_abstain"]
    methods = method_analysis(determinate)
    oracle = oracle_analysis(determinate, methods)
    paired_uncertainty = uncertainty_context(uncertainty_path, len(determinate))
    result = {
        "artifact_type": "affected_versions_ai_gold_ceiling_diagnostic",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "eligible_for_provisional_candidate_analysis": True,
        "population_generalization_supported": False,
        "production_default_changed": False,
        "input_rows": len(rows),
        "inputs": {
            "gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
            "evidence": {
                "path": str(evidence_path),
                "sha256": sha256(evidence_path),
            },
            "predictions": {
                "path": str(predictions_path),
                "sha256": sha256(predictions_path),
            },
        },
        "selected_methods": list(METHODS),
        "all_available_prediction_methods": all_methods,
        "cohorts": {
            "final_determinate": cohort_summary(determinate),
            "final_abstain": cohort_summary(final_abstain),
        },
        "explicit_reasoning_requirements": reasoning_requirements(rows),
        "method_performance_on_determinate": methods,
        "tested_method_union_oracle": oracle,
        "paired_uncertainty_context": paired_uncertainty,
        "method_behavior_on_final_abstain": unresolved_behavior(final_abstain),
        "row_diagnostics": rows,
        "cautions": [
            "AI-adjudicated gold is not human-gold.",
            "Only 40 of 100 rows have final-determinate AI-gold labels.",
            "Final-abstain rows have no accuracy target; non-abstain method outputs on them are behavior only.",
            "The tested-method union oracle is a post-hoc diagnostic and is not deployable.",
            "Method development, evidence review, and AI adjudication are not independent.",
            "Observed strata and explicit reasoning tags do not establish causal error mechanisms.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_ai_gold_ceiling.json"
    markdown_path = output_dir / "affected_versions_ai_gold_ceiling.md"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
