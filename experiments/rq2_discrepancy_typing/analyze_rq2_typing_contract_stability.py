#!/usr/bin/env python3
"""Audit whether RQ2 typing labels are comparable across protocol generations."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import analyze_rq2_typing_holdout_failure_modes as failure_modes


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEED = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_PRIMARY = "data/annotations/ai_adjudicated_gold/rq2_primary.jsonl"
DEFAULT_REVIEW = "data/annotations/ai_adjudicated_gold/rq2_review.jsonl"
DEFAULT_FRESH_SOURCE = "data/annotations/holdout/rq2_typing_v1/source_rows.jsonl"
DEFAULT_FRESH_CONSENSUS = "results/holdout/rq2_typing_v1/dual_review_consensus.jsonl"
DEFAULT_HUMAN_READINESS = (
    "results/holdout/rq2_typing_v1/human_review/"
    "rq2_typing_human_review_readiness.json"
)
DEFAULT_OLD_PROMPT = "docs/prompts/expert_candidate_annotation_prompt.md"
DEFAULT_NEW_PROMPT = "docs/prompts/rq2_typing_holdout_review.md"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1/contract_stability"
EXPECTED_SEED_ROWS = 300
EXPECTED_PRIMARY_ROWS = 300
EXPECTED_REVIEW_ROWS = 60
EXPECTED_FRESH_ROWS = 1250


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--primary", default=DEFAULT_PRIMARY)
    parser.add_argument("--review", default=DEFAULT_REVIEW)
    parser.add_argument("--fresh-source", default=DEFAULT_FRESH_SOURCE)
    parser.add_argument("--fresh-consensus", default=DEFAULT_FRESH_CONSENSUS)
    parser.add_argument("--human-readiness", default=DEFAULT_HUMAN_READINESS)
    parser.add_argument("--old-prompt", default=DEFAULT_OLD_PROMPT)
    parser.add_argument("--new-prompt", default=DEFAULT_NEW_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def counter_dict(values) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def seed_severity_candidate_row(source: dict) -> dict:
    if source.get("field") != "severity":
        raise ValueError("seed severity projection requires a severity row")
    context = source.get("field_context") or {}
    if not isinstance(context.get("nvd"), dict) or not isinstance(
        context.get("ghsa"), dict
    ):
        raise ValueError("seed severity row lacks structured field_context")
    return {
        **source,
        "nvd_value": context["nvd"],
        "ghsa_value": context["ghsa"],
    }


def evaluate_severity(
    cohort: str,
    labeled_rows: list[tuple[dict, str]],
) -> tuple[dict, list[dict]]:
    baseline_correct = candidate_correct = 0
    transitions = Counter()
    cases = []
    for source, label in labeled_rows:
        if source.get("field") != "severity":
            raise ValueError(f"{cohort} contains a non-severity row")
        candidate, reason = failure_modes.post_hoc_candidate(source)
        baseline = source["baseline_status"]
        baseline_correct += baseline == label
        candidate_correct += candidate == label
        if candidate != baseline:
            transitions[(baseline, candidate, label)] += 1
            cases.append(
                {
                    "artifact_type": "rq2_typing_contract_stability_case",
                    "label_is_human": False,
                    "eligible_for_human_gold_claim": False,
                    "cohort": cohort,
                    "sample_id": source["sample_id"],
                    "cve_id": source["cve_id"],
                    "field": "severity",
                    "baseline_status": baseline,
                    "new_contract_projection": candidate,
                    "non_human_label": label,
                    "diagnostic_reason": reason,
                }
            )
    rows = len(labeled_rows)
    return (
        {
            "rows": rows,
            "label_is_human": False,
            "baseline_correct": baseline_correct,
            "baseline_accuracy": baseline_correct / rows if rows else None,
            "new_contract_projection_correct": candidate_correct,
            "new_contract_projection_accuracy": (
                candidate_correct / rows if rows else None
            ),
            "correct_delta": candidate_correct - baseline_correct,
            "changed_rows": len(cases),
            "changed_transition_label": {
                " | ".join(key): value
                for key, value in sorted(transitions.items())
            },
        },
        cases,
    )


def old_affected_projection_cases(
    seed_rows: list[dict],
    primary_by_id: dict[str, dict],
) -> list[dict]:
    cases = []
    for source in seed_rows:
        if source.get("field") != "affected_versions":
            continue
        packages = source.get("package_names") or {}
        projected_empty = not source.get("nvd_value") and not source.get("ghsa_value")
        one_sided_packages = bool(packages.get("nvd")) != bool(packages.get("ghsa"))
        if not projected_empty or not one_sided_packages:
            continue
        label = primary_by_id[source["sample_id"]]["annotation"][
            "discrepancy_label"
        ]
        cases.append(
            {
                "artifact_type": "rq2_typing_contract_stability_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "cohort": "ai_gold_primary",
                "sample_id": source["sample_id"],
                "cve_id": source["cve_id"],
                "field": "affected_versions",
                "baseline_status": source["baseline_status"],
                "non_human_label": label,
                "nvd_projected_value": source.get("nvd_value"),
                "ghsa_projected_value": source.get("ghsa_value"),
                "nvd_package_names": packages.get("nvd") or [],
                "ghsa_package_names": packages.get("ghsa") or [],
                "raw_claim_available_to_labeler": False,
                "diagnostic_reason": (
                    "old seed projects both affected values to empty while retaining "
                    "package identity on only one side"
                ),
            }
        )
    return cases


def fresh_affected_projection_cases(
    source_rows: list[dict],
    consensus_by_id: dict[str, dict],
) -> list[dict]:
    cases = []
    for source in source_rows:
        if source.get("field") != "affected_versions":
            continue
        consensus = consensus_by_id[source["sample_id"]]
        if not consensus.get("strict_consensus"):
            continue
        candidate, reason = failure_modes.post_hoc_candidate(source)
        if candidate == source["baseline_status"]:
            continue
        cases.append(
            {
                "artifact_type": "rq2_typing_contract_stability_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "cohort": "fresh_holdout_strict",
                "sample_id": source["sample_id"],
                "cve_id": source["cve_id"],
                "field": "affected_versions",
                "baseline_status": source["baseline_status"],
                "new_contract_projection": candidate,
                "non_human_label": consensus["consensus_label"],
                "raw_claim_available_to_labeler": True,
                "diagnostic_reason": reason,
            }
        )
    return cases


def build_gate(
    severity_metrics: dict[str, dict],
    old_affected_cases: list[dict],
    fresh_affected_cases: list[dict],
    signed_human_rows: int,
) -> dict:
    severity_deltas = {
        cohort: values["correct_delta"]
        for cohort, values in severity_metrics.items()
    }
    severity_direction_stable = not (
        any(value > 0 for value in severity_deltas.values())
        and any(value < 0 for value in severity_deltas.values())
    )
    affected_input_comparable = not old_affected_cases or not fresh_affected_cases
    human_contract_available = signed_human_rows > 0
    passed = (
        severity_direction_stable
        and affected_input_comparable
        and human_contract_available
    )
    reasons = []
    if not severity_direction_stable:
        reasons.append(
            "severity direction reverses between old AI-gold and the fresh holdout"
        )
    if not affected_input_comparable:
        reasons.append(
            "old affected labels saw empty projected values while fresh reviewers saw raw unbounded claims"
        )
    if not human_contract_available:
        reasons.append("no signed real-human row establishes the intended field construct")
    return {
        "gate_name": "rq2_cross_protocol_candidate_advancement",
        "passed": passed,
        "status": "advance" if passed else "no_go_protocol_incompatible",
        "severity_correct_deltas": severity_deltas,
        "severity_direction_stable": severity_direction_stable,
        "affected_input_comparable": affected_input_comparable,
        "signed_human_rows": signed_human_rows,
        "human_contract_available": human_contract_available,
        "pooled_performance_claim_allowed": False,
        "production_switch_allowed": False,
        "reasons": reasons,
        "required_next_evidence": [
            "a shared calibration set labeled under one explicit human-approved contract",
            "raw source values preserved identically across every compared cohort",
            "a newly sealed time cohort after the contract and candidate are frozen",
        ],
    }


def validate_inputs(
    seed_rows: list[dict],
    primary_rows: list[dict],
    review_rows: list[dict],
    fresh_rows: list[dict],
    consensus_rows: list[dict],
) -> None:
    expected = (
        ("seed", seed_rows, EXPECTED_SEED_ROWS),
        ("primary", primary_rows, EXPECTED_PRIMARY_ROWS),
        ("review", review_rows, EXPECTED_REVIEW_ROWS),
        ("fresh source", fresh_rows, EXPECTED_FRESH_ROWS),
        ("fresh consensus", consensus_rows, EXPECTED_FRESH_ROWS),
    )
    for name, rows, count in expected:
        ids = [row.get("sample_id") for row in rows]
        if len(rows) != count or len(ids) != len(set(ids)):
            raise ValueError(f"{name} must contain {count} unique sample IDs")
    seed_ids = {row["sample_id"] for row in seed_rows}
    if {row["sample_id"] for row in primary_rows} != seed_ids:
        raise ValueError("primary AI-gold IDs do not match the 300-row seed")
    if any(row.get("original_sample_id") not in seed_ids for row in review_rows):
        raise ValueError("review row references an unknown original sample")
    if [row["sample_id"] for row in fresh_rows] != [
        row["sample_id"] for row in consensus_rows
    ]:
        raise ValueError("fresh source and consensus order/IDs differ")


def analyze(
    seed_rows: list[dict],
    primary_rows: list[dict],
    review_rows: list[dict],
    fresh_rows: list[dict],
    consensus_rows: list[dict],
    signed_human_rows: int,
) -> tuple[dict, list[dict]]:
    validate_inputs(seed_rows, primary_rows, review_rows, fresh_rows, consensus_rows)
    seed_by_id = {row["sample_id"]: row for row in seed_rows}
    primary_by_id = {row["sample_id"]: row for row in primary_rows}
    consensus_by_id = {row["sample_id"]: row for row in consensus_rows}

    primary_severity = []
    for source in seed_rows:
        if source["field"] != "severity":
            continue
        label = primary_by_id[source["sample_id"]]["annotation"][
            "discrepancy_label"
        ]
        primary_severity.append((seed_severity_candidate_row(source), label))

    review_severity = []
    for review in review_rows:
        if review["field"] != "severity":
            continue
        source = seed_by_id[review["original_sample_id"]]
        review_severity.append(
            (
                seed_severity_candidate_row(source),
                review["annotation"]["discrepancy_label"],
            )
        )

    fresh_severity = []
    for source in fresh_rows:
        if source["field"] != "severity":
            continue
        consensus = consensus_by_id[source["sample_id"]]
        if consensus.get("strict_consensus"):
            fresh_severity.append((source, consensus["consensus_label"]))

    severity_metrics = {}
    all_cases = []
    for name, rows in (
        ("ai_gold_primary", primary_severity),
        ("ai_gold_review", review_severity),
        ("fresh_holdout_strict", fresh_severity),
    ):
        metrics, cases = evaluate_severity(name, rows)
        severity_metrics[name] = metrics
        all_cases.extend(cases)

    old_affected_cases = old_affected_projection_cases(seed_rows, primary_by_id)
    fresh_affected_cases = fresh_affected_projection_cases(
        fresh_rows, consensus_by_id
    )
    all_cases.extend(old_affected_cases)
    all_cases.extend(fresh_affected_cases)
    gate = build_gate(
        severity_metrics,
        old_affected_cases,
        fresh_affected_cases,
        signed_human_rows,
    )
    metrics = {
        "artifact_type": "rq2_typing_contract_stability_diagnostic",
        "analysis_boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "post_hoc": True,
            "production_baseline_changed": False,
            "valid_for_confirmatory_performance_claim": False,
            "old_and_new_labels_share_one_construct": False,
        },
        "severity": severity_metrics,
        "affected_versions": {
            "old_primary_rows": sum(
                row["field"] == "affected_versions" for row in seed_rows
            ),
            "old_projected_both_empty_one_sided_package_rows": len(
                old_affected_cases
            ),
            "old_case_non_human_labels": counter_dict(
                row["non_human_label"] for row in old_affected_cases
            ),
            "fresh_strict_unbounded_projection_loss_rows": len(
                fresh_affected_cases
            ),
            "fresh_case_non_human_labels": counter_dict(
                row["non_human_label"] for row in fresh_affected_cases
            ),
            "cross_cohort_accuracy_identifiable": False,
            "reason": (
                "the old annotation rows contain empty projected values rather than "
                "the raw unbounded affected claims supplied to fresh reviewers"
            ),
        },
        "advancement_gate": gate,
    }
    return metrics, all_cases


def render_markdown(metrics: dict) -> str:
    severity = metrics["severity"]
    affected = metrics["affected_versions"]
    gate = metrics["advancement_gate"]
    lines = [
        "# RQ2 Typing Contract-Stability Diagnostic",
        "",
        "This is a post-hoc, non-human protocol audit. It does not modify the production baseline and is not a pooled performance evaluation.",
        "",
        "## Severity",
        "",
        "| Cohort | Rows | Baseline correct | New-contract correct | Delta |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for cohort in ("ai_gold_primary", "ai_gold_review", "fresh_holdout_strict"):
        values = severity[cohort]
        lines.append(
            f"| {cohort} | {values['rows']} | {values['baseline_correct']} | "
            f"{values['new_contract_projection_correct']} | {values['correct_delta']:+d} |"
        )
    lines.extend(
        [
            "",
            "The direction reverses because the fresh prompt explicitly treats a missing score beside the same label/vector as incomplete, while the older AI-gold decisions usually retain equivalent or representation labels.",
            "",
            "## Affected versions",
            "",
            f"- Old rows with both projected values empty but package identity on only one side: `{affected['old_projected_both_empty_one_sided_package_rows']}`.",
            f"- Fresh strict rows retaining raw one-sided unbounded claims: `{affected['fresh_strict_unbounded_projection_loss_rows']}`.",
            "- Cross-cohort accuracy is not identifiable because the old labeler did not receive the raw claims used by the new-contract projection.",
            "",
            "## Gate",
            "",
            f"- Status: `{gate['status']}`",
            f"- Passed: `{str(gate['passed']).lower()}`",
            "- Production switch allowed: `false`",
            "",
            "A human-approved shared contract and calibration set are required before freezing another time cohort.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        "seed": resolve(args.seed),
        "primary": resolve(args.primary),
        "review": resolve(args.review),
        "fresh_source": resolve(args.fresh_source),
        "fresh_consensus": resolve(args.fresh_consensus),
        "human_readiness": resolve(args.human_readiness),
        "old_prompt": resolve(args.old_prompt),
        "new_prompt": resolve(args.new_prompt),
    }
    seed_rows = list(iter_jsonl(paths["seed"]))
    primary_rows = list(iter_jsonl(paths["primary"]))
    review_rows = list(iter_jsonl(paths["review"]))
    fresh_rows = list(iter_jsonl(paths["fresh_source"]))
    consensus_rows = list(iter_jsonl(paths["fresh_consensus"]))
    readiness = json.loads(paths["human_readiness"].read_text(encoding="utf-8"))
    metrics, cases = analyze(
        seed_rows,
        primary_rows,
        review_rows,
        fresh_rows,
        consensus_rows,
        int(readiness.get("signed_final_rows") or 0),
    )
    metrics["inputs"] = {
        name: {"path": str(path), "sha256": sha256(path)}
        for name, path in paths.items()
    }
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rq2_typing_contract_stability.json"
    md_path = output_dir / "rq2_typing_contract_stability.md"
    cases_path = output_dir / "rq2_typing_contract_stability_cases.jsonl"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    with cases_path.open("w", encoding="utf-8") as handle:
        for row in cases:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
