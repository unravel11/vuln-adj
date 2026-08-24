#!/usr/bin/env python3
"""Summarize contextual affected-version baselines across candidate diagnostics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SILVER = "results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json"
DEFAULT_CANDIDATE = "results/expert_candidate_validation/expert_candidate_metrics.json"
DEFAULT_DUAL = (
    "results/rq3_adjudication/affected_versions_canonical_dual_review/"
    "dual_ai_review.json"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/affected_versions_canonical_dual_review"
METHODS = (
    "version_token_support_baseline",
    "canonical_version_token_support_baseline",
    "contextual_version_claim_baseline",
    "contextual_canonical_version_claim_baseline",
    "package_gated_contextual_version_claim_baseline",
    "package_gated_contextual_canonical_version_claim_baseline",
    "package_gated_token_baseline",
    "package_gated_canonical_token_baseline",
    "package_range_evidence_baseline",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", default=DEFAULT_SILVER)
    parser.add_argument("--candidate", default=DEFAULT_CANDIDATE)
    parser.add_argument("--dual-review", default=DEFAULT_DUAL)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def render_markdown(summary: dict) -> str:
    lines = [
        "# Affected Versions Contextual Variant Diagnostic",
        "",
        "All values below use LLM silver labels, AI expert candidates, or a selected dual-AI review set. None are human-gold results.",
        "",
        "| Method | Silver agreement | Silver macro-F1 | Coverage | Candidate agreement | Candidate macro-F1 | Coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for method, values in summary["methods"].items():
        silver = values["silver_v2"]
        candidate = values["expert_candidate"]
        lines.append(
            f"| `{method}` | {silver['agreement']:.4f} | {silver['macro_f1']:.4f} | "
            f"{silver['coverage']:.4f} | {candidate['agreement']:.4f} | "
            f"{candidate['macro_f1']:.4f} | {candidate['coverage']:.4f} |"
        )
    dual = summary["dual_ai_selected_set"]
    lines.extend(
        [
            "",
            f"The two blinded AI passes agreed on canonical-match verdict and policy for 10/10 rows, on source for 7/10, and on discrepancy label for 4/10. On the seven source-consensus rows, raw token and package-contextual-canonical each matched 4 rows; unrestricted canonical matched 1 row.",
            "",
            f"Method-selection status: `{summary['method_selection']['status']}`. Canonical matching may remain a feature, but the current evidence does not support using token presence alone as complete range adjudication.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    silver_path = resolve_path(args.silver)
    candidate_path = resolve_path(args.candidate)
    dual_path = resolve_path(args.dual_review)
    output_dir = resolve_path(args.output_dir)

    silver = read_json(silver_path)
    candidate = read_json(candidate_path)["rq3"]["affected_versions"]
    dual = read_json(dual_path)
    methods = {}
    for method in METHODS:
        if method not in silver["methods"] or method not in candidate["methods"]:
            raise ValueError(f"Missing method from inputs: {method}")
        silver_metrics = silver["methods"][method]
        candidate_metrics = candidate["methods"][method]
        methods[method] = {
            "silver_v2": {
                "agreement": silver_metrics["accuracy"],
                "macro_f1": silver_metrics[
                    "macro_f1_over_supported_silver_labels"
                ],
                "coverage": silver_metrics["coverage_non_abstain"],
                "selective_agreement": silver_metrics["accuracy_when_non_abstain"],
            },
            "expert_candidate": {
                "agreement": candidate_metrics["agreement_vs_expert_candidate"],
                "macro_f1": candidate_metrics[
                    "macro_f1_over_supported_candidate_sources"
                ],
                "coverage": candidate_metrics["coverage_non_abstain"],
                "selective_agreement": candidate_metrics[
                    "agreement_when_non_abstain"
                ],
            },
        }

    components = dual["component_agreement"]
    comparisons = dual["consensus_source_comparison"]
    summary = {
        "artifact_type": "affected_versions_contextual_variant_diagnostic",
        "label_is_human": False,
        "human_gold": False,
        "methods": methods,
        "dual_ai_selected_set": {
            "row_count": dual["row_count"],
            "selected_method_disagreement_set": True,
            "discrepancy_label_agreement": components["discrepancy_label"],
            "adjudicated_source_agreement": components["adjudicated_source"],
            "canonical_match_verdict_agreement": components[
                "canonical_match_verdict"
            ],
            "recommended_match_policy_agreement": components[
                "recommended_match_policy"
            ],
            "full_decision_consensus_count": dual[
                "full_decision_consensus_count"
            ],
            "source_consensus_comparison": comparisons,
        },
        "method_selection": {
            "status": "unresolved_candidate_diagnostic_only",
            "eligible_for_provisional_analysis": True,
            "eligible_for_final_paper_claim": False,
            "canonical_token_as_standalone_range_adjudicator_supported": False,
            "context_filter_as_final_method_supported": False,
            "package_gate_as_final_method_supported": False,
            "observations": [
                "Unrestricted raw and canonical token baselines tie at 0.57 silver agreement.",
                "Contextual canonical reaches 0.46 silver agreement at 0.80 coverage and 0.49 candidate agreement at 0.80 coverage.",
                "Package-contextual canonical reaches 4/7 on the selected dual-AI source-consensus rows but only 0.34 full-sample coverage.",
                "A valid contextual token match does not establish package mapping or complete range semantics.",
            ],
        },
        "inputs": {
            "silver": str(silver_path),
            "candidate": str(candidate_path),
            "dual_review": str(dual_path),
        },
        "cautions": [
            "Silver labels are evidence-aware LLM labels, not human gold.",
            "Expert candidates and both blinded reviewers use the same AI model family.",
            "The ten dual-review rows were selected because raw and canonical methods differ.",
            "No result may be generalized or used for final method selection without signed review.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "contextual_variant_diagnostic.json"
    md_path = output_dir / "contextual_variant_diagnostic.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
