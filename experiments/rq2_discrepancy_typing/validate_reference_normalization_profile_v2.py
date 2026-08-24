#!/usr/bin/env python3
"""Validate the candidate-backed reference normalization v2 profile end to end."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CURRENT_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_CURRENT_STATS = (
    "data/processed/bootstrap/discrepancies/field_discrepancy_stats.json"
)
DEFAULT_CURRENT_RERUN_VIEWS = (
    "/tmp/vuln_adj_reference_profile_current/nvd_ghsa_field_views.jsonl"
)
DEFAULT_CURRENT_RERUN_STATS = (
    "/tmp/vuln_adj_reference_profile_current/field_discrepancy_stats.json"
)
DEFAULT_V2_DIR = "results/rq2_discrepancy_typing/reference_normalization_v2"
DEFAULT_V2_VIEWS = f"{DEFAULT_V2_DIR}/full_profile/nvd_ghsa_field_views.jsonl"
DEFAULT_V2_STATS = f"{DEFAULT_V2_DIR}/full_profile/field_discrepancy_stats.json"
DEFAULT_WORKLIST = (
    "results/rq2_discrepancy_typing/"
    "reference_normalization_changed_cases.review.jsonl"
)
DEFAULT_DUAL_CANDIDATE = (
    "results/rq2_discrepancy_typing/reference_normalization_dual_ai_candidate.jsonl"
)
DEFAULT_DUAL_REVIEW = (
    "results/rq2_discrepancy_typing/reference_normalization_dual_ai_review.json"
)
DEFAULT_VARIANT_DIAGNOSTIC = (
    "results/rq2_discrepancy_typing/reference_normalization_variant_diagnostic.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-views", default=DEFAULT_CURRENT_VIEWS)
    parser.add_argument("--current-stats", default=DEFAULT_CURRENT_STATS)
    parser.add_argument("--current-rerun-views", default=DEFAULT_CURRENT_RERUN_VIEWS)
    parser.add_argument("--current-rerun-stats", default=DEFAULT_CURRENT_RERUN_STATS)
    parser.add_argument("--v2-views", default=DEFAULT_V2_VIEWS)
    parser.add_argument("--v2-stats", default=DEFAULT_V2_STATS)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--dual-candidate", default=DEFAULT_DUAL_CANDIDATE)
    parser.add_argument("--dual-review", default=DEFAULT_DUAL_REVIEW)
    parser.add_argument("--variant-diagnostic", default=DEFAULT_VARIANT_DIAGNOSTIC)
    parser.add_argument("--output-dir", default=DEFAULT_V2_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def index_unique(rows: list[dict], path: Path) -> dict[str, dict]:
    indexed = {}
    for row in rows:
        cve_id = str(row.get("cve_id") or "")
        if not cve_id:
            raise ValueError(f"{path}: missing cve_id")
        if cve_id in indexed:
            raise ValueError(f"{path}: duplicate cve_id={cve_id}")
        indexed[cve_id] = row
    return indexed


def status_counts(rows: list[dict]) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        for result in row["field_discrepancies"].values():
            counts[result["status"]] += 1
    return dict(sorted(counts.items()))


def render_markdown(result: dict) -> str:
    current = result["rq2_candidate_diagnostic"]["current"]
    v2 = result["rq2_candidate_diagnostic"]["resource_identity_v1"]
    lines = [
        "# Reference Normalization v2 Profile Validation",
        "",
        "> Candidate-backed experiment only; human-gold and final-paper eligibility remain false.",
        "",
        f"- Current profile byte-identical rerun: {result['current_profile']['field_views_byte_identical']}",
        f"- V2 changed reference statuses: {result['v2_profile']['changed_reference_status_rows']}",
        f"- Non-reference status changes: {result['v2_profile']['changed_non_reference_status_rows']}",
        f"- Changed set equals dual-reviewed worklist: {result['v2_profile']['changed_set_matches_worklist']}",
        f"- Dual-AI approvals: {result['dual_ai_review']['dual_approve_incomplete_rows']}/{result['dual_ai_review']['row_count']}",
        "",
        "| Scope | Current agreement | V2 agreement | Current macro-F1 | V2 macro-F1 |",
        "|---|---:|---:|---:|---:|",
        f"| RQ2 primary determinate | {current['overall_primary_agreement']:.4f} | {v2['overall_primary_agreement']:.4f} | {current['overall_primary_macro_f1']:.4f} | {v2['overall_primary_macro_f1']:.4f} |",
        f"| RQ2 review determinate | {current['overall_review_agreement']:.4f} | {v2['overall_review_agreement']:.4f} | {current['overall_review_macro_f1']:.4f} | {v2['overall_review_macro_f1']:.4f} |",
        "",
        "| Reference label | Current count | V2 count | Delta |",
        "|---|---:|---:|---:|",
    ]
    labels = sorted(
        set(result["distribution_impact"]["references_current"])
        | set(result["distribution_impact"]["references_v2"])
    )
    for label in labels:
        old = result["distribution_impact"]["references_current"].get(label, 0)
        new = result["distribution_impact"]["references_v2"].get(label, 0)
        lines.append(f"| {label} | {old} | {new} | {new - old:+d} |")
    lines.extend(
        [
            "",
            "The default production profile remains `current`. V2 is eligible for provisional candidate-backed analysis only; independent human review and author sign-off are still required before final claims.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        name: resolve_path(value)
        for name, value in {
            "current_views": args.current_views,
            "current_stats": args.current_stats,
            "current_rerun_views": args.current_rerun_views,
            "current_rerun_stats": args.current_rerun_stats,
            "v2_views": args.v2_views,
            "v2_stats": args.v2_stats,
            "worklist": args.worklist,
            "dual_candidate": args.dual_candidate,
            "dual_review": args.dual_review,
            "variant_diagnostic": args.variant_diagnostic,
            "output_dir": args.output_dir,
        }.items()
    }
    for name, path in paths.items():
        if name != "output_dir" and not path.exists():
            raise FileNotFoundError(path)

    current_rows = load_jsonl(paths["current_views"])
    current_rerun_rows = load_jsonl(paths["current_rerun_views"])
    v2_rows = load_jsonl(paths["v2_views"])
    current = index_unique(current_rows, paths["current_views"])
    current_rerun = index_unique(current_rerun_rows, paths["current_rerun_views"])
    v2 = index_unique(v2_rows, paths["v2_views"])
    if len(current) != 8066 or set(current) != set(current_rerun) or set(current) != set(v2):
        raise ValueError("Current, rerun, and v2 views must contain the same 8066 CVEs")

    current_stats = load_json(paths["current_stats"])
    current_rerun_stats = load_json(paths["current_rerun_stats"])
    v2_stats = load_json(paths["v2_stats"])
    if current_stats["fields"] != current_rerun_stats["fields"]:
        raise AssertionError("Current profile rerun changed field counts")
    if sha256(paths["current_views"]) != sha256(paths["current_rerun_views"]):
        raise AssertionError("Current profile field views are not byte-identical")

    changed_reference_status = []
    changed_non_reference_status = []
    for cve_id in sorted(current):
        if v2[cve_id].get("reference_normalization_profile") != "resource_identity_v1":
            raise AssertionError(f"{cve_id}: missing v2 profile marker")
        for field in current[cve_id]["field_discrepancies"]:
            old_status = current[cve_id]["field_discrepancies"][field]["status"]
            new_status = v2[cve_id]["field_discrepancies"][field]["status"]
            if old_status == new_status:
                continue
            change = {
                "cve_id": cve_id,
                "field": field,
                "current_status": old_status,
                "v2_status": new_status,
            }
            if field == "references":
                changed_reference_status.append(change)
            else:
                changed_non_reference_status.append(change)

    worklist = index_unique(load_jsonl(paths["worklist"]), paths["worklist"])
    dual_candidate = index_unique(
        load_jsonl(paths["dual_candidate"]), paths["dual_candidate"]
    )
    changed_ids = {row["cve_id"] for row in changed_reference_status}
    if changed_ids != set(worklist) or changed_ids != set(dual_candidate):
        raise AssertionError("V2 changed set does not match worklist and dual candidate")
    if changed_non_reference_status:
        raise AssertionError("V2 changed a non-reference field status")
    for change in changed_reference_status:
        if (change["current_status"], change["v2_status"]) != (
            "representation_discrepancy",
            "incomplete",
        ):
            raise AssertionError(f"Unexpected transition: {change}")
        candidate = dual_candidate[change["cve_id"]]
        if (
            candidate.get("label_is_human") is not False
            or candidate.get("consensus_status") != "incomplete"
            or candidate.get("requires_human_signoff") is not True
        ):
            raise AssertionError(f"Invalid dual candidate: {change['cve_id']}")

    dual_review = load_json(paths["dual_review"])
    if (
        dual_review.get("label_is_human") is not False
        or dual_review.get("exact_agreement_count") != 56
        or dual_review.get("dual_approve_incomplete_rows") != 56
        or dual_review.get("human_signed_rows") != 0
    ):
        raise AssertionError("Dual-AI review gate failed")

    diagnostic = load_json(paths["variant_diagnostic"])
    current_diag = diagnostic["variants"]["current_exact"]
    v2_diag = diagnostic["variants"]["transport_line_known_query_aliases"]
    result = {
        "artifact_type": "reference_normalization_v2_profile_validation",
        "candidate_backed_profile_validated": True,
        "label_is_human": False,
        "human_gold": False,
        "production_default_profile": "current",
        "production_default_changed": False,
        "eligible_for_provisional_candidate_analysis": True,
        "eligible_for_final_paper_claim": False,
        "current_profile": {
            "row_count": len(current),
            "field_views_byte_identical": True,
            "field_counts_semantically_identical": True,
            "stats_provenance_path_changed": (
                current_stats.get("input_aligned_path")
                != current_rerun_stats.get("input_aligned_path")
            ),
            "canonical_sha256": sha256(paths["current_views"]),
            "rerun_sha256": sha256(paths["current_rerun_views"]),
        },
        "v2_profile": {
            "profile": v2_stats.get("reference_normalization_profile"),
            "row_count": len(v2),
            "changed_reference_status_rows": len(changed_reference_status),
            "changed_non_reference_status_rows": len(changed_non_reference_status),
            "changed_set_matches_worklist": changed_ids == set(worklist),
            "status_transition_counts": {
                "representation_discrepancy->incomplete": len(
                    changed_reference_status
                )
            },
            "changed_cve_ids": sorted(changed_ids),
            "field_views_sha256": sha256(paths["v2_views"]),
        },
        "dual_ai_review": {
            key: dual_review[key]
            for key in (
                "row_count",
                "exact_agreement_count",
                "exact_agreement_rate",
                "cohen_kappa",
                "cohen_kappa_status",
                "dual_approve_incomplete_rows",
                "label_disagreement_count",
                "human_signed_rows",
            )
        },
        "rq2_candidate_diagnostic": {
            "current": {
                "overall_primary_agreement": current_diag[
                    "overall_primary_candidate"
                ]["agreement"],
                "overall_primary_macro_f1": current_diag[
                    "overall_primary_candidate"
                ]["macro_f1_over_supported_candidate_labels"],
                "overall_review_agreement": current_diag[
                    "overall_review_candidate"
                ]["agreement"],
                "overall_review_macro_f1": current_diag[
                    "overall_review_candidate"
                ]["macro_f1_over_supported_candidate_labels"],
            },
            "resource_identity_v1": {
                "overall_primary_agreement": v2_diag["overall_primary_candidate"][
                    "agreement"
                ],
                "overall_primary_macro_f1": v2_diag[
                    "overall_primary_candidate"
                ]["macro_f1_over_supported_candidate_labels"],
                "overall_review_agreement": v2_diag["overall_review_candidate"][
                    "agreement"
                ],
                "overall_review_macro_f1": v2_diag[
                    "overall_review_candidate"
                ]["macro_f1_over_supported_candidate_labels"],
            },
        },
        "distribution_impact": {
            "references_current": current_stats["fields"]["references"],
            "references_v2": v2_stats["fields"]["references"],
            "all_field_instances_current": status_counts(current_rows),
            "all_field_instances_v2": status_counts(v2_rows),
        },
        "input_paths": {
            name: str(path) for name, path in paths.items() if name != "output_dir"
        },
        "cautions": [
            "The v2 profile is backed by two separate passes of the same AI model family, not humans.",
            "The 56 reviewed rows were selected because v2 changes their labels.",
            "Live URL content and redirects were not independently verified by the two reviewers.",
            "The default production profile remains current until human sign-off.",
        ],
    }

    output_dir = paths["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "profile_validation.json"
    markdown_path = output_dir / "profile_validation.md"
    json_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Wrote {json_path}")
    print(f"Wrote {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
