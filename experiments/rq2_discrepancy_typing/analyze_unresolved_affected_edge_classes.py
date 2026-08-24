#!/usr/bin/env python3
"""Classify the 28 unresolved affected-version rows by graph edge structure."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "unresolved_affected_edge_class_audit_v1"
DEFAULT_WORKLIST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "blind/worklist_d.blind.jsonl"
)
DEFAULT_SEALED_MANIFEST = (
    "data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "manifest.sealed.json"
)
DEFAULT_PRIOR_GRAPH = (
    "results/holdout/rq2_typing_v1/contract_calibration_v2/"
    "artifact_lineage_cross_case_v1/analysis.json"
)
DEFAULT_CONSENSUS = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "dual_review_consensus.jsonl"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "affected_versions_unresolved_edge_class_audit_contract_v1.md"
)
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "affected_versions_edge_class_audit_v1"
)
EXPECTED_ROWS = 28
PSEUDO_VERSION = re.compile(r"(?:^|[^0-9])\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}(?:$|[^0-9a-f])")
QUALIFIED_VERSION = re.compile(r"(?:^|[-.])(alpha|beta|rc|pre|preview|p)\d*", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worklist", default=DEFAULT_WORKLIST)
    parser.add_argument("--sealed-manifest", default=DEFAULT_SEALED_MANIFEST)
    parser.add_argument("--prior-graph", default=DEFAULT_PRIOR_GRAPH)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, values: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in values),
        encoding="utf-8",
    )


def normalized_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def identifier_leaf(value: str) -> str:
    leaf = re.split(r"[/ :]", value)[-1]
    return normalized_identifier(leaf)


def item_subject(item: dict) -> str:
    return str(item.get("package_name") or item.get("product") or "")


def singleton_value(item: dict) -> str | None:
    value = item.get("version")
    return value if isinstance(value, str) and value not in {"", "*", "-"} else None


def span_signature(item: dict) -> tuple:
    singleton = singleton_value(item)
    if singleton is not None:
        return ("singleton", singleton, True, singleton, True)

    start_excluding = item.get("version_start_excluding")
    start_including = item.get("version_start_including")
    introduced = item.get("introduced")
    if start_excluding not in {None, "0"}:
        start, start_inclusive = str(start_excluding), False
    elif start_including not in {None, "0"}:
        start, start_inclusive = str(start_including), True
    elif introduced not in {None, "", "0"}:
        start, start_inclusive = str(introduced), True
    else:
        start, start_inclusive = None, False

    end_excluding = item.get("version_end_excluding")
    end_including = item.get("version_end_including")
    fixed = item.get("fixed")
    if end_excluding is not None:
        end, end_inclusive = str(end_excluding), False
    elif end_including is not None:
        end, end_inclusive = str(end_including), True
    elif fixed is not None:
        end, end_inclusive = str(fixed), False
    else:
        end, end_inclusive = None, False
    return ("range", start, start_inclusive, end, end_inclusive)


def cpe_update_qualifier(item: dict) -> str | None:
    criteria = item.get("criteria")
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) <= 6:
        return None
    update = parts[6]
    return update if update not in {"", "*", "-"} else None


def row_tokens(items: list[dict]) -> list[str]:
    tokens: list[str] = []
    for item in items:
        for key in (
            "version", "introduced", "fixed", "version_start_including",
            "version_start_excluding", "version_end_including", "version_end_excluding",
        ):
            value = item.get(key)
            if isinstance(value, str):
                tokens.append(value)
        qualifier = cpe_update_qualifier(item)
        if qualifier:
            tokens.append(qualifier)
    return tokens


def project_family(row: dict) -> str:
    nvd_vendors = {str(item.get("vendor") or "") for item in row["nvd_value"]}
    nvd_subjects = {item_subject(item) for item in row["nvd_value"]}
    ghsa_subjects = {item_subject(item) for item in row["ghsa_value"]}
    if nvd_vendors == {"adobe"} and ghsa_subjects and all(
        subject.startswith("magento/") for subject in ghsa_subjects
    ):
        return "adobe_magento"
    if nvd_vendors == {"mattermost"} and ghsa_subjects and all(
        subject.startswith("github.com/mattermost/") for subject in ghsa_subjects
    ):
        return "mattermost"
    if nvd_vendors == {"linuxfoundation"} and ghsa_subjects == {"github.com/lf-edge/eve"}:
        return "lf_edge_eve"
    if "hutool" in nvd_subjects and ghsa_subjects and all(
        subject.startswith("cn.hutool:") for subject in ghsa_subjects
    ):
        return "hutool"
    vendor_key = "+".join(sorted(nvd_vendors)) or "unknown"
    subject_key = "+".join(sorted(nvd_subjects)) or "unknown"
    return f"single_case:{vendor_key}:{subject_key}"


def prior_bound_pairs(prior_graph: dict) -> set[tuple[str, str]]:
    pairs = set()
    for case in prior_graph.get("cases", []):
        edge = case.get("identity_edge") or {}
        gate = case.get("gate") or {}
        if edge.get("bound") is True and gate.get("passed") is True:
            pairs.add((str(edge.get("from")), str(edge.get("to"))))
    return pairs


def analyze_row(row: dict, bound_pairs: set[tuple[str, str]]) -> dict:
    nvd_subjects = sorted({item_subject(item) for item in row["nvd_value"]})
    ghsa_subjects = sorted({item_subject(item) for item in row["ghsa_value"]})
    ecosystems = sorted({str(item.get("ecosystem")) for item in row["ghsa_value"]})
    nvd_spans = Counter(span_signature(item) for item in row["nvd_value"])
    ghsa_spans = Counter(span_signature(item) for item in row["ghsa_value"])
    shared_spans = nvd_spans & ghsa_spans
    all_items = [*row["nvd_value"], *row["ghsa_value"]]
    all_tokens = row_tokens(all_items)
    exact_overlap = sorted(set(nvd_subjects) & set(ghsa_subjects))
    leaf_overlap = sorted(
        {identifier_leaf(value) for value in nvd_subjects}
        & {identifier_leaf(value) for value in ghsa_subjects}
    )
    subjects_per_side = {
        "nvd": len(nvd_subjects),
        "ghsa": len(ghsa_subjects),
    }
    per_subject_span_counts: dict[str, int] = Counter(
        item_subject(item) for item in all_items
    )
    open_lower = any(span_signature(item)[0] == "range" and span_signature(item)[1] is None for item in all_items)
    open_upper = any(span_signature(item)[0] == "range" and span_signature(item)[3] is None for item in all_items)
    cpe_qualifiers = sorted(
        {qualifier for item in row["nvd_value"] if (qualifier := cpe_update_qualifier(item))}
    )
    prior_pairs = sorted(
        [list(pair) for pair in bound_pairs if pair[0] in nvd_subjects and pair[1] in ghsa_subjects]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "project_family": project_family(row),
        "source_structure": {
            "nvd_vendors": sorted({str(item.get("vendor") or "") for item in row["nvd_value"]}),
            "nvd_subjects": nvd_subjects,
            "ghsa_ecosystems": ecosystems,
            "ghsa_subjects": ghsa_subjects,
            "nvd_item_count": len(row["nvd_value"]),
            "ghsa_item_count": len(row["ghsa_value"]),
        },
        "features": {
            "exact_identifier_overlap": exact_overlap,
            "leaf_identifier_overlap": leaf_overlap,
            "product_to_package_mapping_required": not bool(exact_overlap),
            "multi_subject_union_required": max(subjects_per_side.values()) > 1,
            "mixed_ghsa_ecosystem": len(ecosystems) > 1,
            "open_lower_bound": open_lower,
            "open_upper_bound": open_upper,
            "singleton_count": sum(singleton_value(item) is not None for item in all_items),
            "cpe_update_qualifiers": cpe_qualifiers,
            "prerelease_or_patch_variant": bool(cpe_qualifiers) or any(QUALIFIED_VERSION.search(token) for token in all_tokens),
            "go_pseudo_version": any(PSEUDO_VERSION.search(token) for token in all_tokens),
            "multiple_intervals_same_subject": any(count > 1 for count in per_subject_span_counts.values()),
            "same_range_multiset_ignoring_subject": nvd_spans == ghsa_spans,
            "shared_range_signature_count": sum(shared_spans.values()),
            "prior_official_edge_bound": bool(prior_pairs),
            "prior_official_edge_pairs": prior_pairs,
        },
        "range_signatures": {
            "nvd": [list(span) for span in sorted(nvd_spans.elements(), key=str)],
            "ghsa": [list(span) for span in sorted(ghsa_spans.elements(), key=str)],
        },
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def family_score(rows: list[dict]) -> tuple[int, list[dict]]:
    ecosystems = {ecosystem for row in rows for ecosystem in row["source_structure"]["ghsa_ecosystems"]}
    max_nvd = max(len(row["source_structure"]["nvd_subjects"]) for row in rows)
    max_ghsa = max(len(row["source_structure"]["ghsa_subjects"]) for row in rows)
    prior_edge = any(row["features"]["prior_official_edge_bound"] for row in rows)
    all_share_range = all(row["features"]["shared_range_signature_count"] > 0 for row in rows)
    has_pseudo = any(row["features"]["go_pseudo_version"] for row in rows)
    has_open_upper = any(row["features"]["open_upper_bound"] for row in rows)
    has_union = any(row["features"]["multi_subject_union_required"] for row in rows)
    components = [
        {"signal": "at_least_two_rows", "value": len(rows) >= 2, "points": 4 if len(rows) >= 2 else 0},
        {"signal": "one_ghsa_ecosystem", "value": len(ecosystems) == 1, "points": 3 if len(ecosystems) == 1 else 0},
        {"signal": "at_most_one_nvd_subject", "value": max_nvd <= 1, "points": 3 if max_nvd <= 1 else 0},
        {"signal": "at_most_two_ghsa_subjects", "value": max_ghsa <= 2, "points": 2 if max_ghsa <= 2 else 0},
        {"signal": "prior_official_edge_bound", "value": prior_edge, "points": 4 if prior_edge else 0},
        {"signal": "every_row_shares_stable_range", "value": all_share_range, "points": 2 if all_share_range else 0},
        {"signal": "go_pseudo_version", "value": has_pseudo, "points": -3 if has_pseudo else 0},
        {"signal": "open_upper_bound", "value": has_open_upper, "points": -3 if has_open_upper else 0},
        {"signal": "multi_subject_union", "value": has_union, "points": -1 if has_union else 0},
    ]
    return sum(item["points"] for item in components), components


def build_family_ranking(rows: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["project_family"]].append(row)
    families = []
    for family, family_rows in grouped.items():
        ecosystems = sorted({e for row in family_rows for e in row["source_structure"]["ghsa_ecosystems"]})
        max_nvd = max(len(row["source_structure"]["nvd_subjects"]) for row in family_rows)
        max_ghsa = max(len(row["source_structure"]["ghsa_subjects"]) for row in family_rows)
        max_singletons = max(row["features"]["singleton_count"] for row in family_rows)
        has_cpe_qualifier = any(row["features"]["cpe_update_qualifiers"] for row in family_rows)
        eligibility_checks = {
            "at_least_two_rows": len(family_rows) >= 2,
            "one_ghsa_ecosystem": len(ecosystems) == 1,
            "at_most_one_nvd_subject_per_row": max_nvd <= 1,
            "at_most_two_ghsa_subjects_per_row": max_ghsa <= 2,
            "at_most_four_singletons_per_row": max_singletons <= 4,
            "no_cpe_update_qualifier": not has_cpe_qualifier,
        }
        score, score_components = family_score(family_rows)
        families.append({
            "project_family": family,
            "sample_ids": sorted(row["sample_id"] for row in family_rows),
            "cve_ids": sorted(row["cve_id"] for row in family_rows),
            "row_count": len(family_rows),
            "ghsa_ecosystems": ecosystems,
            "shared_range_rows": sum(row["features"]["shared_range_signature_count"] > 0 for row in family_rows),
            "prior_official_edge_available": any(row["features"]["prior_official_edge_bound"] for row in family_rows),
            "eligibility_checks": eligibility_checks,
            "eligible": all(eligibility_checks.values()),
            "score": score,
            "score_components": score_components,
        })
    families.sort(
        key=lambda item: (
            not item["eligible"],
            -item["score"],
            not item["prior_official_edge_available"],
            -item["shared_range_rows"],
            -item["row_count"],
            item["project_family"],
        )
    )
    for rank, family in enumerate((item for item in families if item["eligible"]), start=1):
        family["eligible_rank"] = rank
    return families


def attach_diagnostics(rows: list[dict], consensus_rows: list[dict]) -> list[dict]:
    by_id = {row["sample_id"]: row for row in consensus_rows}
    diagnostics = []
    for row in rows:
        source = by_id.get(row["sample_id"])
        if source is None:
            raise ValueError(f"missing D/E diagnostic for {row['sample_id']}")
        diagnostics.append({
            "sample_id": row["sample_id"],
            "cve_id": row["cve_id"],
            "reviewer_d_label": source["reviewer_d"]["discrepancy_label"],
            "reviewer_e_label": source["reviewer_e"]["discrepancy_label"],
            "exact_label_agreement": source["exact_label_agreement"],
            "secondary_strict_consensus": source["secondary_strict_consensus"],
            "used_for_selection": False,
            "label_is_human": False,
        })
    return diagnostics


def render_markdown(analysis: dict) -> str:
    selected = analysis["selection"]["selected_family"]
    lines = [
        "# Unresolved Affected-Versions Edge-Class Audit v1",
        "",
        "> Post-unsealing, non-human structural work-allocation audit; not an accuracy result.",
        "",
        f"- Rows: `{analysis['row_count']}`",
        f"- Project families: `{analysis['family_count']}`",
        f"- Eligible repeated families: `{analysis['selection']['eligible_family_count']}`",
        f"- Selected next family: `{selected}`",
        "- Reviewer labels used for selection: `false`",
        "",
        "| Rank | Family | Rows | Score | Prior edge | Shared-range rows |",
        "|---:|---|---:|---:|---|---:|",
    ]
    for family in analysis["family_ranking"]:
        if not family["eligible"]:
            continue
        lines.append(
            f"| {family['eligible_rank']} | {family['project_family']} | {family['row_count']} | "
            f"{family['score']} | {str(family['prior_official_edge_available']).lower()} | "
            f"{family['shared_range_rows']} |"
        )
    lines.extend([
        "",
        "The D/E labels are retained only in `reviewer_diagnostics` after the ranking is fixed.",
        "Selection advances a project-specific evidence contract; it does not resolve any row.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    worklist_path = resolve(args.worklist)
    manifest_path = resolve(args.sealed_manifest)
    prior_graph_path = resolve(args.prior_graph)
    consensus_path = resolve(args.consensus)
    contract_path = resolve(args.contract)
    output_dir = resolve(args.output_dir)

    sealed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hash = sealed_manifest["outputs"]["blind_worklist_d"]["sha256"]
    if file_sha256(worklist_path) != expected_hash:
        raise ValueError("sealed blind worklist hash mismatch")
    worklist = [row for row in load_jsonl(worklist_path) if row.get("field") == "affected_versions"]
    if len(worklist) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} affected-version rows, found {len(worklist)}")
    if len({row["sample_id"] for row in worklist}) != EXPECTED_ROWS:
        raise ValueError("affected-version sample IDs are not unique")

    prior_graph = json.loads(prior_graph_path.read_text(encoding="utf-8"))
    structural_rows = [analyze_row(row, prior_bound_pairs(prior_graph)) for row in worklist]
    family_ranking = build_family_ranking(structural_rows)
    eligible = [family for family in family_ranking if family["eligible"]]
    if not eligible:
        raise ValueError("no repeated family passed the fixed structural eligibility gate")
    selected_family = eligible[0]["project_family"]

    # Reviewer outputs are deliberately loaded only after structural selection.
    reviewer_diagnostics = attach_diagnostics(structural_rows, load_jsonl(consensus_path))
    analysis = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "unresolved_affected_edge_class_audit",
        "row_count": len(structural_rows),
        "family_count": len(family_ranking),
        "rows": structural_rows,
        "family_ranking": family_ranking,
        "selection": {
            "eligible_family_count": len(eligible),
            "selected_family": selected_family,
            "selected_sample_ids": eligible[0]["sample_ids"],
            "selection_uses_reviewer_labels": False,
            "selection_completed_before_reviewer_diagnostics": True,
        },
        "reviewer_diagnostics": reviewer_diagnostics,
        "boundary": {
            "post_unsealing": True,
            "development_diagnostic_only": True,
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "accuracy_claim_allowed": False,
            "production_switch_allowed": False,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path = output_dir / "analysis.json"
    rows_path = output_dir / "rows.jsonl"
    summary_path = output_dir / "summary.md"
    write_json(analysis_path, analysis)
    write_jsonl(rows_path, structural_rows)
    summary_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "inputs": {
            "worklist": {"path": str(worklist_path), "sha256": file_sha256(worklist_path)},
            "sealed_manifest": {"path": str(manifest_path), "sha256": file_sha256(manifest_path)},
            "prior_graph": {"path": str(prior_graph_path), "sha256": file_sha256(prior_graph_path)},
            "consensus_diagnostic_only": {"path": str(consensus_path), "sha256": file_sha256(consensus_path)},
            "contract": {"path": str(contract_path), "sha256": file_sha256(contract_path)},
        },
        "outputs": {
            path.name: {"path": str(path), "sha256": file_sha256(path)}
            for path in (analysis_path, rows_path, summary_path)
        },
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }
    write_json(output_dir / "manifest.json", manifest)
    print(json.dumps({
        "rows": len(structural_rows),
        "eligible_families": [family["project_family"] for family in eligible],
        "selected_family": selected_family,
        "output_dir": str(output_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
