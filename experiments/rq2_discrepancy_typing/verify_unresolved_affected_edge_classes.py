#!/usr/bin/env python3
"""Independently verify the unresolved affected-version edge-class audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "unresolved_affected_edge_class_audit_v1"
DEFAULT_MANIFEST = (
    "results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/"
    "affected_versions_edge_class_audit_v1/manifest.json"
)
PSEUDO = re.compile(r"(?:^|[^0-9])\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}(?:$|[^0-9a-f])")
QUALIFIED = re.compile(r"(?:^|[-.])(alpha|beta|rc|pre|preview|p)\d*", re.I)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_record(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or file_sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def subject(item: dict) -> str:
    return str(item.get("package_name") or item.get("product") or "")


def singleton(item: dict) -> str | None:
    value = item.get("version")
    return value if isinstance(value, str) and value not in {"", "*", "-"} else None


def span(item: dict) -> tuple:
    value = singleton(item)
    if value is not None:
        return ("singleton", value, True, value, True)
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
    if item.get("version_end_excluding") is not None:
        end, end_inclusive = str(item["version_end_excluding"]), False
    elif item.get("version_end_including") is not None:
        end, end_inclusive = str(item["version_end_including"]), True
    elif item.get("fixed") is not None:
        end, end_inclusive = str(item["fixed"]), False
    else:
        end, end_inclusive = None, False
    return ("range", start, start_inclusive, end, end_inclusive)


def cpe_qualifier(item: dict) -> str | None:
    criteria = item.get("criteria")
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) <= 6 or parts[6] in {"", "*", "-"}:
        return None
    return parts[6]


def leaf(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", re.split(r"[/ :]", value)[-1].lower())


def family(row: dict) -> str:
    vendors = {str(item.get("vendor") or "") for item in row["nvd_value"]}
    nvd = {subject(item) for item in row["nvd_value"]}
    ghsa = {subject(item) for item in row["ghsa_value"]}
    if vendors == {"adobe"} and ghsa and all(value.startswith("magento/") for value in ghsa):
        return "adobe_magento"
    if vendors == {"mattermost"} and ghsa and all(value.startswith("github.com/mattermost/") for value in ghsa):
        return "mattermost"
    if vendors == {"linuxfoundation"} and ghsa == {"github.com/lf-edge/eve"}:
        return "lf_edge_eve"
    if "hutool" in nvd and ghsa and all(value.startswith("cn.hutool:") for value in ghsa):
        return "hutool"
    return f"single_case:{'+'.join(sorted(vendors)) or 'unknown'}:{'+'.join(sorted(nvd)) or 'unknown'}"


def prior_pairs(graph: dict) -> set[tuple[str, str]]:
    result = set()
    for case in graph.get("cases", []):
        edge = case.get("identity_edge") or {}
        if edge.get("bound") is True and (case.get("gate") or {}).get("passed") is True:
            result.add((str(edge.get("from")), str(edge.get("to"))))
    return result


def reconstruct_row(row: dict, bound_pairs: set[tuple[str, str]]) -> dict:
    nvd_subjects = sorted({subject(item) for item in row["nvd_value"]})
    ghsa_subjects = sorted({subject(item) for item in row["ghsa_value"]})
    ecosystems = sorted({str(item.get("ecosystem")) for item in row["ghsa_value"]})
    nvd_spans = Counter(span(item) for item in row["nvd_value"])
    ghsa_spans = Counter(span(item) for item in row["ghsa_value"])
    all_items = [*row["nvd_value"], *row["ghsa_value"]]
    tokens = [
        str(item[key])
        for item in all_items
        for key in (
            "version", "introduced", "fixed", "version_start_including",
            "version_start_excluding", "version_end_including", "version_end_excluding",
        )
        if isinstance(item.get(key), str)
    ]
    qualifiers = sorted({value for item in row["nvd_value"] if (value := cpe_qualifier(item))})
    tokens.extend(qualifiers)
    per_subject = Counter(subject(item) for item in all_items)
    exact = sorted(set(nvd_subjects) & set(ghsa_subjects))
    shared = nvd_spans & ghsa_spans
    matching_pairs = sorted(
        [list(pair) for pair in bound_pairs if pair[0] in nvd_subjects and pair[1] in ghsa_subjects]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "field": row["field"],
        "project_family": family(row),
        "source_structure": {
            "nvd_vendors": sorted({str(item.get("vendor") or "") for item in row["nvd_value"]}),
            "nvd_subjects": nvd_subjects,
            "ghsa_ecosystems": ecosystems,
            "ghsa_subjects": ghsa_subjects,
            "nvd_item_count": len(row["nvd_value"]),
            "ghsa_item_count": len(row["ghsa_value"]),
        },
        "features": {
            "exact_identifier_overlap": exact,
            "leaf_identifier_overlap": sorted({leaf(v) for v in nvd_subjects} & {leaf(v) for v in ghsa_subjects}),
            "product_to_package_mapping_required": not bool(exact),
            "multi_subject_union_required": max(len(nvd_subjects), len(ghsa_subjects)) > 1,
            "mixed_ghsa_ecosystem": len(ecosystems) > 1,
            "open_lower_bound": any(span(item)[0] == "range" and span(item)[1] is None for item in all_items),
            "open_upper_bound": any(span(item)[0] == "range" and span(item)[3] is None for item in all_items),
            "singleton_count": sum(singleton(item) is not None for item in all_items),
            "cpe_update_qualifiers": qualifiers,
            "prerelease_or_patch_variant": bool(qualifiers) or any(QUALIFIED.search(token) for token in tokens),
            "go_pseudo_version": any(PSEUDO.search(token) for token in tokens),
            "multiple_intervals_same_subject": any(count > 1 for count in per_subject.values()),
            "same_range_multiset_ignoring_subject": nvd_spans == ghsa_spans,
            "shared_range_signature_count": sum(shared.values()),
            "prior_official_edge_bound": bool(matching_pairs),
            "prior_official_edge_pairs": matching_pairs,
        },
        "range_signatures": {
            "nvd": [list(value) for value in sorted(nvd_spans.elements(), key=str)],
            "ghsa": [list(value) for value in sorted(ghsa_spans.elements(), key=str)],
        },
        "selection_uses_reviewer_labels": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
    }


def score(rows: list[dict]) -> tuple[int, list[dict]]:
    ecosystems = {value for row in rows for value in row["source_structure"]["ghsa_ecosystems"]}
    max_nvd = max(len(row["source_structure"]["nvd_subjects"]) for row in rows)
    max_ghsa = max(len(row["source_structure"]["ghsa_subjects"]) for row in rows)
    signals = [
        ("at_least_two_rows", len(rows) >= 2, 4),
        ("one_ghsa_ecosystem", len(ecosystems) == 1, 3),
        ("at_most_one_nvd_subject", max_nvd <= 1, 3),
        ("at_most_two_ghsa_subjects", max_ghsa <= 2, 2),
        ("prior_official_edge_bound", any(row["features"]["prior_official_edge_bound"] for row in rows), 4),
        ("every_row_shares_stable_range", all(row["features"]["shared_range_signature_count"] > 0 for row in rows), 2),
        ("go_pseudo_version", any(row["features"]["go_pseudo_version"] for row in rows), -3),
        ("open_upper_bound", any(row["features"]["open_upper_bound"] for row in rows), -3),
        ("multi_subject_union", any(row["features"]["multi_subject_union_required"] for row in rows), -1),
    ]
    components = [
        {"signal": name, "value": value, "points": points if value else 0}
        for name, value, points in signals
    ]
    return sum(item["points"] for item in components), components


def reconstruct_ranking(rows: list[dict]) -> list[dict]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["project_family"]].append(row)
    result = []
    for name, values in grouped.items():
        ecosystems = sorted({value for row in values for value in row["source_structure"]["ghsa_ecosystems"]})
        checks = {
            "at_least_two_rows": len(values) >= 2,
            "one_ghsa_ecosystem": len(ecosystems) == 1,
            "at_most_one_nvd_subject_per_row": max(len(row["source_structure"]["nvd_subjects"]) for row in values) <= 1,
            "at_most_two_ghsa_subjects_per_row": max(len(row["source_structure"]["ghsa_subjects"]) for row in values) <= 2,
            "at_most_four_singletons_per_row": max(row["features"]["singleton_count"] for row in values) <= 4,
            "no_cpe_update_qualifier": not any(row["features"]["cpe_update_qualifiers"] for row in values),
        }
        family_score, components = score(values)
        result.append({
            "project_family": name,
            "sample_ids": sorted(row["sample_id"] for row in values),
            "cve_ids": sorted(row["cve_id"] for row in values),
            "row_count": len(values),
            "ghsa_ecosystems": ecosystems,
            "shared_range_rows": sum(row["features"]["shared_range_signature_count"] > 0 for row in values),
            "prior_official_edge_available": any(row["features"]["prior_official_edge_bound"] for row in values),
            "eligibility_checks": checks,
            "eligible": all(checks.values()),
            "score": family_score,
            "score_components": components,
        })
    result.sort(key=lambda item: (
        not item["eligible"], -item["score"], not item["prior_official_edge_available"],
        -item["shared_range_rows"], -item["row_count"], item["project_family"],
    ))
    for rank, item in enumerate((value for value in result if value["eligible"]), start=1):
        item["eligible_rank"] = rank
    return result


def validate(manifest: dict) -> dict:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unexpected edge-audit schema")
    inputs = {
        name: verified_record(record, f"input:{name}")
        for name, record in manifest["inputs"].items()
    }
    outputs = {
        name: verified_record(record, f"output:{name}")
        for name, record in manifest["outputs"].items()
    }
    sealed = json.loads(inputs["sealed_manifest"].read_text(encoding="utf-8"))
    if sealed["outputs"]["blind_worklist_d"]["sha256"] != file_sha256(inputs["worklist"]):
        raise ValueError("sealed worklist hash mismatch")
    worklist = [row for row in load_jsonl(inputs["worklist"]) if row.get("field") == "affected_versions"]
    if len(worklist) != 28 or len({row["sample_id"] for row in worklist}) != 28:
        raise ValueError("affected-version row inventory drift")
    graph = json.loads(inputs["prior_graph"].read_text(encoding="utf-8"))
    rows = [reconstruct_row(row, prior_pairs(graph)) for row in worklist]
    ranking = reconstruct_ranking(rows)
    eligible = [item for item in ranking if item["eligible"]]
    consensus = {row["sample_id"]: row for row in load_jsonl(inputs["consensus_diagnostic_only"])}
    diagnostics = [{
        "sample_id": row["sample_id"],
        "cve_id": row["cve_id"],
        "reviewer_d_label": consensus[row["sample_id"]]["reviewer_d"]["discrepancy_label"],
        "reviewer_e_label": consensus[row["sample_id"]]["reviewer_e"]["discrepancy_label"],
        "exact_label_agreement": consensus[row["sample_id"]]["exact_label_agreement"],
        "secondary_strict_consensus": consensus[row["sample_id"]]["secondary_strict_consensus"],
        "used_for_selection": False,
        "label_is_human": False,
    } for row in rows]
    observed = json.loads(outputs["analysis.json"].read_text(encoding="utf-8"))
    if observed.get("rows") != rows:
        raise ValueError("row features differ from independent reconstruction")
    if observed.get("family_ranking") != ranking:
        raise ValueError("family ranking differs from independent reconstruction")
    expected_selection = {
        "eligible_family_count": len(eligible),
        "selected_family": eligible[0]["project_family"],
        "selected_sample_ids": eligible[0]["sample_ids"],
        "selection_uses_reviewer_labels": False,
        "selection_completed_before_reviewer_diagnostics": True,
    }
    if observed.get("selection") != expected_selection:
        raise ValueError("selected family differs from independent reconstruction")
    if observed.get("reviewer_diagnostics") != diagnostics:
        raise ValueError("reviewer diagnostics differ from sealed D/E result")
    if observed.get("row_count") != 28 or observed.get("family_count") != len(ranking):
        raise ValueError("edge-audit counts differ from reconstruction")
    boundary = observed.get("boundary") or {}
    if boundary.get("label_is_human") is not False or boundary.get("eligible_for_human_gold_claim") is not False:
        raise ValueError("non-human boundary drift")
    return observed


def main() -> int:
    args = parse_args()
    analysis = validate(json.loads(resolve(args.manifest).read_text(encoding="utf-8")))
    print(
        "Verified unresolved affected-version edge audit: "
        f"{analysis['row_count']} rows; selected={analysis['selection']['selected_family']}; "
        "selection_uses_reviewer_labels=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
