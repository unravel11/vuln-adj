#!/usr/bin/env python3
"""Evaluate a conservative CWE ancestor/descendant discrepancy variant."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, deque
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CWE_ZIP = "data/external/cwe/cwec_v4.20.xml.zip"
DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_ALIGNED = "data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl"
DEFAULT_PRIMARY_SOURCE = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_REVIEW_SOURCE = (
    "data/annotations/rq2/consistency_review/"
    "discrepancy_typing_consistency_review.jsonl"
)
DEFAULT_PRIMARY_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_primary.jsonl"
DEFAULT_REVIEW_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_review.jsonl"
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing/cwe_taxonomy"
CWE_SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TAXONOMY_VIEW_ID = "1000"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwe-xml-zip", default=DEFAULT_CWE_ZIP)
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
    parser.add_argument("--aligned", default=DEFAULT_ALIGNED)
    parser.add_argument("--primary-source", default=DEFAULT_PRIMARY_SOURCE)
    parser.add_argument("--review-source", default=DEFAULT_REVIEW_SOURCE)
    parser.add_argument("--primary-candidate", default=DEFAULT_PRIMARY_CANDIDATE)
    parser.add_argument("--review-candidate", default=DEFAULT_REVIEW_CANDIDATE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {error}") from error


def load_unique(path: Path, key: str) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row[key]
        if value in rows:
            raise ValueError(f"Duplicate {key} in {path}: {value}")
        rows[value] = row
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strip_cwe(value: str) -> str:
    text = str(value).strip().upper()
    return text[4:] if text.startswith("CWE-") else text


def cwe_id(value: str) -> str:
    return f"CWE-{strip_cwe(value)}"


def element_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    return " ".join(" ".join(element.itertext()).split())


class CweCatalog:
    def __init__(self, zip_path: Path):
        with ZipFile(zip_path) as archive:
            names = archive.namelist()
            if len(names) != 1 or not names[0].endswith(".xml"):
                raise ValueError(f"Unexpected CWE archive members: {names}")
            root = ET.fromstring(archive.read(names[0]))
        self.version = root.attrib.get("Version")
        self.date = root.attrib.get("Date")
        namespace = root.tag.split("}")[0] + "}"
        self.entries: dict[str, dict] = {}
        self.parents: dict[str, set[str]] = {}
        weaknesses = root.find(namespace + "Weaknesses")
        if weaknesses is None:
            raise ValueError("CWE XML has no Weaknesses element")
        for weakness in weaknesses:
            identifier = weakness.attrib["ID"]
            self.entries[identifier] = {
                "cwe_id": f"CWE-{identifier}",
                "name": weakness.attrib.get("Name"),
                "abstraction": weakness.attrib.get("Abstraction"),
                "status": weakness.attrib.get("Status"),
                "description": element_text(weakness.find(namespace + "Description")),
            }
            parents = set()
            related = weakness.find(namespace + "Related_Weaknesses")
            if related is not None:
                for relation in related:
                    if (
                        relation.attrib.get("Nature") == "ChildOf"
                        and relation.attrib.get("View_ID") == TAXONOMY_VIEW_ID
                    ):
                        parents.add(relation.attrib["CWE_ID"])
            self.parents[identifier] = parents
        if not self.version or not self.entries:
            raise ValueError("CWE XML metadata is incomplete")

    def ancestor_path(self, child: str, ancestor: str) -> list[str] | None:
        child = strip_cwe(child)
        ancestor = strip_cwe(ancestor)
        queue = deque([(child, [child])])
        seen = set()
        while queue:
            current, path = queue.popleft()
            if current == ancestor:
                return path
            if current in seen:
                continue
            seen.add(current)
            for parent in sorted(self.parents.get(current, ())):
                queue.append((parent, [*path, parent]))
        return None

    def comparable_path(self, left: str, right: str) -> list[str] | None:
        path = self.ancestor_path(left, right)
        if path:
            return path
        reverse = self.ancestor_path(right, left)
        return list(reversed(reverse)) if reverse else None

    def describe_path(self, path: list[str]) -> list[dict]:
        return [self.entries.get(identifier, {"cwe_id": f"CWE-{identifier}"}) for identifier in path]


def relation_profile(nvd_values: list[str], ghsa_values: list[str], catalog: CweCatalog) -> dict:
    nvd = sorted({cwe_id(value) for value in nvd_values})
    ghsa = sorted({cwe_id(value) for value in ghsa_values})
    nvd_set = set(nvd)
    ghsa_set = set(ghsa)
    shared = sorted(nvd_set & ghsa_set)
    paths = []
    covered_nvd = set()
    covered_ghsa = set()
    for left in nvd:
        for right in ghsa:
            if left == right:
                continue
            path = catalog.comparable_path(left, right)
            if not path:
                continue
            covered_nvd.add(left)
            covered_ghsa.add(right)
            paths.append(
                {
                    "nvd_cwe": left,
                    "ghsa_cwe": right,
                    "path": catalog.describe_path(path),
                }
            )

    if nvd_set == ghsa_set:
        category = "exact_set"
    elif nvd_set.issubset(ghsa_set) or ghsa_set.issubset(nvd_set):
        category = "literal_strict_subset"
    elif shared:
        nonshared_nvd = nvd_set - ghsa_set
        nonshared_ghsa = ghsa_set - nvd_set
        if nonshared_nvd <= covered_nvd and nonshared_ghsa <= covered_ghsa:
            category = "overlap_full_taxonomy_coverage"
        elif paths:
            category = "overlap_partial_taxonomy_coverage"
        else:
            category = "overlap_no_taxonomy_relation"
    elif covered_nvd == nvd_set and covered_ghsa == ghsa_set and paths:
        category = "disjoint_full_taxonomy_coverage"
    elif paths:
        category = "disjoint_partial_taxonomy_coverage"
    else:
        category = "disjoint_no_taxonomy_relation"
    return {
        "category": category,
        "nvd_values": nvd,
        "ghsa_values": ghsa,
        "shared_values": shared,
        "covered_nvd": sorted(covered_nvd),
        "covered_ghsa": sorted(covered_ghsa),
        "ancestor_descendant_paths": paths,
    }


def taxonomy_v1_status(current_status: str, profile: dict) -> str:
    if (
        current_status == "factual_conflict"
        and profile["category"] == "disjoint_full_taxonomy_coverage"
    ):
        return "representation_discrepancy"
    return current_status


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def classification_metrics(records: list[dict], prediction_key: str) -> dict:
    determinate = [row for row in records if row["candidate_label"] != "uncertain"]
    candidate_counts = Counter(row["candidate_label"] for row in determinate)
    prediction_counts = Counter(row[prediction_key] for row in determinate)
    supported_f1 = []
    per_label = {}
    for label in LABELS:
        tp = sum(
            row["candidate_label"] == label and row[prediction_key] == label
            for row in determinate
        )
        fp = sum(
            row["candidate_label"] != label and row[prediction_key] == label
            for row in determinate
        )
        fn = sum(
            row["candidate_label"] == label and row[prediction_key] != label
            for row in determinate
        )
        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall)
        per_label[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": candidate_counts[label],
            "predicted": prediction_counts[label],
        }
        if candidate_counts[label]:
            supported_f1.append(f1)
    agreement_count = sum(
        row["candidate_label"] == row[prediction_key] for row in determinate
    )
    return {
        "total_candidate_rows": len(records),
        "determinate_rows": len(determinate),
        "agreement_count": agreement_count,
        "agreement": safe_divide(agreement_count, len(determinate)),
        "macro_f1_over_supported_candidate_labels": safe_divide(
            sum(supported_f1), len(supported_f1)
        ),
        "candidate_label_counts": dict(sorted(candidate_counts.items())),
        "predicted_label_counts": dict(sorted(prediction_counts.items())),
        "per_label": per_label,
    }


def candidate_records(
    source_rows: dict[str, dict],
    candidate_rows: dict[str, dict],
    variant_by_cve: dict[str, str],
) -> list[dict]:
    records = []
    for sample_id, candidate in candidate_rows.items():
        source = source_rows[sample_id]
        if source["field"] != "cwe_ids":
            continue
        records.append(
            {
                "sample_id": sample_id,
                "cve_id": source["cve_id"],
                "candidate_label": candidate["annotation"]["discrepancy_label"],
                "current_status": source["baseline_status"],
                "taxonomy_v1_status": variant_by_cve[source["cve_id"]],
            }
        )
    return records


def aligned_context(row: dict) -> dict:
    nvd = row.get("nvd") or {}
    ghsa_rows = row.get("ghsa") or []
    ghsa = ghsa_rows[0] if ghsa_rows else {}
    return {
        "nvd_summary": nvd.get("summary"),
        "ghsa_summary": ghsa.get("summary"),
        "nvd_package_names": sorted(
            {
                str(item.get("package_name") or item.get("product"))
                for item in nvd.get("affected") or []
                if item.get("package_name") or item.get("product")
            }
        ),
        "ghsa_package_names": sorted(
            {
                str(item.get("package_name") or item.get("product"))
                for item in ghsa.get("affected") or []
                if item.get("package_name") or item.get("product")
            }
        ),
    }


def build_blind_worklist(
    primary_source: dict[str, dict],
    review_source: dict[str, dict],
    primary_candidate: dict[str, dict],
    review_candidate: dict[str, dict],
    aligned: dict[str, dict],
    catalog: CweCatalog,
) -> list[dict]:
    selected = set()
    for sample_id, candidate in primary_candidate.items():
        source = primary_source[sample_id]
        if source["field"] != "cwe_ids":
            continue
        if candidate["annotation"]["discrepancy_label"] != source["baseline_status"]:
            selected.add(sample_id)
    for review_id, candidate in review_candidate.items():
        source = review_source[review_id]
        if source["field"] != "cwe_ids":
            continue
        original_id = candidate["original_sample_id"]
        if (
            candidate["annotation"]["discrepancy_label"]
            != primary_candidate[original_id]["annotation"]["discrepancy_label"]
        ):
            selected.add(original_id)
    if len(selected) != 15:
        raise ValueError(f"Expected 15 targeted CWE rows, found {len(selected)}")

    worklist = []
    for index, sample_id in enumerate(sorted(selected), start=1):
        source = primary_source[sample_id]
        profile = relation_profile(source["nvd_value"], source["ghsa_value"], catalog)
        identifiers = sorted(
            {strip_cwe(value) for value in [*source["nvd_value"], *source["ghsa_value"]]},
            key=lambda value: int(value),
        )
        row = {
            "review_id": f"rq2_cwe_taxonomy_dual_review:{index:03d}",
            "sample_id": sample_id,
            "cve_id": source["cve_id"],
            "field": "cwe_ids",
            "selection_reason": "candidate_or_repeatability_disagreement",
            "nvd_value": source["nvd_value"],
            "ghsa_value": source["ghsa_value"],
            "vulnerability_context": aligned_context(aligned[source["cve_id"]]),
            "official_cwe_entries": [catalog.entries[value] for value in identifiers],
            "official_cross_source_ancestor_descendant_paths": profile[
                "ancestor_descendant_paths"
            ],
            "taxonomy_source": {
                "catalog_version": catalog.version,
                "catalog_date": catalog.date,
                "view_id": TAXONOMY_VIEW_ID,
                "source_url": CWE_SOURCE_URL,
            },
            "review_contract": {
                "set_relation": [
                    "exact_set",
                    "literal_strict_subset",
                    "fully_ancestor_descendant_compatible",
                    "partially_related_mixed",
                    "semantically_distinct",
                    "insufficient_taxonomy_or_context",
                ],
                "discrepancy_label": list(LABELS),
                "taxonomy_support_verdict": [
                    "supports_granularity_only",
                    "does_not_support_granularity_only",
                    "mixed",
                    "insufficient",
                ],
                "confidence": ["high", "medium", "low"],
            },
        }
        forbidden = {
            "baseline_status",
            "candidate_label",
            "primary_label",
            "review_label",
            "taxonomy_v1_status",
        }
        if forbidden & set(row):
            raise ValueError("Blinding contract violation")
        worklist.append(row)
    return worklist


def render_markdown(summary: dict) -> str:
    primary = summary["candidate_diagnostic"]["primary"]
    review = summary["candidate_diagnostic"]["review"]
    lines = [
        "# CWE Taxonomy Variant Diagnostic",
        "",
        "This diagnostic uses the official CWE Research Concepts ancestor graph. AI expert candidates are not human gold.",
        "",
        f"CWE catalog: {summary['cwe_catalog']['version']} ({summary['cwe_catalog']['date']}); full-corpus changed rows: {summary['full_corpus']['changed_rows']}.",
        "",
        "| Candidate set | Method | Determinate | Agreement | Macro-F1 |",
        "| --- | --- | ---: | ---: | ---: |",
        f"| primary | current | {primary['current']['determinate_rows']} | {primary['current']['agreement']:.4f} | {primary['current']['macro_f1_over_supported_candidate_labels']:.4f} |",
        f"| primary | taxonomy_v1 | {primary['taxonomy_v1']['determinate_rows']} | {primary['taxonomy_v1']['agreement']:.4f} | {primary['taxonomy_v1']['macro_f1_over_supported_candidate_labels']:.4f} |",
        f"| same-model review | current | {review['current']['determinate_rows']} | {review['current']['agreement']:.4f} | {review['current']['macro_f1_over_supported_candidate_labels']:.4f} |",
        f"| same-model review | taxonomy_v1 | {review['taxonomy_v1']['determinate_rows']} | {review['taxonomy_v1']['agreement']:.4f} | {review['taxonomy_v1']['macro_f1_over_supported_candidate_labels']:.4f} |",
        "",
        "taxonomy_v1 changes factual_conflict to representation_discrepancy only when every CWE on both disjoint sides participates in an official ancestor/descendant path. It is a candidate-guided diagnostic and does not change the production default.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    cwe_zip = resolve_path(args.cwe_xml_zip)
    field_views_path = resolve_path(args.field_views)
    aligned_path = resolve_path(args.aligned)
    primary_source_path = resolve_path(args.primary_source)
    review_source_path = resolve_path(args.review_source)
    primary_candidate_path = resolve_path(args.primary_candidate)
    review_candidate_path = resolve_path(args.review_candidate)
    output_dir = resolve_path(args.output_dir)

    catalog = CweCatalog(cwe_zip)
    aligned = load_unique(aligned_path, "cve_id")
    primary_source = load_unique(primary_source_path, "sample_id")
    review_source = load_unique(review_source_path, "review_sample_id")
    primary_candidate = load_unique(primary_candidate_path, "sample_id")
    review_candidate = load_unique(review_candidate_path, "sample_id")

    relation_counts = Counter()
    transition_counts = Counter()
    variant_by_cve = {}
    changed_rows = []
    processed = 0
    for row in iter_jsonl(field_views_path):
        processed += 1
        discrepancy = row["field_discrepancies"]["cwe_ids"]
        profile = relation_profile(
            discrepancy.get("nvd_value") or [],
            discrepancy.get("ghsa_value") or [],
            catalog,
        )
        current = discrepancy["status"]
        variant = taxonomy_v1_status(current, profile)
        relation_counts[profile["category"]] += 1
        transition_counts[f"{current}->{variant}"] += 1
        variant_by_cve[row["cve_id"]] = variant
        if current != variant:
            changed_rows.append(
                {
                    "cve_id": row["cve_id"],
                    "current_status": current,
                    "taxonomy_v1_status": variant,
                    "relation_profile": profile,
                    "label_is_human": False,
                    "requires_human_signoff": True,
                }
            )
    if processed != 8066:
        raise ValueError(f"Expected 8066 field-view rows, found {processed}")

    primary_records = candidate_records(
        primary_source, primary_candidate, variant_by_cve
    )
    review_records = candidate_records(review_source, review_candidate, variant_by_cve)
    worklist = build_blind_worklist(
        primary_source,
        review_source,
        primary_candidate,
        review_candidate,
        aligned,
        catalog,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    changed_path = output_dir / "cwe_taxonomy_changed_cases.jsonl"
    with changed_path.open("w", encoding="utf-8") as handle:
        for row in changed_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    worklist_path = output_dir / "cwe_taxonomy_dual_review_worklist.blind.jsonl"
    with worklist_path.open("w", encoding="utf-8") as handle:
        for row in worklist:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary = {
        "artifact_type": "cwe_taxonomy_variant_diagnostic",
        "label_is_human": False,
        "human_gold": False,
        "production_default_changed": False,
        "eligible_for_provisional_candidate_analysis": True,
        "eligible_for_final_paper_claim": False,
        "cwe_catalog": {
            "version": catalog.version,
            "date": catalog.date,
            "view_id": TAXONOMY_VIEW_ID,
            "source_url": CWE_SOURCE_URL,
            "zip_path": str(cwe_zip),
            "zip_sha256": sha256(cwe_zip),
            "entry_count": len(catalog.entries),
        },
        "rule": {
            "name": "taxonomy_v1_full_cross_coverage",
            "description": (
                "Change disjoint factual_conflict to representation_discrepancy only "
                "when every CWE on both sides participates in an official Research "
                "Concepts ancestor/descendant path."
            ),
        },
        "full_corpus": {
            "row_count": processed,
            "relation_category_counts": dict(sorted(relation_counts.items())),
            "transition_counts": dict(sorted(transition_counts.items())),
            "changed_rows": len(changed_rows),
            "changed_cases_path": str(changed_path),
        },
        "candidate_diagnostic": {
            "primary": {
                "current": classification_metrics(primary_records, "current_status"),
                "taxonomy_v1": classification_metrics(
                    primary_records, "taxonomy_v1_status"
                ),
            },
            "review": {
                "current": classification_metrics(review_records, "current_status"),
                "taxonomy_v1": classification_metrics(
                    review_records, "taxonomy_v1_status"
                ),
            },
        },
        "blind_worklist": {
            "row_count": len(worklist),
            "path": str(worklist_path),
            "sha256": sha256(worklist_path),
            "blinded_from_baseline_labels": True,
            "blinded_from_primary_candidate_labels": True,
            "blinded_from_review_candidate_labels": True,
            "live_web_lookup_permitted": False,
        },
        "inputs": {
            "field_views": str(field_views_path),
            "aligned": str(aligned_path),
            "primary_source": str(primary_source_path),
            "review_source": str(review_source_path),
            "primary_candidate": str(primary_candidate_path),
            "review_candidate": str(review_candidate_path),
        },
        "cautions": [
            "CWE ancestor/descendant compatibility does not prove that both mappings are correct for a CVE.",
            "The rule was designed after inspecting AI candidate disagreements and is selection-biased.",
            "Same-model candidate and review labels are not independent human annotations.",
            "Human annotator, independent reviewer, and author sign-off remain required for human-gold.",
        ],
    }
    json_path = output_dir / "cwe_taxonomy_variant_diagnostic.json"
    md_path = output_dir / "cwe_taxonomy_variant_diagnostic.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {changed_path}")
    print(f"Wrote {worklist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
