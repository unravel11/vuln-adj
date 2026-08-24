#!/usr/bin/env python3
"""Evaluate conservative reference-URL normalization variants against AI candidates.

This is a candidate-guided diagnostic. It does not read or write canonical human-gold
labels and must not be reported as gold-backed performance.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIMARY_SOURCE = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_REVIEW_SOURCE = (
    "data/annotations/rq2/consistency_review/"
    "discrepancy_typing_consistency_review.jsonl"
)
DEFAULT_PRIMARY_CANDIDATE = (
    "data/annotations/expert_candidate/raw/rq2_primary.jsonl"
)
DEFAULT_REVIEW_CANDIDATE = "data/annotations/expert_candidate/raw/rq2_review.jsonl"
DEFAULT_FIELD_VIEWS = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"

LINE_SUFFIX_RE = re.compile(r"%23L\d+(?:-L\d+)?$", re.IGNORECASE)
GHSA_PATH_RE = re.compile(
    r"/(?:security/)?advisories/(GHSA-[0-9a-z-]+)$", re.IGNORECASE
)
HUNTR_PATH_RE = re.compile(r"/bounties/([0-9a-f-]+)$", re.IGNORECASE)

VARIANTS = {
    "current_exact": {
        "force_https": False,
        "strip_encoded_line_suffix": False,
        "drop_known_presentation_query": False,
        "resource_aliases": False,
    },
    "transport_and_line": {
        "force_https": True,
        "strip_encoded_line_suffix": True,
        "drop_known_presentation_query": False,
        "resource_aliases": False,
    },
    "transport_line_known_query": {
        "force_https": True,
        "strip_encoded_line_suffix": True,
        "drop_known_presentation_query": True,
        "resource_aliases": False,
    },
    "transport_line_known_query_aliases": {
        "force_https": True,
        "strip_encoded_line_suffix": True,
        "drop_known_presentation_query": True,
        "resource_aliases": True,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary-source", default=DEFAULT_PRIMARY_SOURCE)
    parser.add_argument("--review-source", default=DEFAULT_REVIEW_SOURCE)
    parser.add_argument("--primary-candidate", default=DEFAULT_PRIMARY_CANDIDATE)
    parser.add_argument("--review-candidate", default=DEFAULT_REVIEW_CANDIDATE)
    parser.add_argument("--field-views", default=DEFAULT_FIELD_VIEWS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def source_sample_id(row: dict) -> str:
    return str(row.get("sample_id") or row.get("review_sample_id") or "")


def canonicalize_reference_url(value: str, settings: dict[str, bool]) -> str:
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.lower() or "https"
    if settings["force_https"] and scheme in {"http", "https"}:
        scheme = "https"
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    if settings["strip_encoded_line_suffix"]:
        path = LINE_SUFFIX_RE.sub("", path)
    drop_query = (
        settings["drop_known_presentation_query"]
        and host == "liferay.dev"
        and "/known-vulnerabilities/" in path.lower()
        and "/content/cve-" in path.lower()
    )
    query = "" if drop_query else parsed.query

    if settings["resource_aliases"] and host == "github.com":
        match = GHSA_PATH_RE.search(path)
        if match:
            return f"github-advisory:{match.group(1).lower()}"
    if settings["resource_aliases"] and host in {"huntr.com", "huntr.dev"}:
        match = HUNTR_PATH_RE.fullmatch(path)
        if match:
            return f"huntr-bounty:{match.group(1).lower()}"

    return urlunsplit((scheme, host, path, query, ""))


def normalized_host(value: str, settings: dict[str, bool]) -> str:
    host = urlsplit(value).netloc.lower()
    if settings["resource_aliases"] and host in {"huntr.com", "huntr.dev"}:
        return "huntr"
    return host


def classify_references(
    nvd_urls: list[str], ghsa_urls: list[str], settings: dict[str, bool]
) -> str:
    nvd_set = {canonicalize_reference_url(url, settings) for url in nvd_urls}
    ghsa_set = {canonicalize_reference_url(url, settings) for url in ghsa_urls}

    if not nvd_set and not ghsa_set:
        return "equivalent"
    if not nvd_set or not ghsa_set:
        return "incomplete"
    if nvd_set == ghsa_set:
        return "equivalent"
    if nvd_set < ghsa_set or ghsa_set < nvd_set:
        return "incomplete"
    if nvd_set & ghsa_set:
        return "representation_discrepancy"

    nvd_hosts = {normalized_host(url, settings) for url in nvd_urls}
    ghsa_hosts = {normalized_host(url, settings) for url in ghsa_urls}
    if nvd_hosts & ghsa_hosts:
        return "representation_discrepancy"
    return "factual_conflict"


def count_map(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def transition_map(values: list[tuple[str, str]]) -> dict[str, int]:
    counts = Counter(f"{left}->{right}" for left, right in values if left != right)
    return dict(sorted(counts.items()))


def macro_f1(gold: list[str], predicted: list[str]) -> float:
    labels = sorted(set(gold))
    scores = []
    for label in labels:
        tp = sum(g == label and p == label for g, p in zip(gold, predicted))
        fp = sum(g != label and p == label for g, p in zip(gold, predicted))
        fn = sum(g == label and p != label for g, p in zip(gold, predicted))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
    return sum(scores) / len(scores) if scores else 0.0


def index_candidates(rows: list[dict], expected_rows: int) -> dict[str, dict]:
    by_id = {str(row["sample_id"]): row for row in rows}
    if len(rows) != expected_rows or len(by_id) != expected_rows:
        raise ValueError(
            f"Expected {expected_rows} unique candidate rows, got "
            f"{len(rows)} rows and {len(by_id)} IDs"
        )
    if any(row.get("label_is_human") is not False for row in rows):
        raise ValueError("Candidate input must keep label_is_human=false")
    return by_id


def evaluate_candidate_dataset(
    source_rows: list[dict],
    candidate_by_id: dict[str, dict],
    settings: dict[str, bool],
    *,
    references_only: bool,
    expected_rows: int,
) -> dict:
    records = []
    for source in source_rows:
        field = source.get("field")
        if references_only and field != "references":
            continue
        sample_id = source_sample_id(source)
        candidate = candidate_by_id.get(sample_id)
        if candidate is None:
            raise ValueError(f"Missing candidate row for {sample_id}")
        annotation = candidate["annotation"]
        if annotation.get("field") != field:
            raise ValueError(f"Candidate field mismatch for {sample_id}")
        current = str(source["baseline_status"])
        predicted = current
        if field == "references":
            predicted = classify_references(
                list(source.get("nvd_value") or []),
                list(source.get("ghsa_value") or []),
                settings,
            )
        records.append(
            {
                "sample_id": sample_id,
                "cve_id": source.get("cve_id"),
                "current": current,
                "predicted": predicted,
                "candidate": annotation["discrepancy_label"],
            }
        )

    if len(records) != expected_rows:
        raise ValueError(f"Expected {expected_rows} sample rows, got {len(records)}")
    determinate = [row for row in records if row["candidate"] != "uncertain"]
    correct = sum(row["predicted"] == row["candidate"] for row in determinate)
    current_correct = sum(row["current"] == row["candidate"] for row in determinate)
    changed = [row for row in records if row["current"] != row["predicted"]]
    corrections = [
        row["sample_id"]
        for row in determinate
        if row["current"] != row["candidate"]
        and row["predicted"] == row["candidate"]
    ]
    regressions = [
        row["sample_id"]
        for row in determinate
        if row["current"] == row["candidate"]
        and row["predicted"] != row["candidate"]
    ]
    remaining_errors = [
        row["sample_id"]
        for row in determinate
        if row["predicted"] != row["candidate"]
    ]
    gold = [row["candidate"] for row in determinate]
    predicted = [row["predicted"] for row in determinate]
    return {
        "row_count": len(records),
        "determinate_rows": len(determinate),
        "uncertain_rows": len(records) - len(determinate),
        "agreement_count": correct,
        "agreement": correct / len(determinate) if determinate else 0.0,
        "macro_f1_over_supported_candidate_labels": macro_f1(gold, predicted),
        "current_agreement_count": current_correct,
        "candidate_label_counts": count_map([row["candidate"] for row in records]),
        "predicted_label_counts": count_map([row["predicted"] for row in records]),
        "changed_vs_current_count": len(changed),
        "changed_vs_current_transitions": transition_map(
            [(row["current"], row["predicted"]) for row in changed]
        ),
        "changed_sample_ids": [row["sample_id"] for row in changed],
        "corrections_vs_current": corrections,
        "regressions_vs_current": regressions,
        "remaining_error_sample_ids": remaining_errors,
    }


def evaluate_repeated_consensus(
    primary_sources: dict[str, dict],
    primary_candidates: dict[str, dict],
    review_candidates: dict[str, dict],
    settings: dict[str, bool],
    *,
    references_only: bool,
) -> dict:
    rows = []
    for review in review_candidates.values():
        annotation = review["annotation"]
        field = annotation.get("field")
        if references_only and field != "references":
            continue
        original_id = str(review.get("original_sample_id") or "")
        primary = primary_candidates.get(original_id)
        source = primary_sources.get(original_id)
        if primary is None or source is None:
            raise ValueError(f"Missing primary reference row for {original_id}")
        primary_label = primary["annotation"]["discrepancy_label"]
        review_label = annotation["discrepancy_label"]
        if primary_label != review_label or primary_label == "uncertain":
            continue
        predicted = str(source["baseline_status"])
        if field == "references":
            predicted = classify_references(
                list(source.get("nvd_value") or []),
                list(source.get("ghsa_value") or []),
                settings,
            )
        rows.append(
            {
                "sample_id": original_id,
                "candidate_label": primary_label,
                "predicted": predicted,
            }
        )
    correct = sum(row["candidate_label"] == row["predicted"] for row in rows)
    return {
        "row_count": len(rows),
        "agreement_count": correct,
        "agreement": correct / len(rows) if rows else 0.0,
        "sample_ids": [row["sample_id"] for row in rows],
        "remaining_error_sample_ids": [
            row["sample_id"]
            for row in rows
            if row["candidate_label"] != row["predicted"]
        ],
    }


def evaluate_full_corpus(rows: list[dict], settings: dict[str, bool]) -> dict:
    records = []
    for row in rows:
        references = row["unified_view"]["references"]
        current = row["field_discrepancies"]["references"]["status"]
        predicted = classify_references(
            references.get("nvd_urls") or [],
            references.get("ghsa_urls") or [],
            settings,
        )
        records.append(
            {
                "cve_id": row.get("cve_id"),
                "current": current,
                "predicted": predicted,
            }
        )
    changed = [row for row in records if row["current"] != row["predicted"]]
    return {
        "row_count": len(records),
        "current_label_counts": count_map([row["current"] for row in records]),
        "predicted_label_counts": count_map([row["predicted"] for row in records]),
        "changed_vs_current_count": len(changed),
        "changed_vs_current_rate": len(changed) / len(records) if records else 0.0,
        "changed_vs_current_transitions": transition_map(
            [(row["current"], row["predicted"]) for row in changed]
        ),
        "changed_cve_ids": [row["cve_id"] for row in changed],
    }


def build_changed_case_worklist(rows: list[dict]) -> list[dict]:
    current_name = "current_exact"
    stage_names = [name for name in VARIANTS if name != current_name]
    best_name = stage_names[-1]
    current_settings = VARIANTS[current_name]
    best_settings = VARIANTS[best_name]
    worklist = []
    for row in rows:
        references = row["unified_view"]["references"]
        nvd_urls = list(references.get("nvd_urls") or [])
        ghsa_urls = list(references.get("ghsa_urls") or [])
        current = row["field_discrepancies"]["references"]["status"]
        proposed = classify_references(nvd_urls, ghsa_urls, best_settings)
        if current == proposed:
            continue
        trigger_stage = next(
            name
            for name in stage_names
            if classify_references(nvd_urls, ghsa_urls, VARIANTS[name]) != current
        )
        worklist.append(
            {
                "schema_version": "rq2_reference_normalization_review_v1",
                "artifact_type": "candidate_guided_rule_change_review",
                "label_is_human": False,
                "review_status": "pending",
                "cve_id": row.get("cve_id"),
                "field": "references",
                "current_status": current,
                "proposed_status": proposed,
                "trigger_stage": trigger_stage,
                "nvd_urls": nvd_urls,
                "ghsa_urls": ghsa_urls,
                "current_normalized_nvd": sorted({
                    canonicalize_reference_url(url, current_settings)
                    for url in nvd_urls
                }),
                "current_normalized_ghsa": sorted({
                    canonicalize_reference_url(url, current_settings)
                    for url in ghsa_urls
                }),
                "proposed_normalized_nvd": sorted({
                    canonicalize_reference_url(url, best_settings) for url in nvd_urls
                }),
                "proposed_normalized_ghsa": sorted({
                    canonicalize_reference_url(url, best_settings) for url in ghsa_urls
                }),
                "human_review": {
                    "decision": "",
                    "rationale": "",
                    "annotator_id": "",
                    "reviewer_id": "",
                    "reviewed_at": "",
                },
            }
        )
    return sorted(worklist, key=lambda row: (row["trigger_stage"], row["cve_id"] or ""))


def render_markdown(artifact: dict) -> str:
    lines = [
        "# RQ2 Reference Normalization Variant Diagnostic",
        "",
        "> AI-candidate diagnostic only; this is not human-gold validation.",
        "",
        "| Variant | Primary agreement | Review-pass agreement | Repeated-consensus agreement | Full-corpus changes |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, result in artifact["variants"].items():
        primary = result["primary_candidate"]
        review = result["review_candidate"]
        consensus = result["repeated_consensus"]
        full = result["full_corpus"]
        lines.append(
            "| "
            + " | ".join(
                [
                    name,
                    f"{primary['agreement_count']}/{primary['determinate_rows']} ({primary['agreement']:.4f})",
                    f"{review['agreement_count']}/{review['determinate_rows']} ({review['agreement']:.4f})",
                    f"{consensus['agreement_count']}/{consensus['row_count']} ({consensus['agreement']:.4f})",
                    f"{full['changed_vs_current_count']}/{full['row_count']} ({full['changed_vs_current_rate']:.4%})",
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "| Variant | Overall primary agreement | Overall review-pass agreement | Overall repeated-consensus agreement |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, result in artifact["variants"].items():
        primary = result["overall_primary_candidate"]
        review = result["overall_review_candidate"]
        consensus = result["overall_repeated_consensus"]
        lines.append(
            "| "
            + " | ".join(
                [
                    name,
                    f"{primary['agreement_count']}/{primary['determinate_rows']} ({primary['agreement']:.4f})",
                    f"{review['agreement_count']}/{review['determinate_rows']} ({review['agreement']:.4f})",
                    f"{consensus['agreement_count']}/{consensus['row_count']} ({consensus['agreement']:.4f})",
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            f"The best variant changes {artifact['changed_case_worklist']['row_count']}/8,066 full-corpus reference labels. Trigger stages: {artifact['changed_case_worklist']['trigger_stage_counts']}.",
            "",
            "The review pass reuses a 20% subset of the primary sample and the same model family. It is a repeatability diagnostic, not an independent holdout or human inter-annotator evaluation.",
            "",
            "The known-query and resource-alias variants are candidate-guided hypotheses. They must be audited on human labels before changing the production baseline.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    paths = {
        "primary_source": resolve_path(args.primary_source),
        "review_source": resolve_path(args.review_source),
        "primary_candidate": resolve_path(args.primary_candidate),
        "review_candidate": resolve_path(args.review_candidate),
        "field_views": resolve_path(args.field_views),
        "output_dir": resolve_path(args.output_dir),
    }
    for name, path in paths.items():
        if name != "output_dir" and not path.exists():
            raise FileNotFoundError(path)

    primary_source_rows = load_jsonl(paths["primary_source"])
    review_source_rows = load_jsonl(paths["review_source"])
    primary_candidates = index_candidates(
        load_jsonl(paths["primary_candidate"]), expected_rows=300
    )
    review_candidates = index_candidates(
        load_jsonl(paths["review_candidate"]), expected_rows=60
    )
    field_views = load_jsonl(paths["field_views"])
    if len(field_views) != 8066:
        raise ValueError(f"Expected 8066 field views, got {len(field_views)}")
    primary_sources = {source_sample_id(row): row for row in primary_source_rows}

    results = {}
    for name, settings in VARIANTS.items():
        result = {
            "settings": settings,
            "primary_candidate": evaluate_candidate_dataset(
                primary_source_rows,
                primary_candidates,
                settings,
                references_only=True,
                expected_rows=60,
            ),
            "review_candidate": evaluate_candidate_dataset(
                review_source_rows,
                review_candidates,
                settings,
                references_only=True,
                expected_rows=12,
            ),
            "repeated_consensus": evaluate_repeated_consensus(
                primary_sources,
                primary_candidates,
                review_candidates,
                settings,
                references_only=True,
            ),
            "overall_primary_candidate": evaluate_candidate_dataset(
                primary_source_rows,
                primary_candidates,
                settings,
                references_only=False,
                expected_rows=300,
            ),
            "overall_review_candidate": evaluate_candidate_dataset(
                review_source_rows,
                review_candidates,
                settings,
                references_only=False,
                expected_rows=60,
            ),
            "overall_repeated_consensus": evaluate_repeated_consensus(
                primary_sources,
                primary_candidates,
                review_candidates,
                settings,
                references_only=False,
            ),
            "full_corpus": evaluate_full_corpus(field_views, settings),
        }
        if name == "current_exact":
            if result["primary_candidate"]["changed_vs_current_count"]:
                raise AssertionError("current_exact changed primary baseline labels")
            if result["review_candidate"]["changed_vs_current_count"]:
                raise AssertionError("current_exact changed review baseline labels")
            if result["overall_primary_candidate"]["changed_vs_current_count"]:
                raise AssertionError("current_exact changed overall primary baseline labels")
            if result["overall_review_candidate"]["changed_vs_current_count"]:
                raise AssertionError("current_exact changed overall review baseline labels")
            if result["full_corpus"]["changed_vs_current_count"]:
                raise AssertionError("current_exact changed full-corpus baseline labels")
        results[name] = result

    output_dir = paths["output_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    worklist_path = output_dir / "reference_normalization_changed_cases.review.jsonl"
    worklist = build_changed_case_worklist(field_views)
    stage_counts = count_map([row["trigger_stage"] for row in worklist])
    with worklist_path.open("w", encoding="utf-8") as handle:
        for row in worklist:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    artifact = {
        "artifact_type": "rq2_reference_normalization_candidate_diagnostic",
        "label_is_human": False,
        "candidate_status": "unreviewed",
        "same_model_review_is_independent_human_review": False,
        "input_paths": {
            name: str(path) for name, path in paths.items() if name != "output_dir"
        },
        "variants": results,
        "changed_case_worklist": {
            "path": str(worklist_path),
            "row_count": len(worklist),
            "trigger_stage_counts": stage_counts,
            "signed_human_rows": 0,
        },
        "cautions": [
            "RQ2 labels are AI expert-adjudicated candidates, not human-gold.",
            "The review pass reuses primary samples and the same model family.",
            "The normalization variants were designed after candidate error inspection.",
            "Full-corpus label changes are impact estimates, not validated corrections.",
        ],
    }

    json_path = output_dir / "reference_normalization_variant_diagnostic.json"
    md_path = output_dir / "reference_normalization_variant_diagnostic.md"
    json_path.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(json.dumps(artifact, indent=2, ensure_ascii=False))
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {worklist_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
