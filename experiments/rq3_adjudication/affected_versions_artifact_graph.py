#!/usr/bin/env python3
"""Selection-aware artifact-bound extension of the branch/release graph."""

from __future__ import annotations

import re

from affected_versions_branch_graph import extract_branch_graph_features
from affected_versions_semantic_baseline import (
    compact_package_name,
    leaf_package_name,
    normalize_package_name,
    package_profile,
)
from evaluate_affected_versions_silver_v2 import (
    canonical_token_present,
    extract_version_tokens,
)


SOURCES = ("nvd", "ghsa")
REJECTING_BASE_PREDICTIONS = {"abstain", "neither"}


def compact_text(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def source_artifact_aliases(row: dict) -> dict[str, list[str]]:
    aliases: dict[str, set[str]] = {source: set() for source in SOURCES}
    for source in SOURCES:
        for value in row.get(f"{source}_context", {}).get("package_names", []):
            normalized = normalize_package_name(value)
            full = compact_package_name(normalized)
            leaf = leaf_package_name(normalized)
            if len(full) >= 5:
                aliases[source].add(full)
            if len(leaf) >= 5:
                aliases[source].add(leaf)

    shared = aliases["nvd"] & aliases["ghsa"]
    return {
        source: sorted(aliases[source] - shared)
        for source in SOURCES
    }


def cve_scoped_record_text(row: dict, record: dict) -> str | None:
    if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
        return None
    text = " ".join(
        [
            str(record.get("url") or ""),
            str(record.get("title") or ""),
            str(record.get("text_snippet") or ""),
        ]
    ).lower()
    cve_id = str(row.get("cve_id") or "").strip().lower()
    if not cve_id or cve_id not in text:
        return None
    return text


def artifact_bound_support(
    row: dict, source: str, aliases: list[str]
) -> dict:
    tokens = sorted(extract_version_tokens(row.get(f"{source}_value") or []))
    records = []
    matched_tokens: set[str] = set()
    matched_aliases: set[str] = set()
    for record in row.get("evidence_context", {}).get("records", []):
        text = cve_scoped_record_text(row, record)
        if text is None:
            continue
        compact = compact_text(text)
        record_aliases = sorted(alias for alias in aliases if alias in compact)
        record_tokens = sorted(
            token for token in tokens if canonical_token_present(text, token)
        )
        if not record_aliases or not record_tokens:
            continue
        matched_aliases.update(record_aliases)
        matched_tokens.update(record_tokens)
        records.append(
            {
                "url": record.get("url", ""),
                "host": record.get("host", ""),
                "matched_artifact_aliases": record_aliases,
                "matched_version_tokens": record_tokens,
            }
        )
    return {
        "source": source,
        "artifact_aliases": aliases,
        "source_version_tokens": tokens,
        "matched_artifact_aliases": sorted(matched_aliases),
        "matched_version_tokens": sorted(matched_tokens),
        "supporting_records": records,
        "has_positive_support": bool(records),
    }


def artifact_bound_prediction(
    base_prediction: str,
    direct_package_category: str,
    source_support: dict[str, dict],
) -> tuple[str, str]:
    both_supported = all(
        source_support[source]["has_positive_support"] for source in SOURCES
    )
    if (
        direct_package_category == "no_package_name_overlap"
        and base_prediction in REJECTING_BASE_PREDICTIONS
        and both_supported
    ):
        return (
            "both",
            "distinct_identifiers_have_independent_artifact_bound_support",
        )
    return base_prediction, "retain_base_branch_graph_prediction"


def extract_artifact_graph_features(row: dict) -> dict:
    base = extract_branch_graph_features(row)
    direct = package_profile(row)
    aliases = source_artifact_aliases(row)
    support = {
        source: artifact_bound_support(row, source, aliases[source])
        for source in SOURCES
    }
    prediction, reason = artifact_bound_prediction(
        base["predicted_source"], direct["category"], support
    )
    return {
        "sample_id": row.get("sample_id"),
        "cve_id": row.get("cve_id"),
        "field": "affected_versions",
        "feature_label_is_human": False,
        "feature_extraction_uses_gold_labels": False,
        "feature_input_selection_uses_ai_gold_status": True,
        "eligible_for_independent_holdout_claim": False,
        "base_branch_graph_prediction": base["predicted_source"],
        "base_prediction_reason": base["prediction_reason"],
        "direct_package_profile": direct,
        "source_artifact_aliases": aliases,
        "source_artifact_support": support,
        "predicted_source": prediction,
        "prediction_reason": reason,
        "prediction_changed": prediction != base["predicted_source"],
        "rule": (
            "When direct package identifiers do not overlap, retain one-sided "
            "branch decisions; replace only abstain/neither with both when each "
            "source has CVE-scoped artifact-name and version-token support."
        ),
    }
