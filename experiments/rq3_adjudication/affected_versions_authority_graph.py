#!/usr/bin/env python3
"""Gold-blind affected-version source head using authority-filtered evidence."""

from __future__ import annotations

import copy
from urllib.parse import urlparse

from affected_versions_branch_graph import extract_branch_graph_features


MIN_AUTHORITY_TIER = 2


def classify_evidence_authority(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":", 1)[0]
    path = parsed.path.lower()
    if host == "github.com" and "/security/advisories/" in path:
        return "upstream_github_advisory", 3
    if host in {"openwall.com", "www.openwall.com"}:
        return "mailing_list_disclosure", 3
    if host == "github.com" and "/pypa/advisory-database/" in path:
        return "ecosystem_advisory_database", 2
    if host == "nvd.nist.gov":
        return "nvd_record", 0
    if host == "devhub.checkmarx.com":
        return "secondary_aggregator", 0
    if host == "github.com":
        return "github_code_or_poc", 1
    return "other_web_evidence", 1


def authority_filtered_records(row: dict) -> tuple[list[dict], dict]:
    usable = [
        record
        for record in row.get("evidence_context", {}).get("records", [])
        if record.get("fetch_status") == "ok" and record.get("text_snippet")
    ]
    classified = [
        (record, *classify_evidence_authority(str(record.get("url") or "")))
        for record in usable
    ]
    eligible = [item for item in classified if item[2] >= MIN_AUTHORITY_TIER]
    if eligible:
        selected_tier = max(item[2] for item in eligible)
        selected = [item for item in eligible if item[2] == selected_tier]
    else:
        selected_tier = None
        selected = []
    return [item[0] for item in selected], {
        "usable_record_count": len(usable),
        "authority_class_counts": {
            authority_class: sum(item[1] == authority_class for item in classified)
            for authority_class in sorted({item[1] for item in classified})
        },
        "selected_authority_tier": selected_tier,
        "selected_classes": sorted({item[1] for item in selected}),
        "selected_urls": sorted(str(item[0].get("url") or "") for item in selected),
    }


def predict_authority_filtered_source(row: dict) -> dict:
    selected_records, authority_profile = authority_filtered_records(row)
    if not selected_records:
        return {
            "predicted_source": "abstain",
            "source_prediction_status": "abstain",
            "source_prediction_reason": "no_primary_or_ecosystem_evidence_record",
            "authority_profile": authority_profile,
            "rule": "authority-filtered branch graph; no low-authority fallback",
        }
    filtered = copy.deepcopy(row)
    filtered.setdefault("evidence_context", {})["records"] = selected_records
    branch = extract_branch_graph_features(filtered)
    source = branch["predicted_source"]
    return {
        "predicted_source": source,
        "source_prediction_status": (
            "abstain" if source in {"abstain", "both"} else "determinate"
        ),
        "source_prediction_reason": branch["prediction_reason"],
        "authority_profile": authority_profile,
        "branch_profile": branch,
        "rule": "highest-tier primary/ecosystem evidence then branch-boundary source head",
    }
