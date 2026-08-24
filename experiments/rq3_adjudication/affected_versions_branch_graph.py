#!/usr/bin/env python3
"""Gold-blind branch and release-graph diagnostics for affected_versions."""

from __future__ import annotations

import copy
import re
from collections import defaultdict

from affected_versions_release_boundary import (
    boundary_prediction,
    dedupe_events,
    extract_release_boundary_features,
    normalize_token,
    token_equivalent,
)
from affected_versions_semantic_baseline import (
    immediate_release_successor,
    parse_span,
    parse_version,
)


START_KEYS = ("version_start_including", "introduced", "version_start_excluding")
END_KEYS = ("version_end_excluding", "fixed", "version_end_including")
MODIFIED_AFTER_ENRICHMENT_RE = re.compile(
    r"modified\s+after\s+(?:nvd\s+)?enrichment", re.IGNORECASE
)


def first_token(span: dict, keys: tuple[str, ...]) -> tuple[str | None, str | None]:
    for key in keys:
        token = normalize_token(span.get(key))
        if token and token not in {"*", "-", "0"}:
            return key, token
    return None, None


def branch_key(token: object) -> str | None:
    """Return a coarse release branch without claiming ecosystem-specific ordering."""
    version = parse_version(token)
    if version is not None:
        release = version.release
    else:
        match = re.match(r"^v?(\d+)(?:[._-](\d+))?", normalize_token(token))
        if not match:
            return None
        release = tuple(int(value) for value in match.groups() if value is not None)
    if not release:
        return None
    return ".".join(str(value) for value in release[:2])


def opaque_ordinal(token: object) -> int | None:
    text = normalize_token(token)
    if parse_version(text) is not None:
        return None
    match = re.match(r"^v?(\d+)[._-]", text)
    return int(match.group(1)) if match else None


def target_scoped_claim(claim: dict, cve_id: str) -> bool:
    needle = cve_id.lower()
    return needle in str(claim.get("url") or "").lower() or needle in str(
        claim.get("context") or ""
    ).lower()


def prerelease_successor(left, right) -> bool:
    if left.release != right.release:
        return False
    if left.pre is not None and right.pre is not None:
        return left.pre[0] == right.pre[0] and right.pre[1] == left.pre[1] + 1
    if left.dev is not None and right.dev is not None:
        return left.pre == right.pre and right.dev == left.dev + 1
    return False


def release_successor(left, right) -> bool:
    return immediate_release_successor(left, right) or prerelease_successor(
        left, right
    )


def same_major(left, right) -> bool:
    return bool(left.release and right.release and left.release[0] == right.release[0])


def opaque_exception_events(source: str, row: dict, claims: list[dict]) -> list[dict]:
    events = []
    exceptions = [
        claim
        for claim in claims
        if "safe_exception" in claim["roles"]
        and opaque_ordinal(claim["token"]) is not None
    ]
    for span_index, raw_span in enumerate(row.get(f"{source}_value") or []):
        _, start_token = first_token(raw_span, START_KEYS)
        _, end_token = first_token(raw_span, END_KEYS)
        start = opaque_ordinal(start_token)
        end = opaque_ordinal(end_token)
        if start is None and end is None:
            continue
        for claim in exceptions:
            ordinal = opaque_ordinal(claim["token"])
            lower_ok = start is None or ordinal >= start
            upper_ok = end is None or ordinal < end
            if not lower_ok or not upper_ok:
                continue
            events.append(
                {
                    "kind": "opaque_safe_exception_inside_affected_span",
                    "source": source,
                    "span_index": span_index,
                    "span_start_token": start_token,
                    "span_end_token": end_token,
                    "evidence_token": claim["token"],
                    "evidence_roles": claim["roles"],
                    "url": claim["url"],
                    "context": claim["context"],
                    "ordering_scope": "leading_numeric_ordinal_only",
                }
            )
    return events


def endpoint_structure_events(
    source: str, row: dict, claims: list[dict]
) -> tuple[list[dict], list[dict]]:
    support = []
    contradictions = []
    for claim in claims:
        if "affected_endpoint" not in claim["roles"]:
            continue
        endpoint = parse_version(claim["token"])
        if endpoint is None:
            continue
        for span_index, raw_span in enumerate(row.get(f"{source}_value") or []):
            span = parse_span(raw_span)
            if not span.parseable:
                continue
            event = {
                "source": source,
                "span_index": span_index,
                "evidence_token": claim["token"],
                "evidence_roles": claim["roles"],
                "url": claim["url"],
                "context": claim["context"],
            }
            if span.point is not None:
                if (
                    endpoint.pre is not None or endpoint.dev is not None
                ) and span.point.release == endpoint.release and span.point > endpoint:
                    contradictions.append(
                        {
                            **event,
                            "kind": "stable_or_later_point_exceeds_prerelease_endpoint",
                            "source_point": str(span.point),
                        }
                    )
                continue
            if span.start is not None and not same_major(span.start, endpoint):
                continue
            if span.end is None:
                if span.start is not None and span.start <= endpoint:
                    contradictions.append(
                        {
                            **event,
                            "kind": "open_ended_span_exceeds_explicit_affected_endpoint",
                            "source_start": str(span.start),
                        }
                    )
                continue
            if not same_major(span.end, endpoint):
                continue
            if span.end_inclusive and span.end == endpoint:
                support.append(
                    {
                        **event,
                        "kind": "inclusive_end_matches_affected_endpoint",
                        "source_end": str(span.end),
                    }
                )
            elif not span.end_inclusive and release_successor(endpoint, span.end):
                support.append(
                    {
                        **event,
                        "kind": "exclusive_end_is_release_successor",
                        "source_end": str(span.end),
                    }
                )
    return support, contradictions


def fixed_set_profile(source: str, row: dict, claims: list[dict]) -> dict:
    evidence = [
        claim for claim in claims if "fixed_boundary" in set(claim.get("roles") or [])
    ]
    source_tokens = []
    for span in row.get(f"{source}_value") or []:
        _, token = first_token(span, END_KEYS)
        if token and token not in source_tokens:
            source_tokens.append(token)
    matched = []
    missing = []
    for claim in evidence:
        record = {
            "token": claim["token"],
            "branch": branch_key(claim["token"]),
            "url": claim["url"],
            "host": claim["host"],
        }
        if any(token_equivalent(token, claim["token"]) for token in source_tokens):
            matched.append(record)
        else:
            missing.append(record)
    branches = sorted(
        {branch_key(claim["token"]) for claim in evidence if branch_key(claim["token"])}
    )
    return {
        "source": source,
        "source_fixed_tokens": source_tokens,
        "evidence_fixed_branches": branches,
        "matched_evidence_fixed_claims": matched,
        "missing_evidence_fixed_claims": missing,
        "multi_branch_evidence": len(branches) >= 2,
        "multi_branch_coverage_gap": len(branches) >= 2 and bool(missing),
    }


def conflicting_fixed_boundaries(claims: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for claim in claims:
        if "fixed_boundary" not in claim["roles"]:
            continue
        key = branch_key(claim["token"])
        if key:
            grouped[key].append(claim)
    conflicts = []
    for key, branch_claims in sorted(grouped.items()):
        tokens = []
        hosts = set()
        for claim in branch_claims:
            hosts.add(claim["host"])
            if not any(token_equivalent(token, claim["token"]) for token in tokens):
                tokens.append(claim["token"])
        if len(tokens) > 1 and len(hosts) > 1:
            conflicts.append(
                {"branch": key, "tokens": tokens, "hosts": sorted(hosts)}
            )
    return conflicts


def record_scope_profile(row: dict) -> dict:
    cve_id = str(row.get("cve_id") or "").lower()
    fetched = []
    unscoped = []
    modified = []
    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok":
            continue
        text = " ".join(
            [
                str(record.get("url") or ""),
                str(record.get("title") or ""),
                str(record.get("text_snippet") or ""),
            ]
        )
        item = {"url": record.get("url", ""), "host": record.get("host", "")}
        fetched.append(item)
        if cve_id and cve_id not in text.lower():
            unscoped.append(item)
        if MODIFIED_AFTER_ENRICHMENT_RE.search(text):
            modified.append(item)
    return {
        "fetched_records": len(fetched),
        "fetched_records_without_target_cve": unscoped,
        "modified_after_enrichment_records": modified,
    }


def extract_branch_graph_features(row: dict) -> dict:
    base = extract_release_boundary_features(row)
    cve_id = str(row.get("cve_id") or "")
    scoped_claims = [
        claim
        for claim in base["evidence_claims"]
        if target_scoped_claim(claim, cve_id)
    ]
    profiles = copy.deepcopy(base["source_profiles"])
    fixed_profiles = {}
    structural_counts = defaultdict(int)
    for source in ("nvd", "ghsa"):
        endpoint_support, endpoint_conflicts = endpoint_structure_events(
            source, row, scoped_claims
        )
        opaque_conflicts = opaque_exception_events(source, row, scoped_claims)
        for event in [*endpoint_support, *endpoint_conflicts, *opaque_conflicts]:
            structural_counts[event["kind"]] += 1
        profiles[source]["support_events"] = dedupe_events(
            profiles[source]["support_events"] + endpoint_support
        )
        profiles[source]["contradiction_events"] = dedupe_events(
            profiles[source]["contradiction_events"]
            + endpoint_conflicts
            + opaque_conflicts
        )
        fixed_profiles[source] = fixed_set_profile(source, row, scoped_claims)

    prediction, reason = boundary_prediction(profiles)
    fixed_conflicts = conflicting_fixed_boundaries(scoped_claims)
    record_profile = record_scope_profile(row)
    flags = []
    if any(kind.startswith("opaque_safe_exception") for kind in structural_counts):
        flags.append("opaque_ordinal_exception")
    if any("prerelease" in kind for kind in structural_counts):
        flags.append("prerelease_endpoint")
    if structural_counts.get("open_ended_span_exceeds_explicit_affected_endpoint"):
        flags.append("explicit_endpoint_vs_open_ended_span")
    if any(profile["multi_branch_coverage_gap"] for profile in fixed_profiles.values()):
        flags.append("multi_branch_fixed_set_gap")
    if fixed_conflicts:
        flags.append("cross_host_fixed_boundary_conflict")
    if record_profile["fetched_records_without_target_cve"]:
        flags.append("fetched_linked_evidence_without_target_cve")
    if record_profile["modified_after_enrichment_records"]:
        flags.append("modified_after_enrichment")

    return {
        "sample_id": row.get("sample_id"),
        "cve_id": row.get("cve_id"),
        "field": "affected_versions",
        "feature_label_is_human": False,
        "feature_extraction_uses_gold": False,
        "base_release_boundary_prediction": base["predicted_source"],
        "base_prediction_reason": base["prediction_reason"],
        "scoped_evidence_claim_count": len(scoped_claims),
        "source_profiles": profiles,
        "fixed_set_profiles": fixed_profiles,
        "cross_host_fixed_boundary_conflicts": fixed_conflicts,
        "record_scope_profile": record_profile,
        "capability_flags": flags,
        "structural_event_counts": dict(sorted(structural_counts.items())),
        "predicted_source": prediction,
        "prediction_reason": reason,
    }
