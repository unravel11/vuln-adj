#!/usr/bin/env python3
"""Gold-blind release-boundary evidence features for affected_versions."""

from __future__ import annotations

import re
from collections import defaultdict

from affected_versions_semantic_baseline import contains, parse_span, parse_version


VERSION_KEYS = (
    "version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "fixed",
    "introduced",
)
VERSION_CANDIDATE_RE = re.compile(
    r"(?<![a-z0-9])v?\d+(?:[._-][a-z0-9]+)+(?![a-z0-9])",
    re.IGNORECASE,
)
NON_CLAIM_CONTEXT_RE = re.compile(
    r"\b(?:change\s+history|old\s+value|full\s+changelog|branch\s+selector|"
    r"select\s+branch|showing\s+\d+\s+commits?|"
    r"cpe\s+configuration|cpe:2\.3|configuration\s+or|added\s+cpe|new\s+value\s+added|"
    r"historical\s+list\s+of\s+changes)\b",
    re.IGNORECASE,
)
AFFECTED_CUE_RE = re.compile(
    r"\b(?:affected|vulnerab\w*|impact(?:ed)?|through|up\s+to|and\s+earlier)\b",
    re.IGNORECASE,
)
INTRODUCED_CUE_RE = re.compile(
    r"\b(?:introduced|starting\s+with|from)\b", re.IGNORECASE
)
EXCLUSIVE_BOUND_RE = re.compile(
    r"(?:\bprior\s+to\b|\bbefore\b|\bless\s+than\b|<)\s*(?:versions?\s*)?$",
    re.IGNORECASE,
)
EXCLUSIVE_LIST_BOUND_RE = re.compile(
    r"(?:\bprior\s+to\b|\bbefore\b|\bless\s+than\b).{0,80}$",
    re.IGNORECASE,
)
INCLUSIVE_BOUND_RE = re.compile(
    r"(?:\bthrough\b|\bup\s+to\b)\s*$", re.IGNORECASE
)
EARLIER_AFTER_RE = re.compile(
    r"^\s*(?:and\s+)?(?:earlier|before)\b", re.IGNORECASE
)
AFFECTED_AFTER_RE = re.compile(
    r"\b(?:is|are|was|were)?\s*(?:affected|vulnerab\w*)\b",
    re.IGNORECASE,
)
EXCEPTION_BEFORE_RE = re.compile(r"\bexcept\s*$", re.IGNORECASE)
SAFE_AFTER_RE = re.compile(
    r"\b(?:is|are|was|were)?\s*"
    r"(?:unaffected|not\s+affected|no\s+longer\s+affected)\b",
    re.IGNORECASE,
)
FIX_BEFORE_RE = re.compile(
    r"\b(?:fixed|fix(?:es)?|patched|resolved|remediated|"
    r"upgrade(?:d)?\s+to(?:\s+at\s+least)?|at\s+least|"
    r"contain(?:s|ed)?\s+fixes?|updated\s+to|security[- ]fix)\b",
    re.IGNORECASE,
)
FIX_AFTER_RE = re.compile(
    r"\b(?:is|are|was|were|contains?|includes?)\s+"
    r"(?:fixed|patched|a\s+fix|fixes?)\b",
    re.IGNORECASE,
)
AFFECTED_BEFORE_RE = re.compile(
    r"\b(?:affected|vulnerab\w*|affects|impact(?:ed)?)\b",
    re.IGNORECASE,
)
CVSS_RE = re.compile(r"\bcvss\b", re.IGNORECASE)


def normalize_text(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_token(value: object) -> str:
    return str(value or "").strip().lower().rstrip(".,;:)")


def source_token_roles(row: dict) -> dict[str, dict[str, set[str]]]:
    result: dict[str, dict[str, set[str]]] = {}
    key_roles = {
        "version": "affected",
        "version_end_including": "affected_endpoint",
        "version_end_excluding": "fixed_boundary",
        "fixed": "fixed_boundary",
        "version_start_including": "introduced",
        "version_start_excluding": "introduced",
        "introduced": "introduced",
    }
    for source in ("nvd", "ghsa"):
        roles: dict[str, set[str]] = defaultdict(set)
        for span in row.get(f"{source}_value") or []:
            for key in VERSION_KEYS:
                token = normalize_token(span.get(key))
                if token and token not in {"*", "-", "0"}:
                    roles[token].add(key_roles[key])
        result[source] = dict(roles)
    return result


def token_equivalent(left: object, right: object) -> bool:
    left_text = normalize_token(left).rstrip("_")
    right_text = normalize_token(right).rstrip("_")
    if not left_text or not right_text:
        return False
    if left_text == right_text:
        return True
    left_version = parse_version(left_text)
    right_version = parse_version(right_text)
    if left_version is not None and right_version is not None:
        return (
            left_version == right_version
            and len(left_version.release) == len(right_version.release)
        )
    if min(len(left_text), len(right_text)) >= 8:
        return left_text.startswith(right_text) or right_text.startswith(left_text)
    return False


def cue_binds_before(pattern: re.Pattern[str], before: str, limit: int) -> bool:
    text = before[-limit:]
    matches = list(pattern.finditer(text))
    if not matches:
        return False
    tail = text[matches[-1].end() :]
    return ". " not in tail and "; " not in tail


def cue_binds_after(pattern: re.Pattern[str], after: str, limit: int) -> bool:
    text = after[:limit]
    match = pattern.search(text)
    if not match:
        return False
    prefix = text[: match.start()]
    return ". " not in prefix and "; " not in prefix


def classify_claim(text: str, start: int, end: int) -> tuple[set[str], str]:
    before = text[max(0, start - 180) : start]
    after = text[end : min(len(text), end + 180)]
    context = normalize_text(text[max(0, start - 180) : min(len(text), end + 180)])
    if NON_CLAIM_CONTEXT_RE.search(context):
        return set(), context
    if cue_binds_before(CVSS_RE, before, 50) or cue_binds_after(
        CVSS_RE, after, 50
    ):
        return set(), context

    roles: set[str] = set()
    before_tail = before[-90:]
    after_head = after[:90]
    if EXCEPTION_BEFORE_RE.search(before_tail) or cue_binds_after(
        SAFE_AFTER_RE, after, 80
    ):
        return {"safe_exception"}, context
    list_bound = EXCLUSIVE_LIST_BOUND_RE.search(before_tail)
    if EXCLUSIVE_BOUND_RE.search(before_tail) or (
        list_bound
        and not re.search(r"\bfrom\b|>=", list_bound.group(0), re.IGNORECASE)
    ):
        return {"fixed_boundary"}, context
    if INCLUSIVE_BOUND_RE.search(before_tail) or EARLIER_AFTER_RE.search(after_head):
        return {"affected_endpoint"}, context
    if cue_binds_after(AFFECTED_AFTER_RE, after, 90):
        return {"affected"}, context

    if not roles and (
        cue_binds_before(FIX_BEFORE_RE, before, 220)
        or cue_binds_after(FIX_AFTER_RE, after, 100)
    ):
        roles.add("fixed_boundary")
    if not roles and (
        cue_binds_before(AFFECTED_BEFORE_RE, before, 130)
        or cue_binds_after(AFFECTED_CUE_RE, after, 100)
    ):
        roles.add("affected")
    if not roles and INTRODUCED_CUE_RE.search(before[-100:] + " " + after[:100]):
        roles.add("introduced")

    return roles, context


def extract_evidence_claims(row: dict) -> list[dict]:
    claims = []
    seen = set()
    for record in row.get("evidence_context", {}).get("records", []):
        if record.get("fetch_status") != "ok" or not record.get("text_snippet"):
            continue
        text = normalize_text(
            " ".join([str(record.get("title") or ""), str(record.get("text_snippet") or "")])
        )
        cve_id = str(row.get("cve_id") or "").strip().lower()
        if not cve_id or cve_id not in text.lower():
            continue
        for match in VERSION_CANDIDATE_RE.finditer(text):
            token = normalize_token(match.group(0))
            roles, context = classify_claim(text, match.start(), match.end())
            if not roles or roles == {"ambiguous"}:
                continue
            key = (record.get("url", ""), token, tuple(sorted(roles)), context)
            if key in seen:
                continue
            seen.add(key)
            claims.append(
                {
                    "token": token,
                    "roles": sorted(roles),
                    "url": record.get("url", ""),
                    "host": record.get("host", ""),
                    "context": context,
                }
            )
    return claims


def direct_role_events(
    source: str, roles_by_token: dict[str, set[str]], claims: list[dict]
) -> tuple[list[dict], list[dict]]:
    support = []
    contradictions = []
    compatible = {
        "affected": {"affected", "affected_endpoint"},
        "affected_endpoint": {"affected", "affected_endpoint"},
        "fixed_boundary": {"fixed_boundary"},
        "introduced": {"introduced", "affected"},
    }
    incompatible = {
        "affected": {"fixed_boundary", "safe_exception"},
        "affected_endpoint": {"fixed_boundary", "safe_exception"},
        "fixed_boundary": {"affected", "affected_endpoint"},
        "introduced": {"safe_exception"},
    }
    for source_token, source_roles in roles_by_token.items():
        for claim in claims:
            if not token_equivalent(source_token, claim["token"]):
                continue
            claim_roles = set(claim["roles"])
            for source_role in source_roles:
                event = {
                    "kind": "direct_role_match",
                    "source": source,
                    "source_token": source_token,
                    "source_role": source_role,
                    "evidence_token": claim["token"],
                    "evidence_roles": claim["roles"],
                    "url": claim["url"],
                    "context": claim["context"],
                }
                if claim_roles & compatible[source_role]:
                    support.append(event)
                if claim_roles & incompatible[source_role]:
                    contradictions.append(event)
    return support, contradictions


def span_contradiction_events(source: str, row: dict, claims: list[dict]) -> list[dict]:
    contradictions = []
    spans = [parse_span(span) for span in row.get(f"{source}_value") or []]
    for claim in claims:
        if not ({"fixed_boundary", "safe_exception"} & set(claim["roles"])):
            continue
        version = parse_version(claim["token"])
        if version is None:
            continue
        for span_index, span in enumerate(spans):
            if not contains(span, version):
                continue
            contradictions.append(
                {
                    "kind": "evidence_safe_version_inside_claimed_affected_span",
                    "source": source,
                    "span_index": span_index,
                    "evidence_token": claim["token"],
                    "evidence_roles": claim["roles"],
                    "url": claim["url"],
                    "context": claim["context"],
                }
            )
    return contradictions


def dedupe_events(events: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for event in events:
        key = (
            event.get("kind"),
            event.get("source_token"),
            event.get("source_role"),
            event.get("span_index"),
            event.get("evidence_token"),
            event.get("url"),
        )
        if key not in seen:
            seen.add(key)
            result.append(event)
    return result


def boundary_prediction(source_profiles: dict[str, dict]) -> tuple[str, str]:
    nvd = source_profiles["nvd"]
    ghsa = source_profiles["ghsa"]
    nvd_support = bool(nvd["support_events"])
    ghsa_support = bool(ghsa["support_events"])
    nvd_conflict = bool(nvd["contradiction_events"])
    ghsa_conflict = bool(ghsa["contradiction_events"])

    if nvd_conflict and ghsa_conflict:
        return "neither", "both_sources_contradicted_by_boundary_evidence"
    if nvd_conflict and ghsa_support and not ghsa_conflict:
        return "ghsa", "nvd_contradicted_ghsa_supported"
    if ghsa_conflict and nvd_support and not nvd_conflict:
        return "nvd", "ghsa_contradicted_nvd_supported"
    if nvd_support and ghsa_support and not nvd_conflict and not ghsa_conflict:
        return "both", "both_sources_supported_without_boundary_contradiction"
    if nvd_support and not ghsa_support and not nvd_conflict and not ghsa_conflict:
        return "nvd", "only_nvd_has_boundary_support"
    if ghsa_support and not nvd_support and not nvd_conflict and not ghsa_conflict:
        return "ghsa", "only_ghsa_has_boundary_support"
    return "abstain", "insufficient_or_mixed_boundary_evidence"


def extract_release_boundary_features(row: dict) -> dict:
    token_roles = source_token_roles(row)
    claims = extract_evidence_claims(row)
    profiles = {}
    for source in ("nvd", "ghsa"):
        support, direct_contradictions = direct_role_events(
            source, token_roles[source], claims
        )
        contradictions = direct_contradictions + span_contradiction_events(
            source, row, claims
        )
        profiles[source] = {
            "token_roles": {
                token: sorted(roles) for token, roles in sorted(token_roles[source].items())
            },
            "support_events": dedupe_events(support),
            "contradiction_events": dedupe_events(contradictions),
        }
    prediction, reason = boundary_prediction(profiles)
    return {
        "sample_id": row.get("sample_id"),
        "cve_id": row.get("cve_id"),
        "field": "affected_versions",
        "feature_label_is_human": False,
        "feature_extraction_uses_gold": False,
        "evidence_claims": claims,
        "source_profiles": profiles,
        "predicted_source": prediction,
        "prediction_reason": reason,
    }
