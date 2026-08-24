#!/usr/bin/env python3
"""Conservative package-aware affected-version range diagnostics and predictors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from packaging.version import InvalidVersion, Version


GENERIC_REPOSITORY_NAMES = {
    "advisory-database",
    "cve",
    "cves",
    "poc",
    "pocs",
    "security-advisories",
    "vulnerability-database",
}
GENERIC_REPOSITORY_OWNERS = {"advisories"}
GENERIC_IDENTIFIER_TOKENS = {
    "api",
    "anycpu",
    "arm",
    "arm64",
    "bom",
    "build",
    "client",
    "com",
    "community",
    "core",
    "edition",
    "github",
    "hdri",
    "impl",
    "io",
    "js",
    "main",
    "manager",
    "net",
    "openmp",
    "org",
    "papers",
    "platform",
    "plugin",
    "project",
    "py",
    "q16",
    "q8",
    "readers",
    "release",
    "rest",
    "runtime",
    "sdk",
    "server",
    "service",
    "services",
    "tasks",
    "win",
    "x64",
    "x86",
}


@dataclass(frozen=True)
class ParsedSpan:
    raw: tuple
    point: Version | None
    start: Version | None
    start_inclusive: bool
    end: Version | None
    end_inclusive: bool
    parseable: bool


def normalize_package_name(value: object) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"^pkg:[^/]+/", "", text)
    text = text.replace("_", "-")
    text = re.sub(r"/v\d+$", "", text)
    return text


def compact_package_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", normalize_package_name(value))


def leaf_package_name(value: object) -> str:
    text = normalize_package_name(value)
    for separator in ("/", ":", "\\"):
        if separator in text:
            text = text.split(separator)[-1]
    return compact_package_name(text)


def package_profile(row: dict) -> dict:
    nvd_names = {
        normalize_package_name(value)
        for value in row.get("nvd_context", {}).get("package_names", [])
        if normalize_package_name(value)
    }
    ghsa_names = {
        normalize_package_name(value)
        for value in row.get("ghsa_context", {}).get("package_names", [])
        if normalize_package_name(value)
    }
    nvd_compact = {compact_package_name(value) for value in nvd_names}
    ghsa_compact = {compact_package_name(value) for value in ghsa_names}
    nvd_leaf = {leaf_package_name(value) for value in nvd_names}
    ghsa_leaf = {leaf_package_name(value) for value in ghsa_names}
    exact_overlap = sorted(nvd_names & ghsa_names)
    compact_overlap = sorted((nvd_compact & ghsa_compact) - {""})
    leaf_overlap = sorted((nvd_leaf & ghsa_leaf) - {""})
    if exact_overlap or compact_overlap:
        category = "exact_or_canonical_package_overlap"
    elif leaf_overlap:
        category = "leaf_package_overlap_only"
    elif nvd_names and ghsa_names:
        category = "no_package_name_overlap"
    else:
        category = "missing_package_name"
    return {
        "category": category,
        "nvd_package_names": sorted(nvd_names),
        "ghsa_package_names": sorted(ghsa_names),
        "exact_overlap": exact_overlap,
        "canonical_overlap": compact_overlap,
        "leaf_overlap": leaf_overlap,
    }


def github_repository_roots(references: list[object]) -> dict:
    roots = set()
    excluded_generic = set()
    for value in references or []:
        parsed = urlparse(str(value or "").strip())
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            continue
        parts = [unquote(part).strip().lower() for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            continue
        owner = parts[0]
        repository = parts[1].removesuffix(".git")
        if not owner or not repository:
            continue
        root = f"{owner}/{repository}"
        if (
            owner in GENERIC_REPOSITORY_OWNERS
            or repository in GENERIC_REPOSITORY_NAMES
        ):
            excluded_generic.add(root)
        else:
            roots.add(root)
    return {
        "repositories": sorted(roots),
        "excluded_generic_repositories": sorted(excluded_generic),
    }


def identifier_aliases(value: object) -> set[str]:
    text = str(value or "").strip().lower()
    text = re.sub(r"^pkg:[^/]+/", "", text)
    tokens = re.findall(r"[a-z0-9]+", text)
    informative = [
        token
        for token in tokens
        if token not in GENERIC_IDENTIFIER_TOKENS
        and not re.fullmatch(r"v?\d+", token)
    ]
    aliases = {token for token in informative if len(token) >= 5}
    compact = "".join(informative)
    if len(compact) >= 5:
        aliases.add(compact)
    return aliases


def alias_pairs(package_names: list[object], repository: str) -> list[dict]:
    repository_name = repository.split("/", 1)[-1]
    repository_aliases = identifier_aliases(repository_name)
    matches = []
    for package_name in package_names or []:
        for package_alias in sorted(identifier_aliases(package_name)):
            for repository_alias in sorted(repository_aliases):
                if (
                    package_alias == repository_alias
                    or package_alias in repository_alias
                    or repository_alias in package_alias
                ):
                    matches.append(
                        {
                            "package_name": str(package_name),
                            "package_alias": package_alias,
                            "repository_alias": repository_alias,
                        }
                    )
    return matches


def repository_crosswalk_profile(row: dict) -> dict:
    nvd_names = row.get("nvd_context", {}).get("package_names", [])
    ghsa_names = row.get("ghsa_context", {}).get("package_names", [])
    nvd_repositories = github_repository_roots(
        row.get("nvd_context", {}).get("references", [])
    )
    ghsa_repositories = github_repository_roots(
        row.get("ghsa_context", {}).get("references", [])
    )
    shared = sorted(
        set(nvd_repositories["repositories"])
        & set(ghsa_repositories["repositories"])
    )
    candidates = []
    accepted = []
    conflicts = []
    unanchored = []
    for repository in shared:
        nvd_matches = alias_pairs(nvd_names, repository)
        ghsa_matches = alias_pairs(ghsa_names, repository)
        alternative_nvd = [
            candidate
            for candidate in nvd_repositories["repositories"]
            if candidate not in shared and alias_pairs(nvd_names, candidate)
        ]
        alternative_ghsa = [
            candidate
            for candidate in ghsa_repositories["repositories"]
            if candidate not in shared and alias_pairs(ghsa_names, candidate)
        ]
        if not nvd_matches or not ghsa_matches:
            decision = "reject_unanchored_shared_repository"
            unanchored.append(repository)
        elif alternative_nvd or alternative_ghsa:
            decision = "reject_conflicting_package_repository"
            conflicts.append(repository)
        else:
            decision = "accept_repository_bridge"
            accepted.append(repository)
        candidates.append(
            {
                "repository": repository,
                "decision": decision,
                "nvd_alias_matches": nvd_matches,
                "ghsa_alias_matches": ghsa_matches,
                "alternative_nvd_package_repositories": alternative_nvd,
                "alternative_ghsa_package_repositories": alternative_ghsa,
            }
        )
    if accepted:
        category = "accepted_repository_bridge"
    elif conflicts:
        category = "conflicting_repository_bridge"
    elif shared:
        category = "unanchored_shared_repository"
    else:
        category = "no_shared_repository"
    return {
        "category": category,
        "accepted_repositories": accepted,
        "conflicting_repositories": conflicts,
        "unanchored_repositories": unanchored,
        "shared_repositories": shared,
        "nvd_repository_profile": nvd_repositories,
        "ghsa_repository_profile": ghsa_repositories,
        "candidates": candidates,
    }


def repository_crosswalk_package_profile(row: dict) -> dict:
    direct = package_profile(row)
    repository = repository_crosswalk_profile(row)
    if direct["category"] in {
        "exact_or_canonical_package_overlap",
        "leaf_package_overlap_only",
    }:
        category = direct["category"]
        comparable = True
        decision_reason = "package names overlap without a repository bridge"
    elif repository["category"] == "accepted_repository_bridge":
        category = "repository_crosswalk_overlap"
        comparable = True
        decision_reason = (
            "cross-source package identifiers anchor to the same non-conflicting GitHub repository"
        )
    else:
        category = direct["category"]
        comparable = False
        decision_reason = (
            "package names do not overlap and no non-conflicting repository bridge was established"
        )
    return {
        "category": category,
        "comparable": comparable,
        "decision_reason": decision_reason,
        "direct_package_profile": direct,
        "repository_crosswalk_profile": repository,
    }


def canonical_version_text(value: object) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("v") and len(text) > 1 and text[1].isdigit():
        text = text[1:]
    text = re.sub(r"-p(\d+)$", r".post\1", text, flags=re.I)
    text = re.sub(r"-alpha[.-]?(\d+)$", r"a\1", text, flags=re.I)
    text = re.sub(r"-beta[.-]?(\d+)$", r"b\1", text, flags=re.I)
    text = re.sub(r"-rc[.-]?(\d+)$", r"rc\1", text, flags=re.I)
    text = re.sub(r"[.-]final$", "", text, flags=re.I)
    return text


def parse_version(value: object) -> Version | None:
    text = canonical_version_text(value)
    if not text or text in {"*", "-", "0"}:
        return None
    try:
        return Version(text)
    except InvalidVersion:
        return None


def first_value(span: dict, keys: tuple[str, ...]) -> tuple[str | None, str | None]:
    for key in keys:
        value = span.get(key)
        if value is not None and str(value).strip() not in {"", "*", "-", "0"}:
            return key, str(value).strip()
    return None, None


def parse_span(span: dict) -> ParsedSpan:
    raw = tuple(sorted((key, str(value)) for key, value in span.items() if value))
    start_key, start_text = first_value(
        span,
        ("version_start_including", "introduced", "version_start_excluding"),
    )
    end_key, end_text = first_value(
        span,
        ("version_end_excluding", "fixed", "version_end_including"),
    )
    point_text = str(span.get("version") or "").strip()
    has_range = bool(start_text or end_text)
    point = parse_version(point_text) if point_text and not has_range else None
    start = parse_version(start_text) if start_text else None
    end = parse_version(end_text) if end_text else None
    parseable = not (
        (point_text and not has_range and point is None)
        or (start_text and start is None)
        or (end_text and end is None)
    )
    return ParsedSpan(
        raw=raw,
        point=point,
        start=start,
        start_inclusive=start_key != "version_start_excluding",
        end=end,
        end_inclusive=end_key == "version_end_including",
        parseable=parseable,
    )


def contains(span: ParsedSpan, version: Version) -> bool:
    if not span.parseable:
        return False
    if span.point is not None:
        return span.point == version
    if span.start is not None:
        if version < span.start or (version == span.start and not span.start_inclusive):
            return False
    if span.end is not None:
        if version > span.end or (version == span.end and not span.end_inclusive):
            return False
    return True


def same_interval(left: ParsedSpan, right: ParsedSpan) -> bool:
    return (
        left.parseable
        and right.parseable
        and left.point == right.point
        and left.start == right.start
        and left.start_inclusive == right.start_inclusive
        and left.end == right.end
        and left.end_inclusive == right.end_inclusive
    )


def immediate_release_successor(left: Version, right: Version) -> bool:
    if any(
        (
            left.pre,
            left.post,
            left.dev,
            left.local,
            right.pre,
            right.post,
            right.dev,
            right.local,
        )
    ):
        return False
    left_release = left.release
    right_release = right.release
    return (
        len(left_release) == len(right_release)
        and len(left_release) > 0
        and left_release[:-1] == right_release[:-1]
        and right_release[-1] == left_release[-1] + 1
    )


def successor_boundary_candidate(left: ParsedSpan, right: ParsedSpan) -> bool:
    if not left.parseable or not right.parseable or left.point or right.point:
        return False
    same_start = (
        left.start == right.start
        and left.start_inclusive == right.start_inclusive
    )
    if not same_start or left.end is None or right.end is None:
        return False
    return (
        left.end_inclusive
        and not right.end_inclusive
        and immediate_release_successor(left.end, right.end)
    ) or (
        right.end_inclusive
        and not left.end_inclusive
        and immediate_release_successor(right.end, left.end)
    )


def perfect_matching(
    left: list[ParsedSpan],
    right: list[ParsedSpan],
    predicate,
) -> bool:
    if len(left) != len(right):
        return False
    used = set()

    def match(index: int) -> bool:
        if index == len(left):
            return True
        for right_index, right_span in enumerate(right):
            if right_index in used or not predicate(left[index], right_span):
                continue
            used.add(right_index)
            if match(index + 1):
                return True
            used.remove(right_index)
        return False

    return match(0)


def range_relation(row: dict) -> dict:
    nvd = [parse_span(span) for span in row.get("nvd_value") or []]
    ghsa = [parse_span(span) for span in row.get("ghsa_value") or []]
    if not nvd or not ghsa:
        relation = "missing_spans"
    elif any(not span.parseable for span in [*nvd, *ghsa]):
        relation = "unparseable_spans"
    elif perfect_matching(nvd, ghsa, same_interval):
        relation = "normalized_interval_equivalent"
    elif perfect_matching(
        nvd,
        ghsa,
        lambda left, right: same_interval(left, right)
        or successor_boundary_candidate(left, right),
    ):
        relation = "successor_boundary_candidate"
    else:
        nvd_points = [span.point for span in nvd if span.point is not None]
        ghsa_points = [span.point for span in ghsa if span.point is not None]
        if len(nvd_points) == len(nvd) and all(
            any(contains(span, point) for span in ghsa) for point in nvd_points
        ):
            relation = "nvd_points_within_ghsa_ranges"
        elif len(ghsa_points) == len(ghsa) and all(
            any(contains(span, point) for span in nvd) for point in ghsa_points
        ):
            relation = "ghsa_points_within_nvd_ranges"
        else:
            relation = "not_proven_equivalent"
    return {
        "relation": relation,
        "nvd_span_count": len(nvd),
        "ghsa_span_count": len(ghsa),
        "nvd_parseable_count": sum(span.parseable for span in nvd),
        "ghsa_parseable_count": sum(span.parseable for span in ghsa),
    }


def token_prediction(support: dict[str, dict]) -> str:
    nvd_supported = support["nvd"]["score"] > 0
    ghsa_supported = support["ghsa"]["score"] > 0
    if nvd_supported and ghsa_supported:
        return "both"
    if nvd_supported:
        return "nvd"
    if ghsa_supported:
        return "ghsa"
    return "abstain"


def package_gated_token_prediction(row: dict, support: dict[str, dict]) -> dict:
    packages = package_profile(row)
    ranges = range_relation(row)
    if packages["category"] in {"no_package_name_overlap", "missing_package_name"}:
        prediction = "abstain"
        decision_reason = "package identity is not comparable"
    else:
        prediction = token_prediction(support)
        decision_reason = "package identity is comparable; apply evidence-token support"
    return {
        "predicted_source": prediction,
        "package_profile": packages,
        "range_profile": ranges,
        "support": support,
        "decision_reason": decision_reason,
        "rule": "abstain on package mismatch, otherwise use evidence-token support",
    }


def repository_crosswalk_package_gated_token_prediction(
    row: dict, support: dict[str, dict]
) -> dict:
    packages = repository_crosswalk_package_profile(row)
    ranges = range_relation(row)
    if not packages["comparable"]:
        prediction = "abstain"
        decision_reason = packages["decision_reason"]
    else:
        prediction = token_prediction(support)
        decision_reason = (
            f"{packages['decision_reason']}; apply evidence-token support"
        )
    return {
        "predicted_source": prediction,
        "package_profile": packages,
        "range_profile": ranges,
        "support": support,
        "decision_reason": decision_reason,
        "rule": (
            "use direct package overlap or a non-conflicting shared-repository "
            "crosswalk before applying evidence-token support"
        ),
    }


def package_range_evidence_prediction(row: dict, support: dict[str, dict]) -> dict:
    prediction = package_gated_token_prediction(row, support)
    relation = prediction["range_profile"]["relation"]
    if (
        prediction["package_profile"]["category"]
        not in {"no_package_name_overlap", "missing_package_name"}
        and relation == "normalized_interval_equivalent"
    ):
        prediction["predicted_source"] = "both"
        prediction["decision_reason"] = (
            "package identity is comparable and parsed intervals are identical after normalization; prefer both over one-sided token spelling"
        )
    prediction["rule"] = (
        "package-gated evidence support with exact normalized-range equivalence fallback; syntactic successor boundaries remain diagnostic only"
    )
    return prediction
