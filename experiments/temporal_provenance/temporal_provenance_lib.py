#!/usr/bin/env python3
"""Shared, loss-aware helpers for the temporal provenance pilot.

The projections here intentionally differ from the legacy bootstrap schema.
They preserve all GHSA range events and keep NVD CPE configurations separate
from the newer top-level CVE ``affected`` payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


CVE_RE = re.compile(r"^CVE-(?P<year>[0-9]{4})-(?P<number>[0-9]{4,})$")
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def parse_utc(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_cve_id(value: object) -> bool:
    return isinstance(value, str) and CVE_RE.fullmatch(value) is not None


def fkie_nvd_path(cve_id: str) -> str:
    match = CVE_RE.fullmatch(cve_id)
    if match is None:
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    number = match.group("number")
    bucket = number[:-2] + "xx"
    return f"CVE-{match.group('year')}/CVE-{match.group('year')}-{bucket}/{cve_id}.json"


def cvelist_v5_path(cve_id: str) -> str:
    match = CVE_RE.fullmatch(cve_id)
    if match is None:
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    number = int(match.group("number"))
    bucket = f"{number // 1000}xxx"
    return f"cves/{match.group('year')}/{bucket}/{cve_id}.json"


def canonicalize_url(raw_url: object) -> str | None:
    if not isinstance(raw_url, str) or not raw_url.strip():
        return None
    value = raw_url.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    ):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if host in GIT_HOSTS and path.endswith(".git"):
        path = path[:-4]
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def classify_reference_url(canonical_url: str | None) -> str:
    if canonical_url is None:
        return "missing"
    try:
        parts = urlsplit(canonical_url)
    except ValueError:
        return "other"
    host = (parts.hostname or "").lower()
    segments = [segment for segment in parts.path.split("/") if segment]
    if host == "github.com" and len(segments) >= 4:
        marker = segments[2]
        if marker in {"commit", "commits"}:
            return "git_commit"
        if marker == "pull":
            return "pull_request"
        if marker == "issues":
            return "issue"
        if marker in {"compare", "releases"}:
            return marker
    if host == "gitlab.com" and "-/commit" in parts.path:
        return "git_commit"
    if host == "gitlab.com" and "-/merge_requests" in parts.path:
        return "pull_request"
    if parts.path.endswith((".patch", ".diff")):
        return "patch"
    return "other"


def project_references(references: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    projected = []
    for position, reference in enumerate(references or []):
        raw_url = reference.get("url")
        canonical_url = canonicalize_url(raw_url)
        projected.append(
            {
                "position": position,
                "raw_url": raw_url,
                "canonical_url": canonical_url,
                "source_type": reference.get("type"),
                "resource_type": classify_reference_url(canonical_url),
                "source": reference.get("source"),
                "tags": sorted(reference.get("tags") or []),
            }
        )
    return projected


def project_ghsa_affected(record: dict[str, Any]) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for item_position, item in enumerate(record.get("affected") or []):
        package = item.get("package") or {}
        ranges = []
        for range_position, range_item in enumerate(item.get("ranges") or []):
            events = []
            for event_position, event in enumerate(range_item.get("events") or []):
                events.append(
                    {
                        "position": event_position,
                        "values": {key: event[key] for key in sorted(event)},
                    }
                )
            ranges.append(
                {
                    "position": range_position,
                    "type": range_item.get("type"),
                    "repo": range_item.get("repo"),
                    "events": events,
                    "database_specific": range_item.get("database_specific") or {},
                }
            )
        projected.append(
            {
                "position": item_position,
                "package": {
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                    "purl": package.get("purl"),
                },
                "ranges": ranges,
                "versions": list(item.get("versions") or []),
                "ecosystem_specific": item.get("ecosystem_specific") or {},
                "database_specific": item.get("database_specific") or {},
            }
        )
    return projected


def _walk_nvd_nodes(
    nodes: Iterable[dict[str, Any]], path: tuple[int, ...] = ()
) -> Iterable[dict[str, Any]]:
    for node_position, node in enumerate(nodes or []):
        node_path = path + (node_position,)
        for match_position, match in enumerate(node.get("cpeMatch") or []):
            yield {
                "node_path": list(node_path),
                "match_position": match_position,
                "operator": node.get("operator"),
                "negate": node.get("negate"),
                "vulnerable": match.get("vulnerable"),
                "criteria": match.get("criteria"),
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
                "match_criteria_id": match.get("matchCriteriaId"),
            }
        yield from _walk_nvd_nodes(node.get("children") or [], node_path)


def project_nvd_cpe_configurations(record: dict[str, Any]) -> list[dict[str, Any]]:
    projected = []
    for config_position, configuration in enumerate(record.get("configurations") or []):
        for match in _walk_nvd_nodes(configuration.get("nodes") or []):
            projected.append({"configuration_position": config_position, **match})
    return projected


def project_nvd_top_level_affected(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve the 2026 CVE-record affected payload as a distinct lineage."""
    projected = []
    for position, item in enumerate(record.get("affected") or []):
        projected.append(
            {
                "position": position,
                "source": item.get("source"),
                "affected_data": item.get("affectedData"),
            }
        )
    return projected


def project_ghsa_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "aliases": sorted(record.get("aliases") or []),
        "published": record.get("published"),
        "modified": record.get("modified"),
        "withdrawn": record.get("withdrawn"),
        "affected": project_ghsa_affected(record),
        "references": project_references(record.get("references") or []),
    }


def project_nvd_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "source_identifier": record.get("sourceIdentifier"),
        "published": record.get("published"),
        "last_modified": record.get("lastModified"),
        "vuln_status": record.get("vulnStatus"),
        "cpe_configurations": project_nvd_cpe_configurations(record),
        "top_level_affected": project_nvd_top_level_affected(record),
        "references": project_references(record.get("references") or []),
    }


def project_cvelist_v5_record(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("cveMetadata") or {}
    containers = record.get("containers") or {}
    projected_containers = []
    raw_containers = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        raw_containers.append(("cna", 0, cna))
    for position, adp in enumerate(containers.get("adp") or []):
        if isinstance(adp, dict):
            raw_containers.append(("adp", position, adp))
    for container_type, position, container in raw_containers:
        provider = (container.get("providerMetadata") or {}).get("orgId")
        affected = []
        for affected_position, item in enumerate(container.get("affected") or []):
            affected.append(
                {
                    "position": affected_position,
                    "vendor": item.get("vendor"),
                    "product": item.get("product"),
                    "package_name": item.get("packageName"),
                    "collection_url": item.get("collectionURL"),
                    "repo": item.get("repo"),
                    "default_status": item.get("defaultStatus"),
                    "versions": item.get("versions") or [],
                    "modules": item.get("modules") or [],
                    "platforms": item.get("platforms") or [],
                    "program_files": item.get("programFiles") or [],
                    "program_routines": item.get("programRoutines") or [],
                }
            )
        projected_containers.append(
            {
                "container_type": container_type,
                "position": position,
                "provider_org_id": provider,
                "date_public": container.get("datePublic"),
                "affected": affected,
                "references": project_references(container.get("references") or []),
            }
        )
    return {
        "cve_id": metadata.get("cveId"),
        "state": metadata.get("state"),
        "assigner_org_id": metadata.get("assignerOrgId"),
        "date_published": metadata.get("datePublished"),
        "date_updated": metadata.get("dateUpdated"),
        "date_reserved": metadata.get("dateReserved"),
        "containers": projected_containers,
    }
