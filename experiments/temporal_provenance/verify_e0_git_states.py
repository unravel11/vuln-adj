#!/usr/bin/env python3
"""Independently reparse raw Git states for 20 deterministic E0 CVEs."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


AUDIT_SEED = "temporal-provenance-independent-parser-v1\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        default="experiments/temporal_provenance/e0_sample_v1.json",
    )
    parser.add_argument(
        "--git-states-dir",
        default="data/processed/temporal_provenance/pilot_v1/e0_git_states",
    )
    parser.add_argument(
        "--output",
        default=(
            "results/temporal_provenance/pilot_v1/e0_replay/"
            "independent_parser_verification.json"
        ),
    )
    return parser.parse_args()


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def select_cves(sample: dict[str, Any], count: int = 20) -> list[str]:
    cve_ids = sorted(row["cve_id"] for row in sample["rows"])
    if len(cve_ids) < count:
        raise ValueError(f"Need at least {count} E0 CVEs")
    return sorted(
        cve_ids,
        key=lambda cve_id: hashlib.sha256(
            f"{AUDIT_SEED}{cve_id}".encode("utf-8")
        ).hexdigest(),
    )[:count]


def raw_references(references: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "raw_url": item.get("url"),
            "source_type": item.get("type"),
            "source": item.get("source"),
            "tags": sorted(item.get("tags") or []),
        }
        for item in references or []
    ]


def projected_references(references: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "raw_url": item.get("raw_url"),
            "source_type": item.get("source_type"),
            "source": item.get("source"),
            "tags": sorted(item.get("tags") or []),
        }
        for item in references or []
    ]


def raw_ghsa_summary(record: dict[str, Any]) -> dict[str, Any]:
    affected = []
    for item in record.get("affected") or []:
        package = item.get("package") or {}
        ranges = []
        for range_item in item.get("ranges") or []:
            ranges.append(
                {
                    "type": range_item.get("type"),
                    "repo": range_item.get("repo"),
                    "events": [
                        {key: event[key] for key in sorted(event)}
                        for event in range_item.get("events") or []
                    ],
                    "database_specific": range_item.get("database_specific") or {},
                }
            )
        affected.append(
            {
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
    return {
        "id": record.get("id"),
        "aliases": sorted(record.get("aliases") or []),
        "affected": affected,
        "references": raw_references(record.get("references") or []),
    }


def projected_ghsa_summary(projection: dict[str, Any]) -> dict[str, Any]:
    affected = []
    for item in projection.get("affected") or []:
        affected.append(
            {
                "package": item.get("package") or {},
                "ranges": [
                    {
                        "type": range_item.get("type"),
                        "repo": range_item.get("repo"),
                        "events": [
                            event.get("values") or {}
                            for event in range_item.get("events") or []
                        ],
                        "database_specific": range_item.get("database_specific") or {},
                    }
                    for range_item in item.get("ranges") or []
                ],
                "versions": list(item.get("versions") or []),
                "ecosystem_specific": item.get("ecosystem_specific") or {},
                "database_specific": item.get("database_specific") or {},
            }
        )
    return {
        "id": projection.get("id"),
        "aliases": sorted(projection.get("aliases") or []),
        "affected": affected,
        "references": projected_references(projection.get("references") or []),
    }


def walk_raw_nvd_nodes(
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
        yield from walk_raw_nvd_nodes(node.get("children") or [], node_path)


def raw_nvd_summary(record: dict[str, Any]) -> dict[str, Any]:
    matches = []
    for configuration_position, configuration in enumerate(
        record.get("configurations") or []
    ):
        for match in walk_raw_nvd_nodes(configuration.get("nodes") or []):
            matches.append(
                {"configuration_position": configuration_position, **match}
            )
    return {
        "id": record.get("id"),
        "cpe_configurations": matches,
        "top_level_affected": [
            {
                "source": item.get("source"),
                "affected_data": item.get("affectedData"),
            }
            for item in record.get("affected") or []
        ],
        "references": raw_references(record.get("references") or []),
    }


def projected_nvd_summary(projection: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": projection.get("id"),
        "cpe_configurations": list(projection.get("cpe_configurations") or []),
        "top_level_affected": [
            {
                "source": item.get("source"),
                "affected_data": item.get("affected_data"),
            }
            for item in projection.get("top_level_affected") or []
        ],
        "references": projected_references(projection.get("references") or []),
    }


def raw_cvelist_summary(record: dict[str, Any]) -> dict[str, Any]:
    metadata = record.get("cveMetadata") or {}
    containers = record.get("containers") or {}
    source_containers = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        source_containers.append(("cna", 0, cna))
    source_containers.extend(
        ("adp", position, item)
        for position, item in enumerate(containers.get("adp") or [])
        if isinstance(item, dict)
    )
    projected = []
    for container_type, position, container in source_containers:
        affected = []
        for item in container.get("affected") or []:
            affected.append(
                {
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
        projected.append(
            {
                "container_type": container_type,
                "position": position,
                "provider_org_id": (container.get("providerMetadata") or {}).get(
                    "orgId"
                ),
                "affected": affected,
                "references": raw_references(container.get("references") or []),
            }
        )
    return {"cve_id": metadata.get("cveId"), "containers": projected}


def projected_cvelist_summary(projection: dict[str, Any]) -> dict[str, Any]:
    containers = []
    for container in projection.get("containers") or []:
        containers.append(
            {
                "container_type": container.get("container_type"),
                "position": container.get("position"),
                "provider_org_id": container.get("provider_org_id"),
                "affected": [
                    {
                        key: value
                        for key, value in item.items()
                        if key != "position"
                    }
                    for item in container.get("affected") or []
                ],
                "references": projected_references(
                    container.get("references") or []
                ),
            }
        )
    return {"cve_id": projection.get("cve_id"), "containers": containers}


def summaries(
    source: str, record: dict[str, Any], projection: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if source == "ghsa_advisory_database":
        return raw_ghsa_summary(record), projected_ghsa_summary(projection)
    if source == "fkie_nvd_json_data_feeds":
        return raw_nvd_summary(record), projected_nvd_summary(projection)
    if source == "cvelist_v5":
        return raw_cvelist_summary(record), projected_cvelist_summary(projection)
    raise ValueError(f"Unsupported source: {source}")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}") from exc
    return rows


def verify(
    sample: dict[str, Any], git_states_dir: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    selected = select_cves(sample)
    selected_set = set(selected)
    failures = []
    status_counts: Counter[tuple[str, str, str]] = Counter()
    audited_present = 0
    for source, relative_path in manifest["source_files"].items():
        for row in read_jsonl(git_states_dir / relative_path):
            if row["cve_id"] not in selected_set:
                continue
            status_counts[(source, row["snapshot"], row["status"])] += 1
            if row["status"] != "present":
                continue
            audited_present += 1
            raw_blob = git_states_dir / row["raw_blob"]
            if not raw_blob.is_file():
                failures.append({**row_identity(row), "reason": "raw_blob_missing"})
                continue
            raw = raw_blob.read_bytes()
            if sha256_bytes(raw) != row["raw_sha256"]:
                failures.append({**row_identity(row), "reason": "raw_sha256_mismatch"})
                continue
            try:
                record = json.loads(raw)
                raw_summary, projected_summary = summaries(
                    source, record, row["projection"]
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                failures.append(
                    {
                        **row_identity(row),
                        "reason": "independent_parse_error",
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            if canonical(raw_summary) != canonical(projected_summary):
                failures.append(
                    {**row_identity(row), "reason": "projection_summary_mismatch"}
                )
    current_presence = {
        source: status_counts[(source, "current", "present")]
        for source in manifest["source_files"]
    }
    pass_status = (
        audited_present > 0
        and not failures
        and all(count == len(selected) for count in current_presence.values())
    )
    return {
        "schema_version": "temporal-provenance-e0-independent-parser-v1",
        "status": "pass" if pass_status else "stop",
        "selection_seed": AUDIT_SEED.rstrip("\n"),
        "selected_cves": selected,
        "selected_count": len(selected),
        "audited_present_states": audited_present,
        "current_present_by_source": current_presence,
        "status_counts": [
            {
                "source": source,
                "snapshot": snapshot,
                "status": status,
                "count": count,
            }
            for (source, snapshot, status), count in sorted(status_counts.items())
        ],
        "failures": failures,
        "claim_ceiling": "independent_structural_reparse_not_semantic_truth",
    }


def row_identity(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": row.get("source"),
        "snapshot": row.get("snapshot"),
        "cve_id": row.get("cve_id"),
        "path": row.get("path"),
    }


def main() -> int:
    args = parse_args()
    sample_path = Path(args.sample).resolve()
    git_states_dir = Path(args.git_states_dir).resolve()
    output = Path(args.output).resolve()
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    manifest = json.loads(
        (git_states_dir / "manifest.json").read_text(encoding="utf-8")
    )
    result = verify(sample, git_states_dir, manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(
        f"Independent parser: {result['status']} "
        f"({result['audited_present_states']} present states)"
    )
    print(f"Verification: {output}")
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
