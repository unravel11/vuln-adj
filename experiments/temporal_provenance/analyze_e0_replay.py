#!/usr/bin/env python3
"""Apply the current-state replay gate, then summarize historical E0 states."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SNAPSHOT_ORDER = [
    "2024-01-01T00:00:00Z",
    "2025-01-01T00:00:00Z",
    "2026-05-31T00:00:00Z",
    "current",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--git-states-dir",
        default="data/processed/temporal_provenance/pilot_v1/e0_git_states",
    )
    parser.add_argument(
        "--nvd-current-dir",
        default="data/processed/temporal_provenance/pilot_v1/e0_nvd_current",
    )
    parser.add_argument(
        "--output",
        default="results/temporal_provenance/pilot_v1/e0_replay/analysis.json",
    )
    return parser.parse_args()


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


def nvd_cpe_semantics(projection: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for match in projection.get("cpe_configurations") or []:
        result.append(
            {
                key: value
                for key, value in match.items()
                if key != "match_criteria_id"
            }
        )
    return result


def reference_semantics(projection: dict[str, Any]) -> list[dict[str, Any]]:
    projected = [
        {
            "canonical_url": item.get("canonical_url"),
            "resource_type": item.get("resource_type"),
            "source_type": item.get("source_type"),
            "source": item.get("source"),
            "tags": item.get("tags") or [],
        }
        for item in projection.get("references") or []
    ]
    projected.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return projected


def cvelist_affected_semantics(projection: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "container_type": container.get("container_type"),
            "position": container.get("position"),
            "provider_org_id": container.get("provider_org_id"),
            "affected": container.get("affected") or [],
        }
        for container in projection.get("containers") or []
    ]


def cvelist_reference_semantics(projection: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "container_type": container.get("container_type"),
            "position": container.get("position"),
            "provider_org_id": container.get("provider_org_id"),
            "references": reference_semantics(
                {"references": container.get("references") or []}
            ),
        }
        for container in projection.get("containers") or []
    ]


def field_value(source: str, projection: dict[str, Any], field: str) -> Any:
    if source == "ghsa_advisory_database":
        if field == "references":
            return reference_semantics(projection)
        return projection.get(field)
    if source == "fkie_nvd_json_data_feeds":
        if field == "affected":
            return nvd_cpe_semantics(projection)
        if field == "top_level_affected":
            return projection.get("top_level_affected") or []
        if field == "references":
            return reference_semantics(projection)
    if source == "cvelist_v5":
        if field == "affected":
            return cvelist_affected_semantics(projection)
        if field == "references":
            return cvelist_reference_semantics(projection)
    raise ValueError(f"Unsupported source/field: {source}/{field}")


def current_gate(
    git_rows: dict[str, list[dict[str, Any]]],
    nvd_current_rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    current_presence = {}
    current_by_source: dict[str, dict[str, dict[str, Any]]] = {}
    for source, rows in git_rows.items():
        current = [row for row in rows if row.get("snapshot") == "current"]
        present = [row for row in current if row.get("status") == "present"]
        current_presence[source] = {
            "expected": len(current),
            "present": len(present),
            "non_present": len(current) - len(present),
        }
        current_by_source[source] = {row["cve_id"]: row for row in present}

    official = {row["cve_id"]: row for row in nvd_current_rows}
    mirror = current_by_source["fkie_nvd_json_data_feeds"]
    cve_ids = sorted(set(official) | set(mirror))
    comparisons = []
    for cve_id in cve_ids:
        official_row = official.get(cve_id)
        mirror_row = mirror.get(cve_id)
        if official_row is None or mirror_row is None:
            comparisons.append(
                {
                    "cve_id": cve_id,
                    "both_present": False,
                    "exact_projection": False,
                    "cpe_semantic": False,
                    "reference_semantic": False,
                    "top_level_affected": False,
                }
            )
            continue
        official_projection = official_row["projection"]
        mirror_projection = mirror_row["projection"]
        comparisons.append(
            {
                "cve_id": cve_id,
                "both_present": True,
                "exact_projection": official_projection == mirror_projection,
                "cpe_semantic": nvd_cpe_semantics(official_projection)
                == nvd_cpe_semantics(mirror_projection),
                "reference_semantic": reference_semantics(official_projection)
                == reference_semantics(mirror_projection),
                "top_level_affected": official_projection.get("top_level_affected")
                == mirror_projection.get("top_level_affected"),
                "official_last_modified": official_projection.get("last_modified"),
                "mirror_last_modified": mirror_projection.get("last_modified"),
            }
        )
    comparison_counts = {
        key: sum(1 for row in comparisons if row[key])
        for key in (
            "both_present",
            "exact_projection",
            "cpe_semantic",
            "reference_semantic",
            "top_level_affected",
        )
    }
    git_presence_pass = all(
        values["expected"] == 100 and values["present"] == 100
        for values in current_presence.values()
    )
    nvd_projection_pass = (
        len(comparisons) == 100
        and comparison_counts["cpe_semantic"] == 100
        and comparison_counts["reference_semantic"] == 100
    )
    return {
        "status": "pass" if git_presence_pass and nvd_projection_pass else "stop",
        "git_current_presence": current_presence,
        "nvd_official_vs_fkie_current": {
            "comparisons": len(comparisons),
            "counts": comparison_counts,
            "mismatches": [
                row
                for row in comparisons
                if not row["cpe_semantic"] or not row["reference_semantic"]
            ],
        },
        "rules": {
            "e0_git_presence": "100/100 per source",
            "nvd_cpe_semantic": "100/100",
            "nvd_reference_semantic": "100/100",
            "nvd_top_level_affected": "audit_only_exact_history_no_go",
        },
    }


def historical_summary(
    git_rows: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    result = {}
    source_fields = {
        "ghsa_advisory_database": ("affected", "references"),
        "cvelist_v5": ("affected", "references"),
        "fkie_nvd_json_data_feeds": (
            "affected",
            "references",
            "top_level_affected",
        ),
    }
    for source, rows in git_rows.items():
        by_snapshot: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        for row in rows:
            by_snapshot[row["snapshot"]][row["cve_id"]] = row
        snapshot_counts = []
        alias_counts = []
        for snapshot in SNAPSHOT_ORDER:
            snapshot_rows = list(by_snapshot.get(snapshot, {}).values())
            statuses = Counter(row["status"] for row in snapshot_rows)
            snapshot_counts.append(
                {"snapshot": snapshot, **dict(sorted(statuses.items()))}
            )
            if source == "ghsa_advisory_database":
                present = [row for row in snapshot_rows if row["status"] == "present"]
                alias_counts.append(
                    {
                        "snapshot": snapshot,
                        "present": len(present),
                        "as_of_alias_contains_cve": sum(
                            1
                            for row in present
                            if row["cve_id"] in (row["projection"].get("aliases") or [])
                        ),
                    }
                )
        transitions = []
        for previous, current in zip(SNAPSHOT_ORDER, SNAPSHOT_ORDER[1:]):
            previous_rows = by_snapshot.get(previous, {})
            current_rows = by_snapshot.get(current, {})
            both_present = [
                cve_id
                for cve_id in sorted(set(previous_rows) & set(current_rows))
                if previous_rows[cve_id]["status"] == "present"
                and current_rows[cve_id]["status"] == "present"
            ]
            transition = {
                "from": previous,
                "to": current,
                "both_present": len(both_present),
                "fields": {},
            }
            for field in source_fields[source]:
                changed = sum(
                    1
                    for cve_id in both_present
                    if field_value(source, previous_rows[cve_id]["projection"], field)
                    != field_value(source, current_rows[cve_id]["projection"], field)
                )
                transition["fields"][field] = {"changed": changed}
            transitions.append(transition)
        result[source] = {
            "snapshot_status_counts": snapshot_counts,
            "as_of_alias_audit": alias_counts,
            "transitions": transitions,
        }
    return result


def main() -> int:
    args = parse_args()
    git_states_dir = Path(args.git_states_dir).resolve()
    nvd_current_dir = Path(args.nvd_current_dir).resolve()
    output = Path(args.output).resolve()
    git_manifest = json.loads(
        (git_states_dir / "manifest.json").read_text(encoding="utf-8")
    )
    nvd_manifest = json.loads(
        (nvd_current_dir / "manifest.json").read_text(encoding="utf-8")
    )
    if nvd_manifest.get("status") != "complete":
        raise ValueError("Official NVD current acquisition is incomplete")
    git_rows = {
        source: read_jsonl(git_states_dir / relative_path)
        for source, relative_path in git_manifest["source_files"].items()
    }
    nvd_current_rows = read_jsonl(
        nvd_current_dir / nvd_manifest["records_file"]
    )
    gate = current_gate(git_rows, nvd_current_rows)
    analysis = {
        "schema_version": "temporal-provenance-e0-replay-analysis-v1",
        "status": "stop_current_replay" if gate["status"] != "pass" else "pass_e0_replay",
        "claim_ceiling": "engineering_replay_and_observable_state_drift_only",
        "current_replay_gate": gate,
        "historical_summary": None,
    }
    if gate["status"] == "pass":
        analysis["historical_summary"] = historical_summary(git_rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(analysis, indent=2, ensure_ascii=False) + "\n")
    print(f"E0 replay: {analysis['status']}")
    print(
        "NVD CPE/references: "
        f"{gate['nvd_official_vs_fkie_current']['counts']['cpe_semantic']}/"
        f"{gate['nvd_official_vs_fkie_current']['counts']['reference_semantic']}"
    )
    print(f"Analysis: {output}")
    return 0 if analysis["status"] == "pass_e0_replay" else 2


if __name__ == "__main__":
    raise SystemExit(main())
