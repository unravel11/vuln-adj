#!/usr/bin/env python3
"""Pure, outcome-independent helpers for GHSA accepted-event mapping."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from temporal_provenance_lib import (
    canonical_json,
    project_ghsa_affected,
    project_references,
)


GHSA_ID_RE = re.compile(r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$")
FIX_REFERENCE_TYPES = {"git_commit", "pull_request", "patch"}
AtomCounter = Counter[str]


class AmbiguousProviderObject(ValueError):
    """A provider object cannot be separated under the frozen identity."""


@dataclass(frozen=True)
class FieldDelta:
    added: AtomCounter
    removed: AtomCounter

    @property
    def empty(self) -> bool:
        return not self.added and not self.removed

    def to_dict(self) -> dict[str, dict[str, int]]:
        return {
            "added": dict(sorted(self.added.items())),
            "removed": dict(sorted(self.removed.items())),
        }


def _canonical_affected_entry(projected: dict[str, Any]) -> dict[str, Any]:
    entry = dict(projected)
    entry.pop("position", None)
    ranges = []
    for projected_range in entry.get("ranges") or []:
        range_item = dict(projected_range)
        range_item.pop("position", None)
        normalized_range = dict(range_item)
        # Event order is meaningful and is intentionally not sorted.
        events = []
        for projected_event in normalized_range.get("events") or []:
            event = dict(projected_event)
            event.pop("position", None)
            events.append(event)
        normalized_range["events"] = events
        ranges.append(normalized_range)
    entry["ranges"] = sorted(ranges, key=canonical_json)
    entry["versions"] = sorted(entry.get("versions") or [])
    return entry


def package_key(entry: Mapping[str, Any]) -> tuple[str | None, str | None, str | None]:
    package = entry.get("package") or {}
    return package.get("ecosystem"), package.get("name"), package.get("purl")


def affected_atoms(record: dict[str, Any]) -> AtomCounter:
    atoms: AtomCounter = Counter()
    seen_keys: set[tuple[str | None, str | None, str | None]] = set()
    for projected in project_ghsa_affected(record):
        normalized = _canonical_affected_entry(projected)
        key = package_key(normalized)
        if key in seen_keys:
            raise AmbiguousProviderObject(f"duplicate affected package key: {key}")
        seen_keys.add(key)
        atoms[canonical_json(normalized)] += 1
    return atoms


def reference_atoms(
    record: dict[str, Any], *, fix_only: bool = True
) -> AtomCounter:
    atoms: AtomCounter = Counter()
    for projected in project_references(record.get("references") or []):
        resource_type = projected.get("resource_type")
        if fix_only and resource_type not in FIX_REFERENCE_TYPES:
            continue
        atom = {
            "source_type": projected.get("source_type"),
            "canonical_url": projected.get("canonical_url"),
            "resource_type": resource_type,
        }
        atoms[canonical_json(atom)] += 1
    return atoms


def field_atoms(record: dict[str, Any], field: str) -> AtomCounter:
    if field == "affected":
        return affected_atoms(record)
    if field == "fix_references":
        return reference_atoms(record, fix_only=True)
    raise ValueError(f"unsupported GHSA event field: {field}")


def multiset_delta(before: Mapping[str, int], after: Mapping[str, int]) -> FieldDelta:
    before_counter = Counter(before)
    after_counter = Counter(after)
    return FieldDelta(
        added=after_counter - before_counter,
        removed=before_counter - after_counter,
    )


def delta_intersection(left: FieldDelta, right: FieldDelta) -> FieldDelta:
    return FieldDelta(
        added=left.added & right.added,
        removed=left.removed & right.removed,
    )


def has_direction_conflict(proposal: FieldDelta, main: FieldDelta) -> bool:
    return bool((proposal.added & main.removed) or (proposal.removed & main.added))


def proposal_already_present(
    proposal: FieldDelta,
    proposal_after: Mapping[str, int],
    main_before: Mapping[str, int],
) -> bool:
    desired = Counter(proposal_after)
    before = Counter(main_before)
    changed_atoms = set(proposal.added) | set(proposal.removed)
    return bool(changed_atoms) and all(before[atom] == desired[atom] for atom in changed_atoms)


def classify_delta_relation(
    proposal: FieldDelta,
    main: FieldDelta,
    proposal_after: Mapping[str, int],
    main_before: Mapping[str, int],
) -> str:
    if proposal.empty:
        return "no_proposal_field_delta"
    if proposal_already_present(proposal, proposal_after, main_before):
        return "already_present_before_disposition"
    if proposal == main:
        return "exact"
    if main.empty:
        return "no_field_delta"
    overlap = delta_intersection(proposal, main)
    if not overlap.empty and not has_direction_conflict(proposal, main):
        return "partial"
    return "same_field_nonmatching_or_unlinked"


def verify_delta_stability(
    mapped_after: Mapping[str, int],
    adopted_delta: FieldDelta,
    later_states: Iterable[Mapping[str, int]],
) -> dict[str, Any]:
    after = Counter(mapped_after)
    failures: list[dict[str, Any]] = []
    states_checked = 0
    for state_position, state in enumerate(later_states):
        states_checked += 1
        current = Counter(state)
        lost_additions = {
            atom: after[atom] - current[atom]
            for atom in adopted_delta.added
            if current[atom] < after[atom]
        }
        restored_removals = {
            atom: current[atom] - after[atom]
            for atom in adopted_delta.removed
            if current[atom] > after[atom]
        }
        if lost_additions or restored_removals:
            failures.append(
                {
                    "state_position": state_position,
                    "lost_additions": dict(sorted(lost_additions.items())),
                    "restored_removals": dict(sorted(restored_removals.items())),
                }
            )
    return {
        "status": "stable" if not failures else "reverted_or_overwritten",
        "states_checked": states_checked,
        "failures": failures,
    }


def ghsa_id_from_path(path: str) -> str | None:
    for segment in path.split("/"):
        if GHSA_ID_RE.fullmatch(segment):
            return segment
        if segment.endswith(".json") and GHSA_ID_RE.fullmatch(segment[:-5]):
            return segment[:-5]
    return None


def unique_cve_alias(record: dict[str, Any]) -> str | None:
    aliases = sorted(
        {
            alias
            for alias in record.get("aliases") or []
            if isinstance(alias, str) and alias.startswith("CVE-")
        }
    )
    return aliases[0] if len(aliases) == 1 else None


def event_key(
    *,
    ghsa_id: str,
    package_object_key: tuple[str | None, str | None, str | None] | None,
    field: str,
    disposition_id: str,
    proposal_before_blob: str,
    proposal_after_blob: str,
    main_before_blob: str,
    main_after_blob: str,
) -> str:
    if not GHSA_ID_RE.fullmatch(ghsa_id):
        raise ValueError(f"invalid GHSA ID: {ghsa_id}")
    parts = [
        "github_advisory_database",
        ghsa_id,
        canonical_json(package_object_key),
        field,
        disposition_id,
        proposal_before_blob,
        proposal_after_blob,
        main_before_blob,
        main_after_blob,
    ]
    if any(not isinstance(part, str) or not part for part in parts):
        raise ValueError("event key components must be non-empty strings")
    return "|".join(parts)
