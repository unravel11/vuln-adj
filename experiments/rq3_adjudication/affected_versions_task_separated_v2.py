#!/usr/bin/env python3
"""Post-v2 development candidate for task-separated affected-version typing."""

from __future__ import annotations

from affected_versions_task_separated import (
    contradiction_count,
    structured_range_set_relation,
)
from affected_versions_branch_graph import extract_branch_graph_features
from affected_versions_semantic_baseline import (
    range_relation,
    repository_crosswalk_package_profile,
)


def predict_discrepancy_type_v2(row: dict) -> dict:
    package = repository_crosswalk_package_profile(row)
    legacy = range_relation(row)
    structured = structured_range_set_relation(row)
    branch = extract_branch_graph_features(row)
    contradictions = contradiction_count(branch)
    relation = structured["relation"]

    if not package["comparable"]:
        label, status, reason = (
            "uncertain",
            "abstain",
            "package_identity_not_comparable",
        )
    elif legacy["relation"] == "normalized_interval_equivalent":
        label, status, reason = (
            "equivalent",
            "determinate",
            "exact_normalized_interval_equality",
        )
    elif relation == "mutual_semantic_coverage" or legacy["relation"] == "successor_boundary_candidate":
        label, status, reason = (
            "representation_discrepancy",
            "determinate",
            "mutual_coverage_or_successor_representation",
        )
    elif relation == "disjoint_parseable_sets":
        label, status, reason = (
            "factual_conflict",
            "determinate",
            "disjoint_parseable_range_sets",
        )
    elif relation == "ghsa_strict_superset" and contradictions == 0:
        label, status, reason = (
            "representation_discrepancy",
            "determinate",
            "ghsa_range_superset_without_boundary_contradiction",
        )
    elif relation == "partial_overlap_without_containment" and contradictions > 0:
        label, status, reason = (
            "incomplete",
            "determinate",
            "partial_overlap_with_boundary_evidence_gap",
        )
    elif relation == "nvd_strict_superset" and contradictions == 0:
        label, status, reason = (
            "factual_conflict",
            "determinate",
            "nvd_superset_without_compatible_representation_evidence",
        )
    else:
        label, status, reason = (
            "uncertain",
            "abstain",
            "structural_relation_remains_label_ambiguous",
        )
    return {
        "predicted_discrepancy_label": label,
        "type_prediction_status": status,
        "type_prediction_reason": reason,
        "package_profile": package,
        "legacy_range_profile": legacy,
        "structured_range_profile": structured,
        "boundary_contradiction_count": contradictions,
        "rule": (
            "post-v2 structural candidate: exact/mutual/successor representation, "
            "disjoint FC, and selective directional superset/partial-overlap rules"
        ),
    }
