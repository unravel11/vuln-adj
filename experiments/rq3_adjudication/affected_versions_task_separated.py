#!/usr/bin/env python3
"""Gold-blind, task-separated affected-version typing and FC source prediction."""

from __future__ import annotations

from affected_versions_branch_graph import extract_branch_graph_features
from affected_versions_semantic_baseline import (
    ParsedSpan,
    contains,
    parse_span,
    range_relation,
    repository_crosswalk_package_profile,
)


def lower_bound_covers(container: ParsedSpan, target: ParsedSpan) -> bool:
    if container.start is None:
        return True
    if target.start is None:
        return False
    if container.start < target.start:
        return True
    if container.start > target.start:
        return False
    return container.start_inclusive or not target.start_inclusive


def upper_bound_covers(container: ParsedSpan, target: ParsedSpan) -> bool:
    if container.end is None:
        return True
    if target.end is None:
        return False
    if container.end > target.end:
        return True
    if container.end < target.end:
        return False
    return container.end_inclusive or not target.end_inclusive


def span_covers(container: ParsedSpan, target: ParsedSpan) -> bool:
    if not container.parseable or not target.parseable:
        return False
    if target.point is not None:
        return contains(container, target.point)
    if container.point is not None:
        return False
    return lower_bound_covers(container, target) and upper_bound_covers(container, target)


def spans_overlap(left: ParsedSpan, right: ParsedSpan) -> bool:
    if not left.parseable or not right.parseable:
        return False
    if left.point is not None:
        return contains(right, left.point)
    if right.point is not None:
        return contains(left, right.point)

    if left.end is not None and right.start is not None:
        if left.end < right.start:
            return False
        if left.end == right.start and not (left.end_inclusive and right.start_inclusive):
            return False
    if right.end is not None and left.start is not None:
        if right.end < left.start:
            return False
        if right.end == left.start and not (right.end_inclusive and left.start_inclusive):
            return False
    return True


def union_covers(containers: list[ParsedSpan], targets: list[ParsedSpan]) -> bool:
    return bool(containers) and bool(targets) and all(
        any(span_covers(container, target) for container in containers)
        for target in targets
    )


def serialize_span(span: ParsedSpan) -> dict:
    return {
        "raw": [list(item) for item in span.raw],
        "point": str(span.point) if span.point is not None else None,
        "start": str(span.start) if span.start is not None else None,
        "start_inclusive": span.start_inclusive,
        "end": str(span.end) if span.end is not None else None,
        "end_inclusive": span.end_inclusive,
        "parseable": span.parseable,
    }


def structured_range_set_relation(row: dict) -> dict:
    nvd = [parse_span(span) for span in row.get("nvd_value") or []]
    ghsa = [parse_span(span) for span in row.get("ghsa_value") or []]
    parseable = bool(nvd and ghsa) and all(span.parseable for span in [*nvd, *ghsa])
    if not nvd or not ghsa:
        relation = "missing_spans"
    elif not parseable:
        relation = "unparseable_spans"
    else:
        nvd_covers_ghsa = union_covers(nvd, ghsa)
        ghsa_covers_nvd = union_covers(ghsa, nvd)
        any_overlap = any(spans_overlap(left, right) for left in nvd for right in ghsa)
        if nvd_covers_ghsa and ghsa_covers_nvd:
            relation = "mutual_semantic_coverage"
        elif nvd_covers_ghsa:
            relation = "nvd_strict_superset"
        elif ghsa_covers_nvd:
            relation = "ghsa_strict_superset"
        elif any_overlap:
            relation = "partial_overlap_without_containment"
        else:
            relation = "disjoint_parseable_sets"
    return {
        "relation": relation,
        "parseable": parseable,
        "nvd_span_count": len(nvd),
        "ghsa_span_count": len(ghsa),
        "nvd_spans": [serialize_span(span) for span in nvd],
        "ghsa_spans": [serialize_span(span) for span in ghsa],
    }


def contradiction_count(branch: dict) -> int:
    return sum(
        len(branch.get("source_profiles", {}).get(source, {}).get("contradiction_events", []))
        for source in ("nvd", "ghsa")
    )


def predict_discrepancy_type(row: dict) -> dict:
    package = repository_crosswalk_package_profile(row)
    legacy_range = range_relation(row)
    structured_range = structured_range_set_relation(row)
    branch = extract_branch_graph_features(row)
    contradictions = contradiction_count(branch)

    if not package["comparable"]:
        label = "uncertain"
        status = "abstain"
        reason = "package_identity_not_comparable"
    elif legacy_range["relation"] == "normalized_interval_equivalent":
        label = "equivalent"
        status = "determinate"
        reason = "same_package_exact_normalized_interval_equality"
    elif structured_range["relation"] == "mutual_semantic_coverage":
        label = "representation_discrepancy"
        status = "determinate"
        reason = "same_package_mutual_semantic_range_coverage"
    elif legacy_range["relation"] == "successor_boundary_candidate":
        label = "representation_discrepancy"
        status = "determinate"
        reason = f"same_package_{legacy_range['relation']}"
    elif (
        structured_range["relation"]
        in {"partial_overlap_without_containment", "disjoint_parseable_sets"}
        and contradictions > 0
    ):
        label = "factual_conflict"
        status = "determinate"
        reason = "same_package_incompatible_range_sets_with_explicit_boundary_contradiction"
    else:
        label = "uncertain"
        status = "abstain"
        reason = "range_relation_or_evidence_insufficient_for_determinate_type"

    return {
        "predicted_discrepancy_label": label,
        "type_prediction_status": status,
        "type_prediction_reason": reason,
        "package_profile": package,
        "legacy_range_profile": legacy_range,
        "structured_range_profile": structured_range,
        "boundary_contradiction_count": contradictions,
        "branch_prediction": branch["predicted_source"],
        "rule": (
            "package-local range-set relation; determinate RD only for mutual coverage or "
            "successor boundaries, and determinate FC only for partial/disjoint sets with "
            "explicit boundary contradiction"
        ),
    }


def predict_fc_source(row: dict, type_prediction: dict | None = None) -> dict:
    type_prediction = type_prediction or predict_discrepancy_type(row)
    if type_prediction["predicted_discrepancy_label"] != "factual_conflict":
        return {
            "predicted_source": "not_applicable",
            "source_prediction_status": "not_applicable",
            "source_prediction_reason": "source adjudication is defined only for factual conflicts",
            "rule": "conditional FC-only source adjudication",
        }

    return predict_fc_source_head(row)


def predict_fc_source_head(row: dict) -> dict:
    """Predict source support for a gold-defined FC population without a type gate."""
    branch = extract_branch_graph_features(row)
    source = branch["predicted_source"]
    if source == "abstain":
        status = "abstain"
        reason = "boundary evidence cannot select a source on the FC evaluation population"
    else:
        status = "determinate"
        reason = branch["prediction_reason"]
    return {
        "predicted_source": source,
        "source_prediction_status": status,
        "source_prediction_reason": reason,
        "rule": "branch-boundary source head evaluated only on the gold-defined FC population",
    }


def predict_tasks(row: dict) -> dict:
    type_prediction = predict_discrepancy_type(row)
    source_prediction = predict_fc_source(row, type_prediction)
    source_head = predict_fc_source_head(row)
    return {
        "type": type_prediction,
        "source": source_prediction,
        "source_head": source_head,
    }
