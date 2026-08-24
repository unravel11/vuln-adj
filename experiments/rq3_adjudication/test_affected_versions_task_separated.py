#!/usr/bin/env python3

from __future__ import annotations

import unittest
from unittest.mock import patch

import affected_versions_task_separated as target
from affected_versions_semantic_baseline import parse_span


def span(**values: str) -> dict:
    result = {
        "version": None,
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
        "fixed": None,
        "introduced": None,
    }
    result.update(values)
    return result


def row(nvd: list[dict], ghsa: list[dict], nvd_name: str = "pkg", ghsa_name: str = "pkg") -> dict:
    return {
        "sample_id": "sample:001",
        "cve_id": "CVE-2026-0001",
        "nvd_value": nvd,
        "ghsa_value": ghsa,
        "nvd_context": {"package_names": [nvd_name], "references": []},
        "ghsa_context": {"package_names": [ghsa_name], "references": []},
        "evidence_context": {"records": []},
    }


def branch(source: str = "abstain", contradictions: int = 0) -> dict:
    return {
        "predicted_source": source,
        "prediction_reason": "test_branch_reason",
        "source_profiles": {
            "nvd": {"contradiction_events": [{}] * contradictions},
            "ghsa": {"contradiction_events": []},
        },
    }


class StructuredRangeTests(unittest.TestCase):
    def test_open_range_covers_inner_range(self) -> None:
        outer = parse_span(span(version_end_excluding="3.0.0"))
        inner = parse_span(
            span(version_start_including="1.0.0", version_end_excluding="2.0.0")
        )
        self.assertTrue(target.span_covers(outer, inner))
        self.assertFalse(target.span_covers(inner, outer))

    def test_equal_boundary_inclusivity_is_respected(self) -> None:
        exclusive = parse_span(span(version_end_excluding="2.0.0"))
        inclusive = parse_span(span(version_end_including="2.0.0"))
        self.assertFalse(target.span_covers(exclusive, inclusive))
        self.assertTrue(target.span_covers(inclusive, exclusive))

    def test_exact_normalized_intervals_predict_equivalent(self) -> None:
        item = row(
            [span(version_end_including="1.9.9")],
            [span(version_end_including="1.9.9")],
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch()):
            prediction = target.predict_discrepancy_type(item)
        self.assertEqual(prediction["predicted_discrepancy_label"], "equivalent")
        self.assertEqual(prediction["type_prediction_status"], "determinate")

    def test_mutual_nonidentical_coverage_predicts_representation(self) -> None:
        item = row(
            [span(version_end_excluding="3.0.0")],
            [span(version_end_excluding="2.0.0"), span(version_end_excluding="3.0.0")],
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch()):
            prediction = target.predict_discrepancy_type(item)
        self.assertEqual(
            prediction["predicted_discrepancy_label"],
            "representation_discrepancy",
        )

    def test_strict_superset_without_evidence_abstains(self) -> None:
        item = row(
            [span(version_end_excluding="3.0.0")],
            [span(version_start_including="1.0.0", version_end_excluding="2.0.0")],
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch()):
            prediction = target.predict_discrepancy_type(item)
        self.assertEqual(prediction["predicted_discrepancy_label"], "uncertain")
        self.assertEqual(prediction["type_prediction_status"], "abstain")

    def test_package_mismatch_abstains_before_range_comparison(self) -> None:
        item = row(
            [span(version_end_excluding="3.0.0")],
            [span(version_end_excluding="2.0.0")],
            nvd_name="alpha",
            ghsa_name="beta",
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch()):
            prediction = target.predict_discrepancy_type(item)
        self.assertEqual(prediction["predicted_discrepancy_label"], "uncertain")
        self.assertEqual(prediction["type_prediction_status"], "abstain")

    def test_incompatible_sets_need_explicit_contradiction_for_fc(self) -> None:
        item = row(
            [span(version_start_including="1.0.0", version_end_excluding="2.0.0")],
            [span(version_start_including="3.0.0", version_end_excluding="4.0.0")],
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch("nvd", 1)):
            prediction = target.predict_discrepancy_type(item)
            source = target.predict_fc_source(item, prediction)
        self.assertEqual(prediction["predicted_discrepancy_label"], "factual_conflict")
        self.assertEqual(source["predicted_source"], "nvd")

    def test_non_fc_source_is_not_applicable(self) -> None:
        item = row(
            [span(version_end_including="1.0.0")],
            [span(version_end_including="1.0.0")],
        )
        type_prediction = {
            "predicted_discrepancy_label": "representation_discrepancy"
        }
        source = target.predict_fc_source(item, type_prediction)
        self.assertEqual(source["predicted_source"], "not_applicable")
        self.assertEqual(source["source_prediction_status"], "not_applicable")

    def test_fc_source_head_is_not_type_gated(self) -> None:
        item = row(
            [span(version_end_excluding="2.0.0")],
            [span(version_end_excluding="3.0.0")],
        )
        with patch.object(target, "extract_branch_graph_features", return_value=branch("ghsa", 1)):
            source = target.predict_fc_source_head(item)
        self.assertEqual(source["predicted_source"], "ghsa")


if __name__ == "__main__":
    unittest.main()
