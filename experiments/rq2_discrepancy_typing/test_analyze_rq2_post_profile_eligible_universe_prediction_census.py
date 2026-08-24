#!/usr/bin/env python3

from __future__ import annotations

import unittest
from unittest import mock

import analyze_rq2_post_profile_eligible_universe_prediction_census as target


def synthetic_rows() -> tuple[list[dict], list[dict]]:
    source = []
    predictions = []
    for field in target.FIELDS:
        for index in range(2):
            cve_id = f"CVE-2026-{index + 1}"
            current = "equivalent"
            original = audited = cwe = current
            if field == "references" and index == 0:
                original = "incomplete"
                audited = "representation_discrepancy"
            if field == "cwe_ids" and index == 1:
                cwe = "representation_discrepancy"
            source.append(
                {
                    "sample_id": f"sample:{field}:{index}",
                    "cve_id": cve_id,
                    "field": field,
                    "baseline_status": current,
                }
            )
            predictions.append(
                {
                    "sample_id": f"sample:{field}:{index}",
                    "cve_id": cve_id,
                    "field": field,
                    "current": current,
                    "reference_resource_identity_original_v1": original,
                    "reference_resource_identity_audited_v1": audited,
                    "cwe_taxonomy_v1": cwe,
                    "combined_original_v1": original if field == "references" else cwe,
                    "combined_audited_v1": audited if field == "references" else cwe,
                }
            )
    return source, predictions


class EligibleUniversePredictionCensusTests(unittest.TestCase):
    def test_difference_rows_contain_no_correctness_field(self) -> None:
        _, predictions = synthetic_rows()
        rows = target.difference_rows(predictions)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["field"] for row in rows}, {"references", "cwe_ids"})
        self.assertTrue(all(row["label_is_human"] is False for row in rows))
        self.assertTrue(all("correct" not in row for row in rows))

    def test_profiles_are_not_forced_into_sample_equivalence_classes(self) -> None:
        _, predictions = synthetic_rows()
        classes = target.profile_equivalence_classes(predictions)
        self.assertEqual(len(classes), 6)

    def test_pairwise_counts_preserve_cve_clusters(self) -> None:
        _, predictions = synthetic_rows()
        comparison = next(
            row
            for row in target.pairwise_comparisons(predictions)
            if row["first_profile"] == "current"
            and row["second_profile"] == "combined_audited_v1"
        )
        self.assertEqual(comparison["prediction_difference_rows"], 2)
        self.assertEqual(comparison["difference_unique_cves"], 2)
        self.assertEqual(comparison["multi_field_difference_cves"], 0)
        self.assertFalse(comparison["theoretical_rejection_capacity_alpha_0_05"])

    def test_compute_analysis_accepts_complete_small_census_under_patched_bounds(self) -> None:
        source, predictions = synthetic_rows()
        selected = predictions[:4]
        with (
            mock.patch.object(target, "EXPECTED_ELIGIBLE_CVES", 2),
            mock.patch.object(target, "EXPECTED_FIELD_INSTANCES", 10),
        ):
            analysis, differences = target.compute_analysis(
                source, predictions, selected
            )
        self.assertEqual(analysis["field_instances"], 10)
        self.assertEqual(analysis["union_prediction_difference_rows"], 2)
        self.assertEqual(len(differences), 2)
        self.assertFalse(analysis["same_snapshot_resampling_performed"])

    def test_minimum_attainable_p_uses_unique_rows(self) -> None:
        self.assertEqual(target.minimum_attainable_p(0), 1.0)
        self.assertEqual(target.minimum_attainable_p(3), 0.25)
        self.assertEqual(target.minimum_attainable_p(6), 0.03125)


if __name__ == "__main__":
    unittest.main()
