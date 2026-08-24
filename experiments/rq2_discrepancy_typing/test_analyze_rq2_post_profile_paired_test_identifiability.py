#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_rq2_post_profile_paired_test_identifiability as target


def rows() -> tuple[list[dict], list[dict]]:
    source = []
    predictions = []
    fields = (
        "affected_versions",
        "cwe_ids",
        "published",
        "references",
        "severity",
    )
    for index in range(250):
        field = fields[index // 50]
        sample_id = f"sample:{index + 1:03d}"
        current = "equivalent"
        candidate = "equivalent"
        if field == "cwe_ids" and index in {50, 51, 52}:
            current = "factual_conflict"
            candidate = "representation_discrepancy"
        source.append(
            {"sample_id": sample_id, "cve_id": f"CVE-2026-{index + 1}", "field": field}
        )
        predictions.append(
            {
                "sample_id": sample_id,
                "cve_id": f"CVE-2026-{index + 1}",
                "field": field,
                "current": current,
                "reference_resource_identity_original_v1": current,
                "reference_resource_identity_audited_v1": current,
                "cwe_taxonomy_v1": candidate,
                "combined_original_v1": candidate,
                "combined_audited_v1": candidate,
            }
        )
    return source, predictions


class PairedTestIdentifiabilityTests(unittest.TestCase):
    def test_exact_two_sided_boundaries(self) -> None:
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 0), 1.0)
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 3), 0.25)
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 5), 0.0625)
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 6), 0.03125)
        self.assertEqual(target.minimum_rows_for_any_rejection(0.05), 6)

    def test_all_six_profiles_collapse_to_two_vectors(self) -> None:
        source, predictions = rows()
        analysis = target.compute_analysis(source, predictions)
        self.assertEqual(
            analysis["profile_prediction_equivalence_classes"],
            [
                [
                    "current",
                    "reference_resource_identity_original_v1",
                    "reference_resource_identity_audited_v1",
                ],
                ["cwe_taxonomy_v1", "combined_original_v1", "combined_audited_v1"],
            ],
        )
        self.assertFalse(
            analysis["exact_test"][
                "any_current_profile_pair_can_reject_under_any_gold_assignment"
            ]
        )

    def test_complete_assignment_enumeration_has_no_rejection(self) -> None:
        source, predictions = rows()
        result = target.enumerate_representative_assignments(source, predictions)
        self.assertEqual(result["total_label_assignments"], 125)
        self.assertEqual(
            result["effective_discordant_row_assignment_counts"],
            {"0": 27, "1": 54, "2": 36, "3": 8},
        )
        self.assertEqual(
            result["two_sided_exact_p_assignment_counts"],
            {"0.25": 2, "0.5": 18, "1": 105},
        )
        self.assertEqual(result["rejecting_assignments_alpha_0_05"], 0)

    def test_power_and_availability_searches_are_minimal(self) -> None:
        rows_required, power = target.minimum_rows_for_power(0.80, 0.80, 0.05)
        self.assertGreaterEqual(power, 0.80)
        self.assertLess(
            target.candidate_direction_power(rows_required - 1, 0.80, 0.05), 0.80
        )
        cohort_rows, probability = (
            target.minimum_cohort_rows_for_difference_probability(3 / 250, 6, 0.80)
        )
        self.assertGreaterEqual(probability, 0.80)
        self.assertLess(
            target.probability_at_least_differences(cohort_rows - 1, 3 / 250, 6),
            0.80,
        )

    def test_unexpected_representative_difference_count_fails_closed(self) -> None:
        source, predictions = rows()
        predictions[53]["cwe_taxonomy_v1"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "expected three representative"):
            target.enumerate_representative_assignments(source, predictions)


if __name__ == "__main__":
    unittest.main()
