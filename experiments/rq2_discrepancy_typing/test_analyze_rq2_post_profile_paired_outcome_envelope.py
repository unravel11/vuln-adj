#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_rq2_post_profile_paired_outcome_envelope as target


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
        source.append(
            {"sample_id": sample_id, "cve_id": f"CVE-2026-{index + 1}", "field": field}
        )
        current = "equivalent"
        candidate = "equivalent"
        if field == "cwe_ids" and index in {50, 51, 52}:
            current = "factual_conflict"
            candidate = "representation_discrepancy"
        predictions.append(
            {
                "sample_id": sample_id,
                "cve_id": f"CVE-2026-{index + 1}",
                "field": field,
                "current": current,
                "cwe_taxonomy_v1": candidate,
            }
        )
    return source, predictions


class PairedOutcomeEnvelopeTests(unittest.TestCase):
    def test_three_difference_assignment_distribution(self) -> None:
        source, predictions = rows()
        analysis = target.compute_analysis(source, predictions)
        envelope = analysis["outcome_envelope"]
        self.assertEqual(analysis["prediction_difference_rows"], 3)
        self.assertEqual(analysis["identical_prediction_rows"], 247)
        self.assertEqual(analysis["maximum_absolute_accuracy_difference"], 0.012)
        self.assertEqual(envelope["total_assignments"], 125)
        self.assertEqual(
            envelope["paired_delta_assignment_counts"],
            {"-3": 1, "-2": 9, "-1": 30, "0": 45, "1": 30, "2": 9, "3": 1},
        )
        self.assertEqual(envelope["candidate_better_assignments"], 40)
        self.assertEqual(envelope["current_better_assignments"], 40)
        self.assertEqual(envelope["tied_assignments"], 45)
        self.assertFalse(envelope["assignment_counts_are_probabilities"])

    def test_only_cwe_field_has_nonzero_envelope(self) -> None:
        source, predictions = rows()
        analysis = target.compute_analysis(source, predictions)
        self.assertEqual(
            analysis["per_field"]["cwe_ids"]["maximum_absolute_accuracy_difference"],
            0.06,
        )
        for field, result in analysis["per_field"].items():
            if field != "cwe_ids":
                self.assertEqual(result["prediction_difference_rows"], 0)

    def test_unexpected_difference_count_fails_closed(self) -> None:
        source, predictions = rows()
        predictions[53]["cwe_taxonomy_v1"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "expected 3 sealed differences"):
            target.compute_analysis(source, predictions)


if __name__ == "__main__":
    unittest.main()
