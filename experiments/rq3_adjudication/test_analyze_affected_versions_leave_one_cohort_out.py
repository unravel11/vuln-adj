#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_affected_versions_leave_one_cohort_out as target


class LeaveOneCohortOutTests(unittest.TestCase):
    def test_threshold_predictions_abstain_below_threshold(self) -> None:
        self.assertEqual(
            target.threshold_predictions(["a", "b"], [0.8, 0.5], 0.6),
            ["a", "abstain"],
        )

    def test_metrics_count_abstain_as_incorrect(self) -> None:
        result = target.metrics(["a", "b"], ["a", "abstain"])
        self.assertEqual(result["correct"], 1)
        self.assertEqual(result["full_accuracy"], 0.5)
        self.assertEqual(result["prediction_coverage"], 0.5)

    def test_feature_keys_reject_identity_or_label(self) -> None:
        target.validate_feature_keys(
            {
                "package_comparable": True,
                "branch_flag=fetched_linked_evidence_without_target_cve": True,
            }
        )
        with self.assertRaisesRegex(ValueError, "identity or label"):
            target.validate_feature_keys({"gold_label": "factual_conflict"})

    def test_stable_improvement_gate_requires_every_cohort(self) -> None:
        leave_out = {
            "splits": [
                {
                    "held_out_cohort": "a",
                    "baselines": {"baseline": {"correct": 2}},
                    "models": {"model": {"threshold_0.00": {"correct": 3}}},
                },
                {
                    "held_out_cohort": "b",
                    "baselines": {"baseline": {"correct": 2}},
                    "models": {"model": {"threshold_0.00": {"correct": 2}}},
                },
            ]
        }
        result = target.stable_improvement_gate(leave_out, ["baseline"])
        self.assertFalse(result["advance_to_new_sealed_cohort"])
        self.assertEqual(result["passing_candidates"], [])


if __name__ == "__main__":
    unittest.main()
