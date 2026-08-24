#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_affected_versions_task_separated_v2_development as target


class DevelopmentDiagnosticTests(unittest.TestCase):
    def test_abstain_is_incorrect_for_full_accuracy(self) -> None:
        result = target.metrics(
            ["factual_conflict", "representation_discrepancy"],
            ["uncertain", "representation_discrepancy"],
            target.TYPE_ABSTAIN,
        )
        self.assertEqual(result["correct"], 1)
        self.assertEqual(result["full_accuracy"], 0.5)
        self.assertEqual(result["prediction_coverage"], 0.5)
        self.assertEqual(result["selective_accuracy"], 1.0)

    def test_both_is_abstention_on_fc_source_endpoint(self) -> None:
        result = target.metrics(["nvd"], ["both"], target.SOURCE_ABSTAIN)
        self.assertEqual(result["correct"], 0)
        self.assertEqual(result["prediction_coverage"], 0.0)

    def test_empty_endpoint_is_explicit(self) -> None:
        result = target.metrics([], [], target.SOURCE_ABSTAIN)
        self.assertEqual(result["rows"], 0)
        self.assertIsNone(result["full_accuracy"])


if __name__ == "__main__":
    unittest.main()
