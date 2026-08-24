#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import evaluate_affected_versions_holdout_v2 as target


class V2EvaluationTests(unittest.TestCase):
    def test_abstain_is_incorrect_in_full_accuracy(self) -> None:
        rows = [
            {"gold": "factual_conflict", "predictions": {"m": {"value": "uncertain"}}},
            {"gold": "incomplete", "predictions": {"m": {"value": "incomplete"}}},
        ]
        metrics = target.endpoint_metrics(rows, "m", {"uncertain"})
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["prediction_coverage"], 0.5)
        self.assertEqual(metrics["selective_accuracy"], 1.0)

    def test_not_applicable_is_source_abstention(self) -> None:
        rows = [
            {"gold": "nvd", "predictions": {"m": {"value": "not_applicable"}}}
        ]
        metrics = target.endpoint_metrics(rows, "m", {"abstain", "not_applicable"})
        self.assertEqual(metrics["accuracy"], 0.0)
        self.assertEqual(metrics["prediction_coverage"], 0.0)
        self.assertIsNone(metrics["selective_accuracy"])

    def test_paired_delta_uses_full_correctness(self) -> None:
        rows = [
            {
                "gold": "nvd",
                "predictions": {
                    "primary": {"value": "nvd"},
                    "baseline": {"value": "ghsa"},
                },
            }
        ]
        paired = target.paired_comparison(
            rows, "primary", "baseline", {"abstain"}, 100, 1
        )
        self.assertEqual(paired["accuracy_delta"], 1.0)
        self.assertEqual(paired["primary_only_correct"], 1)

    def test_source_population_requires_strict_fc_and_source(self) -> None:
        base = {
            "type_consensus_status": "strict_determinate",
            "discrepancy_label": "factual_conflict",
            "source_consensus_status": "strict_determinate",
        }
        self.assertTrue(target.eligible_source_consensus(base))
        for key, value in (
            ("type_consensus_status", "abstain"),
            ("discrepancy_label", "representation_discrepancy"),
            ("source_consensus_status", "abstain"),
        ):
            changed = dict(base)
            changed[key] = value
            self.assertFalse(target.eligible_source_consensus(changed))

    def test_sealed_code_hashes_reject_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "method.py"
            path.write_text("before\n", encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            target.validate_sealed_code_hashes({str(path): digest}, "method")
            path.write_text("after\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed after prediction seal"):
                target.validate_sealed_code_hashes({str(path): digest}, "method")

    def test_sealed_code_hashes_cannot_be_empty(self) -> None:
        with self.assertRaisesRegex(ValueError, "lacks sealed protocol hashes"):
            target.validate_sealed_code_hashes({}, "protocol")


if __name__ == "__main__":
    unittest.main()
