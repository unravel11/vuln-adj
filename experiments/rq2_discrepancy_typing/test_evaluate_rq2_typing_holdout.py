#!/usr/bin/env python3

from __future__ import annotations

import unittest

import evaluate_rq2_typing_holdout as target


def records() -> list[dict]:
    return [
        {
            "sample_id": "1",
            "cve_id": "CVE-1",
            "field": "severity",
            "weight": 10.0,
            "strict": True,
            "gold": "factual_conflict",
            "current": "factual_conflict",
        },
        {
            "sample_id": "2",
            "cve_id": "CVE-1",
            "field": "published",
            "weight": 20.0,
            "strict": True,
            "gold": "temporal_discrepancy",
            "current": "representation_discrepancy",
        },
        {
            "sample_id": "3",
            "cve_id": "CVE-2",
            "field": "references",
            "weight": 30.0,
            "strict": False,
            "gold": None,
            "current": "incomplete",
        },
    ]


class EvaluateRq2TypingHoldoutTests(unittest.TestCase):
    def test_method_metrics_report_selective_and_full_lower_bound(self) -> None:
        metrics = target.method_metrics(records(), "current")
        self.assertEqual(metrics["strict_rows"], 2)
        self.assertEqual(metrics["strict_accuracy"], 0.5)
        self.assertEqual(metrics["full_cohort_lower_bound_accuracy"], 1 / 3)
        self.assertEqual(metrics["corpus_reweighted_strict_accuracy"], 1 / 3)

    def test_cluster_bootstrap_is_deterministic(self) -> None:
        left = target.cluster_bootstrap(records(), "current", 100, 7)
        right = target.cluster_bootstrap(records(), "current", 100, 7)
        self.assertEqual(left, right)
        self.assertEqual(left["unique_cves"], 2)

    def test_percentile_handles_empty_values(self) -> None:
        self.assertIsNone(target.percentile([], 0.5))


if __name__ == "__main__":
    unittest.main()
