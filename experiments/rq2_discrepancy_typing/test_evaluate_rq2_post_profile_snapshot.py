import unittest

import evaluate_rq2_post_profile_snapshot as target


def records():
    rows = [
        {
            "sample_id": "sample:001",
            "cve_id": "CVE-2026-0001",
            "field": "cwe_ids",
            "weight": 2.0,
            "strict": True,
            "target": "representation_discrepancy",
            "reviewer_a_label": "representation_discrepancy",
            "reviewer_a_confidence": "high",
            "reviewer_a_needs_review": False,
            "reviewer_b_label": "representation_discrepancy",
            "reviewer_b_confidence": "high",
            "reviewer_b_needs_review": False,
            "current": "factual_conflict",
            "cwe_taxonomy_v1": "representation_discrepancy",
        },
        {
            "sample_id": "sample:002",
            "cve_id": "CVE-2026-0002",
            "field": "severity",
            "weight": 1.0,
            "strict": False,
            "target": None,
            "reviewer_a_label": "uncertain",
            "reviewer_a_confidence": "low",
            "reviewer_a_needs_review": True,
            "reviewer_b_label": "factual_conflict",
            "reviewer_b_confidence": "medium",
            "reviewer_b_needs_review": False,
            "current": "factual_conflict",
            "cwe_taxonomy_v1": "factual_conflict",
        },
    ]
    return rows


class EvaluatePostProfileSnapshotTests(unittest.TestCase):
    def test_method_metrics_use_selective_consensus_target(self):
        metrics = target.method_metrics(records(), "cwe_taxonomy_v1")
        self.assertEqual(metrics["strict_consensus_rows"], 1)
        self.assertEqual(metrics["agreement_count"], 1)
        self.assertEqual(metrics["strict_consensus_agreement"], 1.0)
        self.assertEqual(metrics["full_cohort_lower_bound_agreement"], 0.5)

    def test_paired_comparison_only_uses_prediction_differences(self):
        comparison = target.paired_profile_comparison(records(), "cwe_taxonomy_v1")
        self.assertEqual(comparison["prediction_difference_rows"], 1)
        self.assertEqual(comparison["candidate_minus_current_agreement_count"], 1)

    def test_cluster_bootstrap_is_deterministic(self):
        left = target.cluster_bootstrap(records(), "cwe_taxonomy_v1", 50, 7)
        right = target.cluster_bootstrap(records(), "cwe_taxonomy_v1", 50, 7)
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
