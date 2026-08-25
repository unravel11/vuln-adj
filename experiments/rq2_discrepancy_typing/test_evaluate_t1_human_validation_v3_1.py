import unittest

from evaluate_t1_human_validation_v3_1 import (
    nominal_alpha,
    percentile,
    systematic_failures,
)


class EvaluateT1HumanValidationV31Test(unittest.TestCase):
    def test_nominal_alpha_perfect_agreement(self) -> None:
        self.assertEqual(
            nominal_alpha(["a", "b", "a"], ["a", "b", "a"]),
            1.0,
        )

    def test_nominal_alpha_retains_disagreements(self) -> None:
        alpha = nominal_alpha(["a", "a", "b", "b"], ["a", "b", "a", "b"])
        self.assertIsNotNone(alpha)
        self.assertLess(alpha, 1.0)

    def test_percentile_interpolates(self) -> None:
        self.assertAlmostEqual(percentile([0.0, 1.0], 0.25), 0.25)

    def test_systematic_failure_requires_two_fields_at_thirty_percent(self) -> None:
        rows = [
            {"case_id": "s1", "field": "severity"},
            {"case_id": "s2", "field": "severity"},
            {"case_id": "a1", "field": "affected_versions"},
            {"case_id": "a2", "field": "affected_versions"},
        ]
        labels_a = {row["case_id"]: "no_action" for row in rows}
        labels_b = {row["case_id"]: "abstain" for row in rows}
        findings = systematic_failures(rows, labels_a, labels_b, "action")
        self.assertEqual(len(findings), 1)
        self.assertEqual(set(findings[0]["fields"]), {"severity", "affected_versions"})


if __name__ == "__main__":
    unittest.main()
