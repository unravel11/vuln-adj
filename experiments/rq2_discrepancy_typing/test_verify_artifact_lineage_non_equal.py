import unittest

import verify_artifact_lineage_non_equal as target


class VerifyArtifactLineageNonEqualTests(unittest.TestCase):
    def test_fixed_outcome_accepts_no_go_result(self):
        target.verify_fixed_outcome(
            {
                "row_count": 5,
                "projection_gate_passed": 4,
                "non_human_consistency_only": {
                    "rows_matching_both_sealed_ai_reviewers": 2,
                },
                "advancement_gate": {
                    "status": "no_go_non_equal_graph_unstable",
                    "passed": False,
                    "observed_projection_coverage": 0.8,
                    "observed_both_reviewer_consistency": 0.4,
                    "failed_checks": ["minimum_both_reviewer_consistency"],
                },
            }
        )

    def test_fixed_outcome_rejects_advance(self):
        with self.assertRaisesRegex(ValueError, "no-go"):
            target.verify_fixed_outcome(
                {
                    "row_count": 5,
                    "projection_gate_passed": 4,
                    "non_human_consistency_only": {
                        "rows_matching_both_sealed_ai_reviewers": 2,
                    },
                    "advancement_gate": {
                        "status": "advance_non_equal_graph_candidate",
                        "passed": True,
                        "observed_projection_coverage": 0.8,
                        "observed_both_reviewer_consistency": 0.4,
                        "failed_checks": [],
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
