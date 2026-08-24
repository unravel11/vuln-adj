import unittest

import merge_rq2_typing_contract_calibration as target


def passing_strata():
    return {
        name: {"strict_expected_rate": 1.0}
        for name in target.builder.STRATUM_TARGETS
    }


class MergeContractCalibrationTests(unittest.TestCase):
    def test_gate_pass_is_non_human_only(self):
        gate = target.build_gate(
            {"exact_label_agreement_rate": 0.95, "strict_consensus_coverage": 0.90},
            passing_strata(),
        )
        self.assertTrue(gate["passed"])
        self.assertTrue(gate["candidate_profile_freeze_allowed"])
        self.assertFalse(gate["production_switch_allowed"])
        self.assertFalse(gate["human_gold_claim_allowed"])
        self.assertFalse(gate["confirmatory_performance_claim_allowed"])

    def test_gate_fails_on_one_unstable_core_stratum(self):
        strata = passing_strata()
        strata["affected_one_sided_unbounded_claim"]["strict_expected_rate"] = 0.7
        gate = target.build_gate(
            {"exact_label_agreement_rate": 0.95, "strict_consensus_coverage": 0.90},
            strata,
        )
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["status"], "no_go_ai_calibration_unstable")

    def test_missing_vector_exploratory_row_does_not_bind_gate(self):
        strata = passing_strata()
        strata["severity_missing_vector_one_missing_score"][
            "strict_expected_rate"
        ] = 0.0
        gate = target.build_gate(
            {"exact_label_agreement_rate": 0.95, "strict_consensus_coverage": 0.90},
            strata,
        )
        self.assertTrue(gate["passed"])

    def test_expected_label_for_control_uses_prior_consensus(self):
        self.assertEqual(
            target.expected_label(
                {
                    "calibration_stratum": "severity_unchanged_control",
                    "prior_non_human_consensus_label": "equivalent",
                }
            ),
            "equivalent",
        )


if __name__ == "__main__":
    unittest.main()
