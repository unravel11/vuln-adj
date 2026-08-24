import unittest

import merge_rq2_typing_contract_calibration_v2 as target


def passing_strata():
    result = {}
    for name in target.builder.STRATUM_TARGETS:
        result[name] = {
            "strict_expected_rate": 1.0 if name in target.FIXED_EXPECTED_LABELS else None,
            "strict_consensus_coverage": 1.0,
        }
    return result


class MergeContractCalibrationV2Tests(unittest.TestCase):
    def test_pass_remains_non_human(self):
        gate = target.build_gate(
            {"exact_label_agreement_rate": 0.95, "strict_consensus_coverage": 0.90},
            passing_strata(),
        )
        self.assertTrue(gate["passed"])
        self.assertFalse(gate["production_switch_allowed"])
        self.assertFalse(gate["human_gold_claim_allowed"])

    def test_open_affected_stratum_can_fail_gate(self):
        strata = passing_strata()
        strata["affected_prerelease_boundary"]["strict_consensus_coverage"] = 0.5
        gate = target.build_gate(
            {"exact_label_agreement_rate": 0.95, "strict_consensus_coverage": 0.90},
            strata,
        )
        self.assertFalse(gate["passed"])


if __name__ == "__main__":
    unittest.main()
