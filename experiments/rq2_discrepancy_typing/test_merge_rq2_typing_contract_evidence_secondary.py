import unittest

import merge_rq2_typing_contract_evidence_secondary as target


class MergeTypingContractEvidenceSecondaryTests(unittest.TestCase):
    def parent_summary(self):
        return {
            "rows": 42,
            "strict_consensus_rows": 41,
            "gate": {"checks": {
                "overall_exact_agreement": True,
                "affected_prerelease_boundary.strict_consensus_coverage": False,
                "another_check": True,
            }},
            "strata": {"affected_prerelease_boundary": {
                "rows": 3,
                "strict_consensus_rows": 2,
            }},
        }

    def test_gate_passes_only_with_strict_evidence_backed_secondary(self):
        gate = target.build_gate(self.parent_summary(), True, True)
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["evidence_augmented_strict_consensus_rows"], 42)

    def test_gate_remains_no_go_without_evidence_citations(self):
        gate = target.build_gate(self.parent_summary(), True, False)
        self.assertFalse(gate["passed"])
        self.assertEqual(
            gate["status"], "no_go_ai_contract_v2_evidence_secondary_unresolved"
        )


if __name__ == "__main__":
    unittest.main()
