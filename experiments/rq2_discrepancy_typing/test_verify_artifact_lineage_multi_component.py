import unittest

import verify_artifact_lineage_multi_component as target


def fixed_analysis():
    return {
        "row_count": 1,
        "projection_gate_passed": 1,
        "component_count": 2,
        "component_heterogeneity_count": 0,
        "candidate_counts": {"representation_discrepancy": 1},
        "non_human_consistency_only": {
            "rows_matching_both_sealed_ai_reviewers": 0,
        },
        "cases": [
            {
                "release_sets": {
                    "relation": "equal",
                    "nvd_product_versions": ["1.4.0", "1.5.0"],
                    "ghsa_component_union_versions": ["1.4.0", "1.5.0"],
                }
            }
        ],
        "contract_diagnostic": {
            "status": (
                "snapshot_extensional_projection_supported_"
                "human_resolution_required"
            ),
            "production_switch_allowed": False,
        },
    }


class VerifyArtifactLineageMultiComponentTests(unittest.TestCase):
    def test_fixed_outcome_accepts_expected_diagnostic(self):
        target.verify_fixed_outcome(fixed_analysis())

    def test_fixed_outcome_rejects_human_gold_style_switch(self):
        analysis = fixed_analysis()
        analysis["contract_diagnostic"]["production_switch_allowed"] = True
        with self.assertRaisesRegex(ValueError, "production switch"):
            target.verify_fixed_outcome(analysis)


if __name__ == "__main__":
    unittest.main()
