import unittest

import verify_artifact_lineage_cross_case as target


class VerifyArtifactLineageCrossCaseTests(unittest.TestCase):
    def test_boundary_accepts_required_epistemic_flags(self):
        target.verify_boundary(
            {
                "selection_uses_reviewer_labels": False,
                "upstream_source_conditioned_on_non_human_consensus": True,
                "post_unsealing": True,
                "development_diagnostic_only": True,
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "production_switch_allowed": False,
                "generalization_claim_allowed": False,
            }
        )

    def test_boundary_rejects_human_gold_claim(self):
        with self.assertRaisesRegex(ValueError, "label_is_human"):
            target.verify_boundary(
                {
                    "selection_uses_reviewer_labels": False,
                    "upstream_source_conditioned_on_non_human_consensus": True,
                    "post_unsealing": True,
                    "development_diagnostic_only": True,
                    "label_is_human": True,
                    "eligible_for_human_gold_claim": False,
                    "production_switch_allowed": False,
                    "generalization_claim_allowed": False,
                }
            )


if __name__ == "__main__":
    unittest.main()
