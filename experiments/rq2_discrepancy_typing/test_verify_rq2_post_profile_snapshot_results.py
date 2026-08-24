import unittest

import verify_rq2_post_profile_snapshot_results as target


class VerifyPostProfileResultsTests(unittest.TestCase):
    def test_forbidden_gold_keys_rejects_target_alias(self):
        self.assertEqual(
            target.forbidden_gold_keys({"nested": {"gold": "label"}}),
            ["nested.gold"],
        )

    def test_forbidden_gold_keys_allows_explicit_false_eligibility_boundary(self):
        self.assertEqual(
            target.forbidden_gold_keys({"eligible_for_human_gold_claim": False}),
            [],
        )


if __name__ == "__main__":
    unittest.main()
