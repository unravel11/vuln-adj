import unittest

from verify_rq2_post_profile_cwe_all50 import expected_relation, recursive_keys


class VerifyPostProfileCweAll50Tests(unittest.TestCase):
    def test_set_relation_is_recomputed_from_raw_sets(self):
        self.assertEqual(expected_relation(["CWE-1"], ["CWE-1"]), "exact_set")
        self.assertEqual(
            expected_relation(["CWE-1"], ["CWE-1", "CWE-2"]),
            "literal_strict_subset",
        )
        self.assertEqual(
            expected_relation(["CWE-1", "CWE-2"], ["CWE-2", "CWE-3"]),
            "overlap_non_subset",
        )
        self.assertEqual(expected_relation(["CWE-1"], ["CWE-2"]), "disjoint")

    def test_recursive_keys_detect_nested_profile_leakage(self):
        self.assertIn("current_prediction", recursive_keys({"nested": [{"current_prediction": "x"}]}))


if __name__ == "__main__":
    unittest.main()
