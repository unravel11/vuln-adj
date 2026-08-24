import unittest

import verify_rq2_residual_nonaffected_evidence as target


class VerifyResidualNonAffectedEvidenceTests(unittest.TestCase):
    def test_independent_repair_is_narrow(self):
        malformed = "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187https://"
        expected = "https://bugzilla.suse.com/show_bug.cgi?id=CVE-2023-32187"
        self.assertEqual(target.repaired(malformed), expected)
        self.assertEqual(target.repaired("https://example.test/https://"), "https://example.test/https://")

    def test_independent_relation_distinguishes_overlap_and_subset(self):
        self.assertEqual(target.relation({"a", "b"}, {"a", "c"}), "overlap_non_subset")
        self.assertEqual(target.relation({"a"}, {"a", "c"}), "nvd_subset_of_ghsa")


if __name__ == "__main__":
    unittest.main()
