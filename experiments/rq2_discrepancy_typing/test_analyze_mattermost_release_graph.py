import json
import unittest

import analyze_mattermost_release_graph as target


class AnalyzeMattermostReleaseGraphTests(unittest.TestCase):
    def test_fixed_domain_has_expected_19_releases(self):
        self.assertEqual(len(target.EXPECTED_PRODUCT_VERSIONS), 19)
        self.assertEqual(target.EXPECTED_PRODUCT_VERSIONS[0], "9.11.0")
        self.assertEqual(target.EXPECTED_PRODUCT_VERSIONS[-1], "10.4.3")

    def test_family_advancement_contract_requires_two_rows(self):
        self.assertEqual(len(target.EXPECTED_SIGNATURES), 2)

    def test_v3_uses_fixed_git_tag_domain(self):
        self.assertEqual(target.SCHEMA_VERSION, "mattermost_release_graph_v3")
        self.assertEqual(
            {version: f"v{version}" for version in target.EXPECTED_PRODUCT_VERSIONS}["10.3.0"],
            "v10.3.0",
        )

    def test_ancestry_membership_is_fail_closed(self):
        self.assertTrue(target.ancestry_membership("ahead"))
        self.assertFalse(target.ancestry_membership("behind"))
        self.assertFalse(target.ancestry_membership("identical"))
        self.assertIsNone(target.ancestry_membership("diverged"))

    def test_version_span_preserves_exclusive_upper_bound(self):
        span = target.range_tuple("9.11.0", "9.11.6")
        self.assertTrue(target.version_in_span("9.11.5", span))
        self.assertFalse(target.version_in_span("9.11.6", span))

    def test_set_relation_detects_strict_superset(self):
        self.assertEqual(
            target.set_relation({"9.11.0"}, {"9.11.0", "9.11.1"}),
            "nvd_subset_of_ghsa",
        )
        self.assertEqual(target.candidate_for_relation("nvd_subset_of_ghsa"), "incomplete")

    def test_pseudo_commit_requires_sha_and_exact_timestamp(self):
        body = json.dumps({
            "sha": "64c566a8280bffffffffffffffffffffffffffff",
            "commit": {"committer": {"date": "2025-01-02T08:18:31Z"}},
        }).encode()
        result = target.parse_pseudo_commit(
            "CVE-2025-22449",
            target.PSEUDO_FIXES["CVE-2025-22449"],
            body,
        )
        self.assertTrue(result["bound"])

    def test_claim_signature_normalizes_introduced_zero_to_open_lower(self):
        item = {
            "package_name": target.CURRENT_MODULE,
            "version_start_including": "0",
            "version_start_excluding": None,
            "version_end_excluding": "8.0.0-20250102081831-64c566a8280b",
            "version_end_including": None,
        }
        self.assertEqual(
            target.claim_signature([item]),
            {target.CURRENT_MODULE: [target.range_tuple(None, target.PSEUDO_FIXES["CVE-2025-22449"])]},
        )


if __name__ == "__main__":
    unittest.main()
