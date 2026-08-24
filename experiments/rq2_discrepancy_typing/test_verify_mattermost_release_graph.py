import json
import unittest

import verify_mattermost_release_graph as target


class VerifyMattermostReleaseGraphTests(unittest.TestCase):
    def test_ancestry_mapping_rejects_diverged(self):
        self.assertTrue(target.ancestry_membership("ahead"))
        self.assertFalse(target.ancestry_membership("identical"))
        self.assertIsNone(target.ancestry_membership("diverged"))

    def test_commit_parser_binds_pseudo_timestamp_and_sha(self):
        body = json.dumps({
            "sha": "64c566a8280be9463fcdff7f9e797c045e477674",
            "commit": {"committer": {"date": "2025-01-02T08:18:31Z"}},
        }).encode()
        self.assertTrue(target.parse_commit("CVE-2025-22449", body)["bound"])

    def test_cache_inventory_is_fixed(self):
        self.assertEqual(len(target.expected_cache_inventory()), 160)

    def test_directional_relation(self):
        self.assertEqual(target.relation({"a"}, {"a", "b"}), "nvd_subset_of_ghsa")


if __name__ == "__main__":
    unittest.main()
