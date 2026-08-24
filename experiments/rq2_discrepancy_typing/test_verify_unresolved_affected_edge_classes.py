import unittest

import verify_unresolved_affected_edge_classes as target


class VerifyUnresolvedAffectedEdgeClassesTests(unittest.TestCase):
    def test_introduced_zero_is_open_lower(self):
        self.assertEqual(
            target.span({
                "version": None,
                "introduced": "0",
                "version_start_including": "0",
                "version_end_excluding": "1.2.3",
            }),
            ("range", None, False, "1.2.3", False),
        )

    def test_mattermost_family_rule_is_exact(self):
        row = {
            "nvd_value": [{"vendor": "mattermost", "package_name": "mattermost_server"}],
            "ghsa_value": [{"package_name": "github.com/mattermost/mattermost/server/v8"}],
        }
        self.assertEqual(target.family(row), "mattermost")


if __name__ == "__main__":
    unittest.main()
