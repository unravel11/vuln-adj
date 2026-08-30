import unittest

import analyze_e0_replay as target


class SemanticComparisonTests(unittest.TestCase):
    def test_cpe_semantics_ignore_match_identity_but_keep_range(self):
        left = {
            "cpe_configurations": [
                {
                    "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                    "match_criteria_id": "left",
                    "version_end_excluding": "2.0",
                }
            ]
        }
        right = {
            "cpe_configurations": [
                {
                    "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                    "match_criteria_id": "right",
                    "version_end_excluding": "2.0",
                }
            ]
        }
        self.assertEqual(
            target.nvd_cpe_semantics(left), target.nvd_cpe_semantics(right)
        )
        right["cpe_configurations"][0]["version_end_excluding"] = "3.0"
        self.assertNotEqual(
            target.nvd_cpe_semantics(left), target.nvd_cpe_semantics(right)
        )

    def test_reference_semantics_do_not_depend_on_raw_url_or_position(self):
        left = {
            "references": [
                {
                    "position": 0,
                    "raw_url": "HTTPS://github.com/o/r/commit/a/",
                    "canonical_url": "https://github.com/o/r/commit/a",
                    "resource_type": "git_commit",
                    "source_type": None,
                    "source": "nvd",
                    "tags": ["Patch"],
                }
            ]
        }
        right = {
            "references": [
                {
                    "position": 9,
                    "raw_url": "https://github.com/o/r/commit/a",
                    "canonical_url": "https://github.com/o/r/commit/a",
                    "resource_type": "git_commit",
                    "source_type": None,
                    "source": "nvd",
                    "tags": ["Patch"],
                }
            ]
        }
        self.assertEqual(
            target.reference_semantics(left), target.reference_semantics(right)
        )


if __name__ == "__main__":
    unittest.main()

