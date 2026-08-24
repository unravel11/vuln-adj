import unittest

from build_rq2_post_profile_cwe_evidence_secondary import (
    collect_references,
    derive_fetch_url,
    derive_targets,
    recursive_keys,
)


class BuildPostProfileCweEvidenceSecondaryTests(unittest.TestCase):
    def test_targets_are_derived_from_three_profile_differences(self):
        rows = [
            {
                "sample_id": f"sample:{index}",
                "cve_id": f"CVE-2026-{index:04d}",
                "field": "cwe_ids",
                "strict_consensus": index == 2,
                "consensus_label": "representation_discrepancy" if index == 2 else None,
                "current": "factual_conflict",
                "candidate": "representation_discrepancy",
            }
            for index in (3, 1, 2)
        ]
        evaluation = {
            "paired_profile_comparisons": {
                "cwe_taxonomy_v1": {
                    "prediction_difference_rows": 3,
                    "rows": rows,
                }
            }
        }
        targets = derive_targets(evaluation)
        self.assertEqual([row["sample_id"] for row in targets], ["sample:1", "sample:2", "sample:3"])

    def test_target_derivation_fails_when_profiles_do_not_differ(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2026-0001",
            "field": "cwe_ids",
            "strict_consensus": False,
            "consensus_label": None,
            "current": "factual_conflict",
            "candidate": "factual_conflict",
        }
        evaluation = {
            "paired_profile_comparisons": {
                "cwe_taxonomy_v1": {
                    "prediction_difference_rows": 3,
                    "rows": [row, {**row, "sample_id": "sample:2"}, {**row, "sample_id": "sample:3"}],
                }
            }
        }
        with self.assertRaisesRegex(ValueError, "does not distinguish"):
            derive_targets(evaluation)

    def test_reference_selection_is_ranked_deduplicated_and_excludes_repo_root(self):
        source = {
            "reference_context": {
                "nvd_urls": [
                    "https://github.com/org/repo",
                    "https://github.com/org/repo/commit/abc",
                    "https://github.com/org/repo/security/advisories/GHSA-abcd",
                ],
                "ghsa_urls": [
                    "https://github.com/org/repo/security/advisories/GHSA-abcd",
                    "https://example.org/advisory/1",
                ],
            }
        }
        selected = collect_references(source)
        self.assertEqual(
            [row["source_url"] for row in selected],
            [
                "https://github.com/org/repo/security/advisories/GHSA-abcd",
                "https://github.com/org/repo/commit/abc",
                "https://example.org/advisory/1",
            ],
        )
        self.assertEqual(selected[0]["source_databases"], ["nvd", "ghsa"])
        self.assertEqual(
            derive_fetch_url("https://github.com/org/repo/commit/abc"),
            "https://github.com/org/repo/commit/abc.patch",
        )

    def test_recursive_keys_detects_nested_prediction_leakage(self):
        self.assertIn("current", recursive_keys({"nested": [{"current": "x"}]}))


if __name__ == "__main__":
    unittest.main()
