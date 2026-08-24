import unittest

import analyze_lf_edge_eve_release_graph as target


class AnalyzeLfEdgeEveReleaseGraphTests(unittest.TestCase):
    def test_fixed_domain_has_207_release_tags(self):
        self.assertEqual(len(target.EXPECTED_PRODUCT_VERSIONS), 207)
        self.assertEqual(target.EXPECTED_PRODUCT_VERSIONS[0], "3.0.0")
        self.assertEqual(target.EXPECTED_PRODUCT_VERSIONS[-1], "10.1.0")
        self.assertNotIn("4.9.1-uefi", target.EXPECTED_PRODUCT_VERSIONS)

    def test_lts_suffix_uses_numeric_core_for_cpe_interval(self):
        span = target.range_tuple("9.0.0", "9.5.0")
        self.assertTrue(target.version_in_span("9.4.3-lts", span))
        self.assertFalse(target.version_in_span("9.5.0", span))

    def test_ancestry_membership_fails_closed_on_diverged(self):
        self.assertTrue(target.ancestry_membership("ahead"))
        self.assertFalse(target.ancestry_membership("behind"))
        self.assertFalse(target.ancestry_membership("identical"))
        self.assertIsNone(target.ancestry_membership("diverged"))

    def test_patch_paths_are_extracted_from_diff_headers(self):
        patch = b"diff --git a/pkg/vtpm/src/server.cpp b/pkg/vtpm/src/server.cpp\n"
        self.assertEqual(target.parse_patch_paths(patch), ["pkg/vtpm/src/server.cpp"])

    def test_advisory_facts_normalize_package_and_patch(self):
        facts = target.advisory_facts({
            "ghsa_id": "GHSA-test",
            "cve_id": "CVE-test",
            "source_code_location": target.REPOSITORY_URL,
            "vulnerabilities": [{
                "package": {"name": "github.com/lf-edge/eve/pkg/vtpm/"},
                "first_patched_version": "10.1.0",
            }],
        })
        self.assertEqual(facts["packages"], ["github.com/lf-edge/eve/pkg/vtpm"])
        self.assertEqual(facts["first_patched_versions"], ["10.1.0"])

    def test_claim_signature_normalizes_introduced_zero(self):
        item = {
            "package_name": target.STRUCTURED_PACKAGE,
            "version_start_including": "0",
            "version_end_excluding": target.CASE_SPECS["CVE-2023-43630"]["pseudo"],
        }
        self.assertEqual(
            target.claim_signature([item]),
            {
                target.STRUCTURED_PACKAGE: [
                    target.range_tuple(None, target.CASE_SPECS["CVE-2023-43630"]["pseudo"])
                ]
            },
        )

    def test_relation_candidate_is_directional(self):
        self.assertEqual(
            target.set_relation({"9.0.0"}, {"9.0.0", "9.1.0"}),
            "nvd_subset_of_ghsa",
        )
        self.assertEqual(target.candidate_for_relation("nvd_subset_of_ghsa"), "incomplete")


if __name__ == "__main__":
    unittest.main()
