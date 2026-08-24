import unittest

import analyze_xwiki_artifact_version_projection as target


class AnalyzeXWikiArtifactVersionProjectionTests(unittest.TestCase):
    def test_normalize_cpe_prerelease_updates(self):
        cases = {
            "cpe:2.3:a:xwiki:xwiki:3.0:milestone_2:*:*:*:*:*:*": "3.0-milestone-2",
            "cpe:2.3:a:xwiki:xwiki:3.0:milestone3:*:*:*:*:*:*": "3.0-milestone-3",
            "cpe:2.3:a:xwiki:xwiki:3.0:rc1:*:*:*:*:*:*": "3.0-rc-1",
            "cpe:2.3:a:xwiki:xwiki:3.0:-:*:*:*:*:*:*": "3.0",
        }
        for criteria, expected in cases.items():
            with self.subTest(criteria=criteria):
                self.assertEqual(
                    target.normalize_cpe_release({"criteria": criteria}), expected
                )

    def test_pom_identity_inherits_group_and_version(self):
        body = b"""<project xmlns="http://maven.apache.org/POM/4.0.0">
        <parent><groupId>org.xwiki.platform</groupId><artifactId>parent</artifactId>
        <version>14.9-rc-1</version></parent>
        <artifactId>xwiki-platform-skin-skinx</artifactId></project>"""
        self.assertEqual(
            target.pom_identity(body),
            {
                "group_id": "org.xwiki.platform",
                "artifact_id": "xwiki-platform-skin-skinx",
                "version": "14.9-rc-1",
                "coordinate": target.CURRENT_COORDINATE,
            },
        )

    def test_projection_gate_fails_closed_on_lineage_gaps(self):
        checks = {
            "component_membership_bound": True,
            "same_version_release_policy_bound": True,
            "current_lineage_poms_match_release_versions": True,
            "ghsa_lower_bound_exists_in_current_lineage": False,
            "nvd_explicit_versions_exist_in_current_lineage": False,
            "legacy_to_current_lineage_mapping_bound": False,
            "upper_bound_versions_exist_in_current_lineage": True,
        }
        gate = target.projection_gate(checks)
        self.assertFalse(gate["passed"])
        self.assertEqual(
            gate["status"], "abstain_artifact_version_projection_unresolved"
        )
        self.assertEqual(gate["typing_disposition"], "uncertain")

    def test_projection_gate_allows_only_all_bound_checks(self):
        checks = {
            name: True
            for name in (
                "component_membership_bound",
                "same_version_release_policy_bound",
                "current_lineage_poms_match_release_versions",
                "ghsa_lower_bound_exists_in_current_lineage",
                "nvd_explicit_versions_exist_in_current_lineage",
                "legacy_to_current_lineage_mapping_bound",
                "upper_bound_versions_exist_in_current_lineage",
            )
        }
        gate = target.projection_gate(checks)
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["typing_disposition"], "compare_sets")


if __name__ == "__main__":
    unittest.main()
