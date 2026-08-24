import unittest

import analyze_xwiki_artifact_version_projection_v2 as target


class AnalyzeXWikiArtifactVersionProjectionV2Tests(unittest.TestCase):
    def test_xwiki_version_ordering(self):
        values = [
            "3.0-milestone-1",
            "3.0-milestone-2",
            "3.0-milestone-3",
            "3.0-rc-1",
            "3.0",
            "3.0.1",
            "3.1-milestone-1",
        ]
        self.assertEqual(sorted(values, key=target.xwiki_version_key), values)

    def test_release_projection_is_strict_subset(self):
        current = [
            "3.1-milestone-1",
            "3.1",
            "14.8-rc-1",
            "14.8",
            "14.9-rc-1",
        ]
        explicit = [
            "3.0-milestone-2",
            "3.0-milestone-3",
            "3.0-rc-1",
            "3.0",
        ]
        result = target.build_release_sets(current, explicit)
        self.assertEqual(result["relation"], "strict_subset")
        self.assertEqual(result["ghsa_only"], ["3.0-milestone-1"])
        self.assertEqual(result["nvd_only"], [])

    def test_skinx_dependency_extracts_property_reference(self):
        body = b"""<project xmlns="http://maven.apache.org/POM/4.0.0">
        <dependencies><dependency><groupId>com.xpn.xwiki.platform.plugins</groupId>
        <artifactId>xwiki-plugin-skinx</artifactId>
        <version>${platform.plugin.skinx.version}</version>
        </dependency></dependencies></project>"""
        self.assertEqual(
            target.skinx_dependency(body),
            {
                "coordinate": target.v1.LEGACY_COORDINATE,
                "version_expression": "${platform.plugin.skinx.version}",
            },
        )

    def test_gate_emits_non_human_incomplete_candidate(self):
        checks = {
            "all_product_dependency_edges_bound": True,
            "all_legacy_poms_bound": True,
            "legacy_release_classes_present": True,
            "legacy_to_current_source_continuity_bound": True,
            "unified_release_domain_bound": True,
            "strict_subset_computed": True,
        }
        gate = target.projection_gate(checks, "strict_subset")
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["development_typing_candidate"], "incomplete")
        self.assertFalse(gate["label_is_human"])

    def test_gate_fails_when_source_continuity_is_missing(self):
        checks = {
            "all_product_dependency_edges_bound": True,
            "all_legacy_poms_bound": True,
            "legacy_release_classes_present": True,
            "legacy_to_current_source_continuity_bound": False,
            "unified_release_domain_bound": True,
            "strict_subset_computed": True,
        }
        gate = target.projection_gate(checks, "strict_subset")
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["development_typing_candidate"], "uncertain")


if __name__ == "__main__":
    unittest.main()
