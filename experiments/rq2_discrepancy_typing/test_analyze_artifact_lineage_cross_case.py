import unittest

import analyze_artifact_lineage_cross_case as target


class AnalyzeArtifactLineageCrossCaseTests(unittest.TestCase):
    def test_semantic_version_ordering_supports_release_tokens(self):
        values = ["2.0.0", "2.4.16", "2.5.0", "2.5.12"]
        self.assertEqual(sorted(values, key=target.semantic_version_key), values)

    def test_maven_pom_extractor_binds_identity_and_version(self):
        source = target.EvidenceSource(
            key="demo",
            sample_id="sample:1",
            version="1.2.3",
            url="https://repo.maven.apache.org/maven2/org/demo/core/1.2.3/core-1.2.3.pom",
            parser="maven_pom",
            expected_identity="org.demo:core",
        )
        body = b'''<project xmlns="http://maven.apache.org/POM/4.0.0">
        <groupId>org.demo</groupId><artifactId>core</artifactId>
        <version>1.2.3</version><name>Demo Core</name></project>'''
        self.assertTrue(target.extract_evidence(source, body)["passed"])

    def test_composer_extractor_binds_root_package(self):
        source = target.EvidenceSource(
            key="demo",
            sample_id="sample:1",
            version="1.2.3",
            url="https://raw.githubusercontent.com/demo/demo/1.2.3/composer.json",
            parser="composer_manifest",
            expected_identity="demo/demo",
        )
        self.assertTrue(
            target.extract_evidence(source, b'{"name":"demo/demo"}')["passed"]
        )

    def test_go_extractor_binds_module(self):
        source = target.EvidenceSource(
            key="demo",
            sample_id="sample:1",
            version="1.2.3",
            url="https://raw.githubusercontent.com/demo/demo/v1.2.3/go.mod",
            parser="go_module",
            expected_identity="github.com/demo/demo",
        )
        self.assertTrue(
            target.extract_evidence(source, b"module github.com/demo/demo\n")["passed"]
        )

    def test_gate_allows_equal_relation_only_when_all_checks_pass(self):
        checks = {name: True for name in (
            "claim_subjects_bound", "boundary_releases_bound",
            "lineage_path_complete", "ordering_supported",
            "shared_release_domain_bound", "set_relation_computed",
        )}
        gate = target.projection_gate(checks, "equal")
        self.assertTrue(gate["passed"])
        self.assertEqual(gate["development_typing_candidate"], "representation_discrepancy")
        self.assertFalse(gate["label_is_human"])

    def test_gate_abstains_when_identity_is_unbound(self):
        checks = {name: True for name in (
            "claim_subjects_bound", "boundary_releases_bound",
            "lineage_path_complete", "ordering_supported",
            "shared_release_domain_bound", "set_relation_computed",
        )}
        checks["claim_subjects_bound"] = False
        gate = target.projection_gate(checks, "equal")
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["development_typing_candidate"], "uncertain")


if __name__ == "__main__":
    unittest.main()
