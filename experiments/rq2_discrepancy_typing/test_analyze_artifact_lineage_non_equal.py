import json
import unittest

from packaging.version import Version

import analyze_artifact_lineage_non_equal as target


class AnalyzeArtifactLineageNonEqualTests(unittest.TestCase):
    def test_version_normalization_unifies_prerelease_spellings(self):
        self.assertEqual(
            target.normalized_version("6.3.0-alpha-1"),
            target.normalized_version("6.3.0-alpha.1"),
        )

    def test_equivalent_prerelease_spellings_have_stable_tie_break(self):
        values = {"6.3.0-alpha-1", "6.3.0-alpha.1"}
        self.assertEqual(
            sorted(values, key=lambda value: (target.normalized_version(value), value)),
            ["6.3.0-alpha-1", "6.3.0-alpha.1"],
        )

    def test_set_relation_distinguishes_containment(self):
        self.assertEqual(target.set_relation({"1", "2"}, {"1", "2", "3"}), "strict_subset")
        self.assertEqual(target.relation_candidate("strict_subset"), "incomplete")

    def test_point_claim_selects_only_exact_release(self):
        record = {
            "criteria": "cpe:2.3:a:demo:demo:1.2.3:*:*:*:*:*:*:*",
            "version": "1.2.3",
        }
        self.assertTrue(target.record_contains(record, Version("1.2.3")))
        self.assertFalse(target.record_contains(record, Version("1.2.4")))

    def test_packagist_catalog_binds_identity_and_versions(self):
        source = target.source("demo", "sample:1", "https://example.test", "packagist_catalog", "demo/pkg")
        body = json.dumps(
            {"packages": {"demo/pkg": [
                {"name": "demo/pkg", "version": "v1.2.3", "source": {"url": "https://github.com/demo/pkg.git"}},
                {"version": "v1.2.2"},
            ]}}
        ).encode()
        parsed = target.parse_catalog(source, body)
        self.assertTrue(parsed["identity_bound"])
        self.assertIn("1.2.3", parsed["canonical_to_raw"])
        self.assertIn("1.2.2", parsed["canonical_to_raw"])

    def test_advancement_gate_fails_low_consistency(self):
        cases = [
            {"gate": {"passed": True}, "label_is_human": False, "eligible_for_human_gold_claim": False}
            for _ in range(5)
        ]
        consistency = [{"matches_both": index < 2} for index in range(5)]
        gate = target.advancement_gate(cases, consistency)
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["status"], "no_go_non_equal_graph_unstable")


if __name__ == "__main__":
    unittest.main()
