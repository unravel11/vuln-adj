import json
import unittest

import analyze_artifact_lineage_unseen_ecosystem as target


class AnalyzeArtifactLineageUnseenEcosystemTests(unittest.TestCase):
    def test_nuget_catalog_uses_url_bound_identity_and_versions(self):
        source = target.CASE_SPECS[target.NUGET_SAMPLE]["components"][
            "Oracle.ManagedDataAccess"
        ]["catalog"]
        catalog = target.parse_catalog(
            source, json.dumps({"versions": ["19.3.0", "21.9.0"]}).encode()
        )
        self.assertTrue(catalog["identity_bound"])
        self.assertEqual(set(catalog["canonical_to_raw"]), {"19.3.0", "21.9.0"})

    def test_pypi_dependency_constraint_is_not_exact_resolution(self):
        source = target.CASE_SPECS[target.PYPI_SAMPLE]["extra_sources"][0]
        body = json.dumps(
            {
                "info": {
                    "name": "langchain",
                    "version": "0.0.245",
                    "requires_dist": ["numexpr (>=2.8.4,<3.0.0)"],
                }
            }
        ).encode()
        parsed = target.parse_pypi_release(source, body)
        self.assertTrue(parsed["passed"])
        self.assertFalse(parsed["dependency_exactly_resolved"])

    def test_crates_caret_dependency_is_not_exact_resolution(self):
        source = target.CASE_SPECS[target.CRATES_SAMPLE]["extra_sources"][0]
        body = json.dumps(
            {
                "dependencies": [
                    {
                        "crate_id": "deno_runtime",
                        "req": "^0.150.0",
                        "kind": "normal",
                        "optional": False,
                    }
                ]
            }
        ).encode()
        parsed = target.parse_crates_dependencies(source, body)
        self.assertTrue(parsed["passed"])
        self.assertFalse(parsed["dependency_exactly_resolved"])

    def test_missing_catalog_boundary_is_fail_closed(self):
        catalog = target.canonical_catalog(
            "deno", "deno", ["1.41.3", "2.2.0", "2.3.0"]
        )
        passed, missing = target.boundaries_in_catalog(
            [
                {
                    "start": "1.41.3",
                    "end": "2.1.13",
                    "start_inclusive": True,
                    "end_inclusive": False,
                    "kind": "range",
                }
            ],
            catalog,
        )
        self.assertFalse(passed)
        self.assertEqual(missing, ["2.1.13"])

    def test_fixed_advancement_gate_rejects_zero_of_three(self):
        cases = [
            {
                "ecosystem": ecosystem,
                "gate": {"passed": False},
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "selection_uses_reviewer_labels": False,
                "upstream_source_conditioned_on_non_human_consensus": False,
            }
            for ecosystem in ("NuGet", "PyPI", "crates.io")
        ]
        gate = target.advancement_gate(cases)
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["status"], "no_go_unseen_ecosystem_graph_unstable")
        self.assertEqual(gate["observed_projection_coverage"], 0)


if __name__ == "__main__":
    unittest.main()
