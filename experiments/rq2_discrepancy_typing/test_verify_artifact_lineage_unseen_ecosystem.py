import unittest

import verify_artifact_lineage_unseen_ecosystem as target


def fixed_analysis():
    failure_sets = {
        target.target.NUGET_SAMPLE: [
            "component_boundaries_in_registry_catalogs",
            "nvd_product_release_domain_bound",
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        ],
        target.target.PYPI_SAMPLE: [
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        ],
        target.target.CRATES_SAMPLE: [
            "component_boundaries_in_registry_catalogs",
            "nvd_product_release_domain_bound",
            "deterministic_component_to_product_release_mapping",
            "affected_component_union_mappable",
            "shared_product_release_domain_bound",
            "set_relation_computed",
        ],
    }
    return {
        "row_count": 3,
        "projection_gate_passed": 0,
        "component_heterogeneity_count": 3,
        "candidate_counts": {"uncertain": 3},
        "advancement_gate": {
            "status": "no_go_unseen_ecosystem_graph_unstable",
            "passed": False,
            "observed_projection_coverage": 0,
            "observed_passing_ecosystems": [],
            "failed_checks": [
                "minimum_projection_coverage",
                "minimum_passing_ecosystems",
            ],
        },
        "cases": [
            {"sample_id": sample_id, "gate": {"failed_checks": failures}}
            for sample_id, failures in failure_sets.items()
        ],
    }


class VerifyArtifactLineageUnseenEcosystemTests(unittest.TestCase):
    def test_fixed_outcome_accepts_expected_no_go(self):
        target.verify_fixed_outcome(fixed_analysis())

    def test_fixed_outcome_rejects_any_projection_pass(self):
        analysis = fixed_analysis()
        analysis["projection_gate_passed"] = 1
        with self.assertRaisesRegex(ValueError, "0/3"):
            target.verify_fixed_outcome(analysis)


if __name__ == "__main__":
    unittest.main()
