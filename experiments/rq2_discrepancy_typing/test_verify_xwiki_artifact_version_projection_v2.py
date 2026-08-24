import copy
import unittest

import verify_xwiki_artifact_version_projection_v2 as target


def valid_analysis():
    edges = {
        product: {
            "legacy_coordinate": target.audit.v1.LEGACY_COORDINATE,
            "legacy_version": legacy,
            "core_version": product,
            "edge_bound": True,
        }
        for product, legacy in target.audit.EXPECTED_PRODUCT_TO_LEGACY.items()
    }
    presence = {
        version: {name: True for name in target.audit.RELEVANT_CLASSES}
        for version in (*target.audit.LEGACY_VERSIONS, "3.1-milestone-1")
    }
    checks = {
        "all_product_dependency_edges_bound": True,
        "all_legacy_poms_bound": True,
        "legacy_release_classes_present": True,
        "legacy_to_current_source_continuity_bound": True,
        "unified_release_domain_bound": True,
        "strict_subset_computed": True,
    }
    return {
        "schema_version": target.audit.SCHEMA_VERSION,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "post_unsealing_conditional_analysis": True,
        "sample_id": target.audit.v1.secondary.TARGET_SAMPLE_ID,
        "product_to_legacy_edges": edges,
        "source_lineage": {
            "relevant_files_checked": len(target.audit.RELEVANT_CLASSES),
            "transition_common_relevant_files": len(target.audit.RELEVANT_CLASSES),
            "transition_identical_relevant_files": len(target.audit.RELEVANT_CLASSES),
            "source_continuity_bound": True,
            "relevant_class_presence": presence,
        },
        "release_set_projection": {
            "nvd_release_count": 10,
            "ghsa_release_count": 11,
            "relation": "strict_subset",
            "nvd_only": [],
            "ghsa_only": ["3.0-milestone-1"],
        },
        "checks": checks,
        "gate": {
            "status": "artifact_version_projection_allowed_development_only",
            "passed": True,
            "required_checks": list(checks),
            "failed_checks": [],
            "development_typing_candidate": "incomplete",
            "label_is_human": False,
        },
    }


class VerifyXWikiArtifactVersionProjectionV2Tests(unittest.TestCase):
    def test_accepts_expected_development_candidate(self):
        target.validate_analysis(valid_analysis())

    def test_rejects_human_label_claim(self):
        analysis = copy.deepcopy(valid_analysis())
        analysis["label_is_human"] = True
        with self.assertRaisesRegex(ValueError, "non-human"):
            target.validate_analysis(analysis)

    def test_rejects_missing_product_dependency_edge(self):
        analysis = copy.deepcopy(valid_analysis())
        analysis["product_to_legacy_edges"]["3.0-milestone-1"]["edge_bound"] = False
        with self.assertRaisesRegex(ValueError, "not bound"):
            target.validate_analysis(analysis)

    def test_rejects_extra_ghsa_only_release(self):
        analysis = copy.deepcopy(valid_analysis())
        analysis["release_set_projection"]["ghsa_only"].append("3.0-milestone-2")
        with self.assertRaisesRegex(ValueError, "drifted"):
            target.validate_analysis(analysis)


if __name__ == "__main__":
    unittest.main()
