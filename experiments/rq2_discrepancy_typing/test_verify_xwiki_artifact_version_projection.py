import copy
import unittest

import verify_xwiki_artifact_version_projection as target


def valid_analysis():
    return {
        "schema_version": target.audit.SCHEMA_VERSION,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "sample_id": target.audit.secondary.TARGET_SAMPLE_ID,
        "current_coordinate": target.audit.CURRENT_COORDINATE,
        "legacy_coordinate_observed": target.audit.LEGACY_COORDINATE,
        "current_release_catalog": {
            "first_release": "3.1-milestone-1",
            "ghsa_start": "3.0-milestone-1",
            "ghsa_start_present": False,
            "nvd_explicit_present": {
                "3.0": False,
                "3.0-milestone-2": False,
                "3.0-milestone-3": False,
                "3.0-rc-1": False,
            },
        },
        "source_path_probe": {
            "xwiki_web_3_0_milestone_1_http_status": 404,
            "xwiki_web_3_0_http_status": 404,
        },
        "gate": {
            "status": "abstain_artifact_version_projection_unresolved",
            "passed": False,
            "typing_disposition": "uncertain",
            "failed_checks": [
                "ghsa_lower_bound_exists_in_current_lineage",
                "nvd_explicit_versions_exist_in_current_lineage",
                "legacy_to_current_lineage_mapping_bound",
            ],
        },
    }


class VerifyXWikiArtifactVersionProjectionTests(unittest.TestCase):
    def test_accepts_expected_fail_closed_analysis(self):
        target.validate_analysis(valid_analysis())

    def test_rejects_incomplete_without_lineage_evidence(self):
        analysis = copy.deepcopy(valid_analysis())
        analysis["gate"].update(
            {
                "status": "artifact_version_projection_allowed",
                "passed": True,
                "typing_disposition": "incomplete",
            }
        )
        with self.assertRaisesRegex(ValueError, "fail closed"):
            target.validate_analysis(analysis)

    def test_rejects_claim_that_ghsa_start_exists(self):
        analysis = copy.deepcopy(valid_analysis())
        analysis["current_release_catalog"]["ghsa_start_present"] = True
        with self.assertRaisesRegex(ValueError, "unexpectedly exists"):
            target.validate_analysis(analysis)


if __name__ == "__main__":
    unittest.main()
