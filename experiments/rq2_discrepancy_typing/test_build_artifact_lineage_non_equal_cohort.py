import unittest

import build_artifact_lineage_development_cohort as equal_cohort
import build_artifact_lineage_non_equal_cohort as target


def record(subject, start, end):
    return {
        "product": subject,
        "package_name": subject,
        "version_start_including": start,
        "introduced": start,
        "version_end_excluding": end,
        "fixed": end,
    }


class BuildArtifactLineageNonEqualCohortTests(unittest.TestCase):
    def test_non_equal_cross_subject_row_is_selected(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo", "1.0", "2.0")],
            "ghsa_value": [record("org.demo:core", "1.0", "2.1")],
        }
        selected = target.select_row(row)
        self.assertIsNotNone(selected)
        self.assertFalse(selected["selection_uses_reviewer_labels"])

    def test_equal_range_row_is_excluded(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo", "1.0", "2.0")],
            "ghsa_value": [record("org.demo:core", "1.0", "2.0")],
        }
        self.assertIsNone(target.select_row(row))

    def test_prior_xwiki_case_is_excluded(self):
        row = {
            "sample_id": "rq2_typing_holdout_v1:148",
            "cve_id": "CVE-2023-29206",
            "field": "affected_versions",
            "nvd_value": [record("xwiki", "3.0", "14.8")],
            "ghsa_value": [record("org.xwiki:skinx", "3.0-m1", "14.9-rc1")],
        }
        self.assertIsNone(target.select_row(row))


if __name__ == "__main__":
    unittest.main()
