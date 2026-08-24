import unittest

import build_artifact_lineage_development_cohort as target


def record(subject, *, start=None, end=None, criteria=None):
    return {
        "product": subject,
        "package_name": subject,
        "criteria": criteria,
        "version_start_including": start,
        "introduced": start,
        "version_end_excluding": end,
        "fixed": end,
    }


class BuildArtifactLineageDevelopmentCohortTests(unittest.TestCase):
    def test_cpe_prerelease_is_preserved_for_point(self):
        item = record(
            "demo",
            criteria="cpe:2.3:a:vendor:demo:3.0:rc1:*:*:*:*:*:*",
        )
        self.assertEqual(target.cpe_release(item), "3.0-rc-1")
        self.assertEqual(target.record_span(item)["kind"], "point")

    def test_equal_cross_subject_ranges_are_selected(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo", start="1.0", end="2.0")],
            "ghsa_value": [record("org.demo:demo-core", start="1.0", end="2.0")],
            "reference_context": {},
        }
        selected = target.select_row(row)
        self.assertIsNotNone(selected)
        self.assertFalse(selected["selection_uses_reviewer_labels"])

    def test_equal_same_subject_is_not_artifact_mismatch(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo", start="1.0", end="2.0")],
            "ghsa_value": [record("DEMO", start="1.0", end="2.0")],
        }
        self.assertIsNone(target.select_row(row))

    def test_unequal_ranges_are_rejected(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo", start="1.0", end="2.0")],
            "ghsa_value": [record("org.demo:demo-core", start="1.0", end="2.1")],
        }
        self.assertIsNone(target.select_row(row))


if __name__ == "__main__":
    unittest.main()
