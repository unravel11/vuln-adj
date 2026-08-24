import unittest

import build_artifact_lineage_multi_component_cohort as target


def record(subject):
    return {
        "product": subject,
        "package_name": subject,
        "version": "1.0.0",
        "criteria": "cpe:2.3:a:demo:demo:1.0.0:*:*:*:*:*:*:*",
    }


class BuildArtifactLineageMultiComponentCohortTests(unittest.TestCase):
    def test_one_product_to_two_components_is_selected(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo")],
            "ghsa_value": [record("org.demo:a"), record("org.demo:b")],
        }
        selected = target.select_row(row)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["ghsa_subjects"], ["org.demo:a", "org.demo:b"])

    def test_one_to_one_row_is_excluded(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo")],
            "ghsa_value": [record("org.demo:a")],
        }
        self.assertIsNone(target.select_row(row))

    def test_selection_never_claims_human_gold(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2099-0001",
            "field": "affected_versions",
            "nvd_value": [record("demo")],
            "ghsa_value": [record("org.demo:a"), record("org.demo:b")],
        }
        selected = target.select_row(row)
        self.assertFalse(selected["selection_uses_reviewer_labels"])
        self.assertFalse(selected["label_is_human"])


if __name__ == "__main__":
    unittest.main()
