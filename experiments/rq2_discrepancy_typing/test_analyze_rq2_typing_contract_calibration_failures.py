import unittest

import analyze_rq2_typing_contract_calibration_failures as target


class AnalyzeContractCalibrationFailuresTests(unittest.TestCase):
    def test_cvss_version(self):
        self.assertEqual(
            target.cvss_version({"vector": "CVSS:3.1/AV:N/AC:L"}), "3.1"
        )
        self.assertIsNone(target.cvss_version({"vector": "AV:N/AC:L"}))

    def test_prerelease_detection(self):
        self.assertTrue(target.has_prerelease_token([{"fixed": "15.10-rc-1"}]))
        self.assertFalse(target.has_prerelease_token([{"fixed": "15.10.1"}]))

    def test_singleton_and_range_detection(self):
        self.assertTrue(target.concrete_singletons([{"version": "1.2.3"}]))
        self.assertFalse(target.concrete_singletons([{"version": "*"}]))
        self.assertTrue(
            target.contains_range([{"introduced": "1.2.3", "fixed": "1.2.4"}])
        )

    def test_failure_bucket_prioritizes_unresolved_identity(self):
        source = {
            "field": "affected_versions",
            "nvd_value": [{"version": "1.0.0"}],
            "ghsa_value": [{"introduced": "1.0.0", "fixed": "1.0.1"}],
        }
        case = {
            "reviewer_a": {"discrepancy_label": "representation_discrepancy"},
            "reviewer_b": {"discrepancy_label": "uncertain"},
        }
        self.assertEqual(
            target.failure_bucket(source, case), "unresolved_artifact_identity"
        )

    def test_failure_bucket_cross_cvss_version(self):
        source = {
            "field": "severity",
            "nvd_value": {"vector": "CVSS:3.1/AV:N"},
            "ghsa_value": {"vector": "CVSS:4.0/AV:N"},
        }
        case = {
            "reviewer_a": {"discrepancy_label": "representation_discrepancy"},
            "reviewer_b": {"discrepancy_label": "representation_discrepancy"},
        }
        self.assertEqual(
            target.failure_bucket(source, case),
            "cross_cvss_version_noncomparable_vectors",
        )


if __name__ == "__main__":
    unittest.main()
