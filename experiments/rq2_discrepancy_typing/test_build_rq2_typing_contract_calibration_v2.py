import unittest

import build_rq2_typing_contract_calibration_v2 as target


class BuildContractCalibrationV2Tests(unittest.TestCase):
    def test_normalized_range_signature_matches_cpe_and_ghsa_encoding(self):
        nvd = [{
            "introduced": "1.0.0",
            "version_start_including": "1.0.0",
            "version_end_excluding": "2.0.0",
            "fixed": None,
            "version": "*",
            "vulnerable": True,
        }]
        ghsa = [{
            "introduced": "1.0.0",
            "fixed": "2.0.0",
            "version_end_excluding": "2.0.0",
            "version": None,
            "vulnerable": True,
        }]
        self.assertEqual(
            target.normalized_range_signature(nvd),
            target.normalized_range_signature(ghsa),
        )

    def test_cross_cvss_version_classification(self):
        row = {
            "field": "severity",
            "nvd_value": {"label": "MEDIUM", "score": 6.1, "vector": "CVSS:3.1/AV:N"},
            "ghsa_value": {"label": "MODERATE", "score": None, "vector": "CVSS:4.0/AV:N"},
        }
        self.assertEqual(
            target.classify(row),
            "severity_cross_cvss_version_different_vector",
        )

    def test_singleton_vs_interval_classification(self):
        row = {
            "field": "affected_versions",
            "baseline_status": "representation_discrepancy",
            "nvd_value": [{"version": "1.0.0"}],
            "ghsa_value": [{"introduced": "1.0.0", "fixed": "1.0.1"}],
            "package_names": {"nvd": ["p"], "ghsa": ["p"]},
        }
        self.assertEqual(target.classify(row), "affected_singleton_vs_interval")


if __name__ == "__main__":
    unittest.main()
