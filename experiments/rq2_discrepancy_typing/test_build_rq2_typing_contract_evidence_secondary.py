import unittest

import build_rq2_typing_contract_evidence_secondary as target


class BuildTypingContractEvidenceSecondaryTests(unittest.TestCase):
    def test_normalize_ghsa_preserves_package_and_range(self):
        source = target.EVIDENCE_SOURCES[0]
        payload = {
            "ghsa_id": "GHSA-cmvg-w72j-7phx",
            "cve_id": target.TARGET_CVE_ID,
            "summary": "summary",
            "description": "description",
            "published_at": "2023-01-01T00:00:00Z",
            "vulnerabilities": [{
                "package": {"ecosystem": "Maven", "name": "org.xwiki.platform:xwiki-platform-skin-skinx"},
                "vulnerable_version_range": ">= 3.0-milestone-1, < 14.9-rc-1",
                "first_patched_version": {"identifier": "14.9-rc-1"},
            }],
        }
        record = target.normalize_evidence(
            source, payload,
            {"http_status": 200, "response_sha256": "abc", "fetched_at": "2026-01-01T00:00:00Z"},
        )
        self.assertIn("xwiki-platform-skin-skinx", record["text_snippet"])
        self.assertIn("14.9-rc-1", record["text_snippet"])

    def test_blind_row_keeps_evidence_and_omits_parent_decisions(self):
        source = {
            "sample_id": target.TARGET_SAMPLE_ID,
            "cve_id": target.TARGET_CVE_ID,
            "nvd_source_id": target.TARGET_CVE_ID,
            "ghsa_source_id": "GHSA-cmvg-w72j-7phx",
            "field": "affected_versions",
            "nvd_value": [],
            "ghsa_value": [],
            "field_context": {},
            "package_names": {"nvd": ["xwiki"], "ghsa": ["component"]},
            "reference_context": {"nvd_urls": [], "ghsa_urls": []},
            "prior_non_human_consensus_label": "representation_discrepancy",
        }
        blind = target.build_blind_row(source, [{"url": "https://example.test"}])
        self.assertIn("evidence_context", blind)
        self.assertNotIn("prior_non_human_consensus_label", blind)


if __name__ == "__main__":
    unittest.main()
