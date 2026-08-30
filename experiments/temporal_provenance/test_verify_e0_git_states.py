import unittest

from temporal_provenance_lib import (
    project_cvelist_v5_record,
    project_ghsa_record,
    project_nvd_record,
)
from verify_e0_git_states import canonical, select_cves, summaries


class IndependentParserTests(unittest.TestCase):
    def test_audit_selection_is_deterministic_and_order_independent(self):
        rows = [{"cve_id": f"CVE-2020-{number:04d}"} for number in range(1, 26)]
        forward = select_cves({"rows": rows})
        reverse = select_cves({"rows": list(reversed(rows))})
        self.assertEqual(forward, reverse)
        self.assertEqual(len(forward), 20)

    def test_independent_ghsa_summary_matches_projection(self):
        record = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2020-0001"],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "demo"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0"},
                                {"introduced": "3.0"},
                                {"last_affected": "3.1"},
                            ],
                        }
                    ],
                    "versions": ["1.0", "1.1"],
                }
            ],
            "references": [
                {
                    "type": "WEB",
                    "url": "https://github.com/o/r/commit/abc",
                    "tags": ["Patch"],
                }
            ],
        }
        raw, projected = summaries(
            "ghsa_advisory_database", record, project_ghsa_record(record)
        )
        self.assertEqual(canonical(raw), canonical(projected))

    def test_independent_nvd_summary_matches_projection(self):
        record = {
            "id": "CVE-2020-0001",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:o:p:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.0",
                                    "matchCriteriaId": "id-1",
                                }
                            ],
                        }
                    ]
                }
            ],
            "affected": [{"source": "cve", "affectedData": {"x": 1}}],
            "references": [{"url": "https://example.test/a"}],
        }
        raw, projected = summaries(
            "fkie_nvd_json_data_feeds", record, project_nvd_record(record)
        )
        self.assertEqual(canonical(raw), canonical(projected))

    def test_independent_cvelist_summary_matches_projection(self):
        record = {
            "cveMetadata": {"cveId": "CVE-2020-0001"},
            "containers": {
                "cna": {
                    "providerMetadata": {"orgId": "org"},
                    "affected": [
                        {
                            "vendor": "vendor",
                            "product": "product",
                            "versions": [{"version": "1.0", "status": "affected"}],
                        }
                    ],
                    "references": [{"url": "https://example.test/b"}],
                },
                "adp": [
                    {
                        "providerMetadata": {"orgId": "adp"},
                        "affected": [],
                        "references": [],
                    }
                ],
            },
        }
        raw, projected = summaries(
            "cvelist_v5", record, project_cvelist_v5_record(record)
        )
        self.assertEqual(canonical(raw), canonical(projected))


if __name__ == "__main__":
    unittest.main()
