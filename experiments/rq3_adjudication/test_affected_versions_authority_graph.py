#!/usr/bin/env python3

from __future__ import annotations

import unittest

import affected_versions_authority_graph as target


def record(url: str) -> dict:
    return {
        "url": url,
        "fetch_status": "ok",
        "text_snippet": "CVE-2025-0001 is affected before version 2.0.0",
    }


class AuthorityGraphTests(unittest.TestCase):
    def test_authority_classes_are_ordered(self) -> None:
        self.assertEqual(
            target.classify_evidence_authority(
                "https://github.com/org/repo/security/advisories/GHSA-test"
            ),
            ("upstream_github_advisory", 3),
        )
        self.assertEqual(
            target.classify_evidence_authority(
                "https://github.com/pypa/advisory-database/tree/main/vulns/x.yaml"
            ),
            ("ecosystem_advisory_database", 2),
        )
        self.assertEqual(
            target.classify_evidence_authority(
                "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"
            ),
            ("nvd_record", 0),
        )

    def test_filter_uses_only_highest_eligible_tier(self) -> None:
        upstream = record(
            "https://github.com/org/repo/security/advisories/GHSA-test"
        )
        ecosystem = record(
            "https://github.com/pypa/advisory-database/tree/main/vulns/x.yaml"
        )
        nvd = record("https://nvd.nist.gov/vuln/detail/CVE-2025-0001")
        selected, profile = target.authority_filtered_records(
            {"evidence_context": {"records": [nvd, ecosystem, upstream]}}
        )
        self.assertEqual(selected, [upstream])
        self.assertEqual(profile["selected_authority_tier"], 3)

    def test_nvd_only_evidence_abstains_without_fallback(self) -> None:
        row = {
            "cve_id": "CVE-2025-0001",
            "nvd_value": [],
            "ghsa_value": [],
            "evidence_context": {
                "records": [
                    record("https://nvd.nist.gov/vuln/detail/CVE-2025-0001")
                ]
            },
        }
        prediction = target.predict_authority_filtered_source(row)
        self.assertEqual(prediction["predicted_source"], "abstain")
        self.assertEqual(
            prediction["source_prediction_reason"],
            "no_primary_or_ecosystem_evidence_record",
        )


if __name__ == "__main__":
    unittest.main()
