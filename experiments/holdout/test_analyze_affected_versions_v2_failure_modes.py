#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_affected_versions_v2_failure_modes as target


def mapping(nvd=None, ghsa=None, third=None) -> dict:
    return {"nvd": nvd or [], "ghsa": ghsa or [], "third": third or []}


def decision(url: str) -> dict:
    return {
        "positive_support": mapping(nvd=[url]),
        "contradiction_or_scope_exclusion": mapping(ghsa=[url]),
    }


class FailureAnalysisTests(unittest.TestCase):
    def test_evidence_url_classes(self) -> None:
        cases = {
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0001": "nvd_record",
            "https://github.com/org/repo/security/advisories/GHSA-test": "upstream_github_advisory",
            "https://github.com/pypa/advisory-database/tree/main/vulns/x.yaml": "ecosystem_advisory_database",
            "https://www.openwall.com/lists/oss-security/2024/01/01/1": "mailing_list_disclosure",
            "https://devhub.checkmarx.com/cve-details/CVE-2025-0001": "secondary_aggregator",
            "https://github.com/org/repo/commit/abc": "github_code_or_poc",
        }
        for url, expected in cases.items():
            self.assertEqual(target.classify_evidence_url(url), expected)

    def test_same_nvd_page_is_not_primary_evidence(self) -> None:
        url = "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"
        profile = target.evidence_profile(decision(url), decision(url))
        self.assertTrue(profile["same_single_url"])
        self.assertTrue(profile["only_nvd_record_collectively"])
        self.assertFalse(
            profile["at_least_one_reviewer_has_primary_or_ecosystem_evidence"]
        )

    def test_two_upstream_advisories_count_for_both_reviewers(self) -> None:
        left = decision(
            "https://github.com/org/repo/security/advisories/GHSA-left"
        )
        right = decision("https://www.openwall.com/lists/oss-security/2024/01/01/1")
        profile = target.evidence_profile(left, right)
        self.assertFalse(profile["same_exact_url_set"])
        self.assertTrue(profile["both_reviewers_have_primary_or_ecosystem_evidence"])


if __name__ == "__main__":
    unittest.main()
