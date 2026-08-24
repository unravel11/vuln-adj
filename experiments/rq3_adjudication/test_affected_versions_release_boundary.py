#!/usr/bin/env python3
"""Focused tests for release-boundary evidence extraction."""

from __future__ import annotations

import unittest

from affected_versions_release_boundary import (
    extract_evidence_claims,
    extract_release_boundary_features,
)


def row(nvd_value, ghsa_value, text):
    return {
        "sample_id": "affected_versions_fc_manual_check:test",
        "cve_id": "CVE-2026-0001",
        "nvd_value": nvd_value,
        "ghsa_value": ghsa_value,
        "evidence_context": {
            "records": [
                {
                    "url": "https://vendor.example/advisory",
                    "host": "vendor.example",
                    "fetch_status": "ok",
                    "title": "Advisory CVE-2026-0001",
                    "text_snippet": text,
                }
            ]
        },
    }


class ReleaseBoundaryTests(unittest.TestCase):
    def test_fixed_release_inside_flat_range_prefers_ghsa(self):
        features = extract_release_boundary_features(
            row(
                [{"version_end_excluding": "2.12.0"}],
                [{"version_end_excluding": "2.11.1", "fixed": "2.11.1"}],
                "Versions prior to 2.12.0 and 2.11.1 are affected. "
                "A fix is included in 2.12.0 and 2.11.1.",
            )
        )
        self.assertEqual(features["predicted_source"], "ghsa")

    def test_affected_endpoint_and_fixed_successor_support_both(self):
        features = extract_release_boundary_features(
            row(
                [{"version_end_including": "3909.v1f2c633e8590"}],
                [
                    {
                        "version_end_excluding": "3910.ve59cec5e33ea",
                        "fixed": "3910.ve59cec5e33ea",
                    }
                ],
                "Kubernetes 3909.v1f2c633e8590 and earlier are affected. "
                "The updated release 3910.ve59cec5e33ea_ contains fixes.",
            )
        )
        self.assertEqual(features["predicted_source"], "both")

    def test_vulnerable_point_contradicts_fixed_boundary(self):
        features = extract_release_boundary_features(
            row(
                [{"version": "3.6.7"}],
                [{"version_end_excluding": "3.6.7", "fixed": "3.6.7"}],
                "NodeBB 3.6.7 is vulnerable to incorrect access control.",
            )
        )
        self.assertEqual(features["predicted_source"], "nvd")

    def test_no_claim_cue_abstains(self):
        features = extract_release_boundary_features(
            row(
                [{"version": "1.2.3"}],
                [{"version_end_excluding": "1.2.4", "fixed": "1.2.4"}],
                "Release index: 1.2.3, 1.2.4.",
            )
        )
        self.assertEqual(features["predicted_source"], "abstain")

    def test_fixed_cue_does_not_cross_sentence(self):
        sample = row(
            [{"version_start_including": "2.10.0"}],
            [{"version_end_excluding": "2.10.4", "fixed": "2.10.4"}],
            "Users should upgrade to at least 2.9.5. "
            "2.10 users should upgrade to at least 2.10.4.",
        )
        claims = extract_evidence_claims(sample)
        roles = {
            claim["token"]: set(claim["roles"])
            for claim in claims
            if claim["token"] in {"2.10", "2.10.4"}
        }
        self.assertNotIn("fixed_boundary", roles.get("2.10", set()))
        self.assertIn("fixed_boundary", roles["2.10.4"])

    def test_unaffected_cue_binds_to_its_own_version(self):
        sample = row(
            [{"version": "2.11.0"}],
            [{"version_end_excluding": "2.11.1", "fixed": "2.11.1"}],
            "Users should upgrade to at least 2.11.1. 3.0 is unaffected.",
        )
        claims = extract_evidence_claims(sample)
        roles = {
            claim["token"]: set(claim["roles"])
            for claim in claims
            if claim["token"] in {"2.11.1", "3.0"}
        }
        self.assertEqual(roles["2.11.1"], {"fixed_boundary"})
        self.assertEqual(roles["3.0"], {"safe_exception"})


if __name__ == "__main__":
    unittest.main()
