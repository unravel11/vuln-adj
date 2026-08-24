#!/usr/bin/env python3
"""Focused tests for branch/release-graph diagnostics."""

from __future__ import annotations

import unittest

from affected_versions_branch_graph import extract_branch_graph_features


def row(nvd_value, ghsa_value, text, url="https://vendor.example/CVE-2026-0001"):
    return {
        "sample_id": "affected_versions_fc_manual_check:test",
        "cve_id": "CVE-2026-0001",
        "nvd_value": nvd_value,
        "ghsa_value": ghsa_value,
        "evidence_context": {
            "records": [
                {
                    "url": url,
                    "host": "vendor.example",
                    "fetch_status": "ok",
                    "title": "Advisory CVE-2026-0001",
                    "text_snippet": text,
                }
            ]
        },
    }


class BranchGraphTests(unittest.TestCase):
    def test_opaque_safe_exception_contradicts_both_flattened_ranges(self):
        features = extract_branch_graph_features(
            row(
                [
                    {
                        "version_start_including": "378.vd6e2874a_69eb",
                        "version_end_including": "396.v86ce29279947",
                    }
                ],
                [
                    {
                        "version_start_including": "378.380.v545b",
                        "version_end_excluding": "397.v907382dd9b",
                    }
                ],
                "CVE-2026-0001 affects 396.v86ce29279947 and earlier, "
                "except 378.380.v545b_1154b_3fb_.",
            )
        )
        self.assertEqual(features["predicted_source"], "neither")
        self.assertIn("opaque_ordinal_exception", features["capability_flags"])

    def test_prerelease_successor_prefers_ghsa(self):
        features = extract_branch_graph_features(
            row(
                [{"version": "0.43.1"}],
                [{"version_end_excluding": "0.43.1b5", "fixed": "0.43.1b5"}],
                "CVE-2026-0001 affects v0.43.1b4 and before.",
            )
        )
        self.assertEqual(features["predicted_source"], "ghsa")

    def test_explicit_endpoint_rejects_open_ended_span(self):
        features = extract_branch_graph_features(
            row(
                [
                    {
                        "version_start_including": "9.0.0",
                        "version_end_excluding": "9.3.3",
                    }
                ],
                [{"version_start_including": "9.0.0"}],
                "CVE-2026-0001 affects versions 9.0.0 through 9.3.2.",
            )
        )
        self.assertEqual(features["predicted_source"], "nvd")
        self.assertIn(
            "explicit_endpoint_vs_open_ended_span", features["capability_flags"]
        )

    def test_endpoint_on_different_major_does_not_conflict(self):
        features = extract_branch_graph_features(
            row(
                [{"version_start_including": "2.0.0"}],
                [{"version_start_including": "2.0.0"}],
                "CVE-2026-0001 affects versions through 1.9.9.",
            )
        )
        self.assertEqual(features["predicted_source"], "abstain")

    def test_multi_branch_gap_is_a_capability_flag_not_a_label(self):
        features = extract_branch_graph_features(
            row(
                [{"version_end_excluding": "7.10"}],
                [{"version_end_excluding": "0.0.0-20220310190112-c0c966dc31e2"}],
                "CVE-2026-0001 is fixed in 7.10 and 8.12.1-lts.",
            )
        )
        self.assertIn("multi_branch_fixed_set_gap", features["capability_flags"])
        self.assertFalse(features["feature_extraction_uses_gold"])


if __name__ == "__main__":
    unittest.main()
