#!/usr/bin/env python3

from __future__ import annotations

import unittest

from build_affected_versions_blind_worklist import ALLOWED_KEYS, blind_row, forbidden_keys


class BlindWorklistV2Tests(unittest.TestCase):
    def test_forbidden_keys_are_recursive(self) -> None:
        value = {"safe": [{"prediction_detail": {}}], "gold_source": "nvd"}
        self.assertEqual(
            forbidden_keys(value),
            ["safe[0].prediction_detail", "gold_source"],
        )

    def test_shared_blinder_emits_exact_allowlist(self) -> None:
        row = {
            "sample_id": "affected_versions_holdout_v2:001",
            "cve_id": "CVE-2026-0001",
            "nvd_source_id": "CVE-2026-0001",
            "ghsa_source_id": "GHSA-test",
            "field": "affected_versions",
            "nvd_value": [],
            "ghsa_value": [],
            "nvd_context": {},
            "ghsa_context": {},
            "evidence_context": {"candidate_url_count": 0, "records": []},
            "baseline_status": "factual_conflict",
        }
        blinded = blind_row(row)
        self.assertEqual(set(blinded), set(ALLOWED_KEYS))
        self.assertEqual(forbidden_keys(blinded), [])
        self.assertNotIn("candidate_url_count", blinded["evidence_context"])


if __name__ == "__main__":
    unittest.main()
