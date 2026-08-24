#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_affected_versions_blind_worklist as target


class BlindWorklistTests(unittest.TestCase):
    def test_blind_row_drops_baseline_fields(self) -> None:
        row = {key: {} for key in target.ALLOWED_KEYS}
        row.update(
            {
                "sample_id": "sample:001",
                "cve_id": "CVE-2026-0001",
                "nvd_source_id": "CVE-2026-0001",
                "ghsa_source_id": "GHSA-test",
                "field": "affected_versions",
                "nvd_value": [],
                "ghsa_value": [],
                "evidence_context": {"candidate_url_count": 0, "records": []},
                "baseline_status": "factual_conflict",
                "baseline_note": "must not survive",
            }
        )
        blinded = target.blind_row(row)
        self.assertNotIn("baseline_status", blinded)
        self.assertNotIn("baseline_note", blinded)
        self.assertEqual(set(blinded), set(target.ALLOWED_KEYS))

    def test_recursive_forbidden_key_is_rejected(self) -> None:
        row = {key: {} for key in target.ALLOWED_KEYS}
        row["sample_id"] = "sample:001"
        row["evidence_context"] = {"records": [{"gold_label": "hidden"}]}
        with self.assertRaisesRegex(ValueError, "forbidden keys"):
            target.blind_row(row)


if __name__ == "__main__":
    unittest.main()
