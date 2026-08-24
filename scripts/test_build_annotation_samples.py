#!/usr/bin/env python3
"""Focused tests for refreshing frozen annotation cohorts."""

from __future__ import annotations

import unittest

from build_annotation_samples import refresh_existing_rows


SPEC = {
    "name": "affected_versions_fc_manual_check",
    "field": "affected_versions",
    "status": "factual_conflict",
}


def candidate(cve_id: str, nvd_value: list[dict]) -> dict:
    return {
        "_line_number": 42,
        "cve_id": cve_id,
        "nvd_source_id": cve_id,
        "ghsa_source_id": "GHSA-test",
        "field_discrepancies": {
            "affected_versions": {
                "status": "factual_conflict",
                "note": "refreshed",
                "nvd_value": nvd_value,
                "ghsa_value": [{"fixed": "2.0.0"}],
            }
        },
        "unified_view": {
            "severity": {"nvd": {}, "ghsa": {}},
            "published": {"nvd": None, "ghsa": None},
            "package_names": {"nvd": ["widget"], "ghsa": ["widget"]},
            "references": {"nvd_urls": [], "ghsa_urls": []},
        },
    }


class RefreshExistingRowsTest(unittest.TestCase):
    def test_preserves_identity_and_annotation_while_refreshing_values(self) -> None:
        annotation = {
            "manual_label": "uncertain",
            "is_baseline_false_positive": "",
            "adjudicated_source": "abstain",
            "adjudicated_value": "",
            "evidence_urls": [],
            "evidence_notes": "reviewed",
            "annotator_notes": "keep me",
        }
        existing = [
            {
                "sample_id": "affected_versions_fc_manual_check:017",
                "cve_id": "CVE-2025-26646",
                "nvd_value": [{"version": "stale"}],
                "annotation": annotation,
            }
        ]
        current_value = [{"version": "1.2.3"}]

        refreshed = refresh_existing_rows(
            [candidate("CVE-2025-26646", current_value)], existing, SPEC
        )

        self.assertEqual(
            refreshed[0]["sample_id"], "affected_versions_fc_manual_check:017"
        )
        self.assertEqual(refreshed[0]["source_line_number"], 42)
        self.assertEqual(refreshed[0]["nvd_value"], current_value)
        self.assertEqual(refreshed[0]["annotation"], annotation)

    def test_rejects_existing_row_that_is_no_longer_eligible(self) -> None:
        existing = [
            {
                "sample_id": "affected_versions_fc_manual_check:001",
                "cve_id": "CVE-2025-0001",
            }
        ]

        with self.assertRaisesRegex(RuntimeError, "no longer matches"):
            refresh_existing_rows([], existing, SPEC)


if __name__ == "__main__":
    unittest.main()
