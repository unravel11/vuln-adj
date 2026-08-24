#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import build_affected_versions_holdout_v2 as target


def row(cve_id: str) -> dict:
    return {
        "_source_line_number": 1,
        "cve_id": cve_id,
        "nvd_source_id": f"NVD-{cve_id}",
        "ghsa_source_id": f"GHSA-{cve_id}",
        "field_discrepancies": {
            "affected_versions": {
                "status": "factual_conflict",
                "note": "test",
                "nvd_value": [],
                "ghsa_value": [],
            }
        },
        "unified_view": {
            "severity": {"nvd": None, "ghsa": None},
            "published": {"nvd": None, "ghsa": None},
            "package_names": {"nvd": ["a"], "ghsa": ["b"]},
            "references": {"nvd_urls": [], "ghsa_urls": []},
        },
    }


class HoldoutV2BuilderTests(unittest.TestCase):
    def test_combined_exclusions_reject_overlap(self) -> None:
        with self.assertRaisesRegex(ValueError, "overlap by cve_id"):
            target.combine_exclusions(
                [("development", {"CVE-1": row("CVE-1")}), ("v1", {"CVE-1": row("CVE-1")})]
            )

    def test_selection_excludes_both_prior_cohorts(self) -> None:
        rows = [row(f"CVE-2026-{index:04d}") for index in range(1, 9)]
        selected, eligible = target.select_holdout(
            rows, {"CVE-2026-0001", "CVE-2026-0002"}, "seed-v2", 3
        )
        self.assertEqual(eligible, 6)
        self.assertFalse(
            {item["cve_id"] for item in selected}
            & {"CVE-2026-0001", "CVE-2026-0002"}
        )

    def test_selection_is_order_independent(self) -> None:
        rows = [row(f"CVE-2026-{index:04d}") for index in range(1, 9)]
        first, _ = target.select_holdout(rows, {"CVE-2026-0001"}, "seed-v2", 4)
        second, _ = target.select_holdout(
            list(reversed(copy.deepcopy(rows))), {"CVE-2026-0001"}, "seed-v2", 4
        )
        self.assertEqual(
            [item["cve_id"] for item in first],
            [item["cve_id"] for item in second],
        )

    def test_source_row_contains_no_label_or_annotation(self) -> None:
        source = target.build_source_row(row("CVE-2026-0001"), 1)
        self.assertEqual(source["sample_id"], "affected_versions_holdout_v2:001")
        self.assertFalse(any("gold" in key or "label" in key for key in source))
        self.assertNotIn("annotation", source)


if __name__ == "__main__":
    unittest.main()
