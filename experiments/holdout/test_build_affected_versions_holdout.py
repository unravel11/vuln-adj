#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import build_affected_versions_holdout as target


def row(cve_id: str, status: str = "factual_conflict") -> dict:
    return {
        "_source_line_number": 1,
        "cve_id": cve_id,
        "nvd_source_id": cve_id,
        "ghsa_source_id": f"GHSA-{cve_id}",
        "field_discrepancies": {
            "affected_versions": {
                "status": status,
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


class HoldoutBuilderTests(unittest.TestCase):
    def test_filter_and_selection_are_order_independent(self) -> None:
        rows = [row(f"CVE-2026-{index:04d}") for index in range(1, 7)]
        first, eligible = target.select_holdout(rows, {"CVE-2026-0001"}, "seed", 3)
        second, _ = target.select_holdout(
            list(reversed(copy.deepcopy(rows))), {"CVE-2026-0001"}, "seed", 3
        )
        self.assertEqual(eligible, 5)
        self.assertEqual(
            [item["cve_id"] for item in first], [item["cve_id"] for item in second]
        )
        self.assertNotIn("CVE-2026-0001", {item["cve_id"] for item in first})

    def test_duplicate_candidate_cve_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate cve_id"):
            target.select_holdout([row("CVE-2026-0001"), row("CVE-2026-0001")], set(), "seed", 1)

    def test_missing_exclusion_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "no longer affected_versions FC"):
            target.select_holdout([row("CVE-2026-0001")], {"CVE-2026-9999"}, "seed", 1)

    def test_source_row_contains_no_annotation_or_gold(self) -> None:
        source = target.build_source_row(row("CVE-2026-0001"), 1)
        self.assertNotIn("annotation", source)
        self.assertFalse(any("gold" in key or "label" in key for key in source))
        self.assertEqual(source["sample_id"], "affected_versions_holdout_v1:001")

    def test_identity_drift_is_detectable(self) -> None:
        current = row("CVE-2026-0001")
        excluded = copy.deepcopy(current)
        excluded["ghsa_source_id"] = "GHSA-different"
        self.assertNotEqual(target.identity(current), target.identity(excluded))

    def test_identity_commitment_is_order_independent(self) -> None:
        rows = [row("CVE-2026-0001"), row("CVE-2026-0002")]
        self.assertEqual(
            target.identity_commitment(rows),
            target.identity_commitment(list(reversed(rows))),
        )


if __name__ == "__main__":
    unittest.main()
