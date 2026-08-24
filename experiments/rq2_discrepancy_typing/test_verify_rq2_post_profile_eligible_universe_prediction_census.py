#!/usr/bin/env python3

from __future__ import annotations

import unittest

import verify_rq2_post_profile_eligible_universe_prediction_census as target


class VerifyEligibleUniversePredictionCensusTests(unittest.TestCase):
    def test_minimum_p_boundary(self) -> None:
        self.assertEqual(target.minimum_p(0), 1.0)
        self.assertEqual(target.minimum_p(5), 0.0625)
        self.assertEqual(target.minimum_p(6), 0.03125)

    def test_independent_source_rows_cover_each_field(self) -> None:
        field_by_cve = {
            "CVE-2026-1": {
                "field_discrepancies": {
                    field: {
                        "status": "equivalent",
                        "nvd_value": None,
                        "ghsa_value": None,
                    }
                    for field in target.FIELDS
                }
            }
        }
        rows = target.independent_source_rows(field_by_cve, {"CVE-2026-1"})
        self.assertEqual(len(rows), len(target.FIELDS))
        self.assertEqual({row["field"] for row in rows}, set(target.FIELDS))


if __name__ == "__main__":
    unittest.main()
