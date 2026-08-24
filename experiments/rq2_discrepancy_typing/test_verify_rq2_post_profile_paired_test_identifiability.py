#!/usr/bin/env python3

from __future__ import annotations

import unittest

import verify_rq2_post_profile_paired_test_identifiability as target


class VerifyPairedTestIdentifiabilityTests(unittest.TestCase):
    def test_exact_p_boundary_is_independent(self) -> None:
        self.assertEqual(target.exact_p(0, 3), 0.25)
        self.assertEqual(target.exact_p(0, 6), 0.03125)
        self.assertEqual(target.exact_p(1, 8), 0.0390625)

    def test_independent_power_search_reaches_target_minimally(self) -> None:
        rows, power = target.minimum_power_rows(0.80)
        self.assertGreaterEqual(power, 0.80)
        self.assertLess(target.candidate_power(rows - 1, 0.80), 0.80)


if __name__ == "__main__":
    unittest.main()
