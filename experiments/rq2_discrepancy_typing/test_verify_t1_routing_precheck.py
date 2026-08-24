#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_t1_routing_precheck as analyzer
import test_analyze_t1_routing_precheck as fixtures
import verify_t1_routing_precheck as verifier


class IndependentRoutingPrecheckVerifierTests(unittest.TestCase):
    def test_independent_recomputation_matches_analyzer(self) -> None:
        rows = fixtures.corpus()
        observed = analyzer.compute_analysis(rows)
        expected = verifier.recompute(rows)
        for key, value in expected.items():
            self.assertEqual(observed[key], value, key)

    def test_policy_implementations_match_on_boundary_fixture(self) -> None:
        view = fixtures.policy_view()
        for field in analyzer.FIELDS:
            self.assertEqual(
                analyzer.policy_actions(view, field),
                verifier.all_actions(view, field),
                field,
            )

    def test_verifier_exact_test_boundary(self) -> None:
        self.assertEqual(verifier.exact_p(0, 5), 0.0625)
        self.assertEqual(verifier.exact_p(0, 6), 0.03125)
        self.assertEqual(verifier.rejection_rows(), 6)


if __name__ == "__main__":
    unittest.main()
