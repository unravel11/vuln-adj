#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_rq2_typing_tiebreak as subject


def vote(label, confidence="high", review=False):
    return {"discrepancy_label": label, "confidence": confidence, "needs_human_review": review}


class VerifyTypingTiebreakTests(unittest.TestCase):
    def test_vote_recomputation_requires_two_qualified_votes(self):
        label, counts = subject.recompute_vote(
            [vote("incomplete"), vote("factual_conflict"), vote("incomplete")]
        )
        self.assertEqual(label, "incomplete")
        self.assertEqual(counts, {"factual_conflict": 1, "incomplete": 2})

    def test_uncertain_and_low_votes_are_excluded(self):
        label, counts = subject.recompute_vote(
            [vote("uncertain", review=True), vote("incomplete", "low", True), vote("factual_conflict")]
        )
        self.assertIsNone(label)
        self.assertEqual(counts, {"factual_conflict": 1})


if __name__ == "__main__":
    unittest.main()
