#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import merge_rq2_typing_tiebreak as subject


def annotation(label, confidence="high", needs_review=False):
    return {
        "discrepancy_label": label,
        "confidence": confidence,
        "needs_human_review": needs_review,
    }


class MergeTypingTiebreakTests(unittest.TestCase):
    def test_third_vote_resolves_disagreement(self):
        label, counts = subject.majority_label(
            [annotation("factual_conflict"), annotation("incomplete"), annotation("factual_conflict")]
        )
        self.assertEqual(label, "factual_conflict")
        self.assertEqual(counts, {"factual_conflict": 2, "incomplete": 1})

    def test_third_vote_cannot_override_two_uncertain_votes(self):
        label, counts = subject.majority_label(
            [annotation("uncertain", needs_review=True), annotation("uncertain", needs_review=True), annotation("incomplete")]
        )
        self.assertIsNone(label)
        self.assertEqual(counts, {"incomplete": 1})

    def test_low_confidence_original_vote_is_not_counted(self):
        label, counts = subject.majority_label(
            [annotation("representation_discrepancy", confidence="low", needs_review=True), annotation("incomplete"), annotation("representation_discrepancy")]
        )
        self.assertIsNone(label)
        self.assertEqual(counts, {"incomplete": 1, "representation_discrepancy": 1})

    def test_same_label_can_be_recovered_by_two_qualified_votes(self):
        label, _ = subject.majority_label(
            [annotation("representation_discrepancy"), annotation("representation_discrepancy", confidence="low", needs_review=True), annotation("representation_discrepancy")]
        )
        self.assertEqual(label, "representation_discrepancy")


if __name__ == "__main__":
    unittest.main()
