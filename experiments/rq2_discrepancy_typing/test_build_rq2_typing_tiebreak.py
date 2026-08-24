#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_rq2_typing_tiebreak as subject


class BuildTypingTiebreakTests(unittest.TestCase):
    def test_selects_only_non_strict_rows_in_hash_order(self):
        blind = {
            "s1": {"sample_id": "s1"},
            "s2": {"sample_id": "s2"},
            "s3": {"sample_id": "s3"},
        }
        consensus = [
            {"sample_id": "s1", "strict_consensus": True},
            {"sample_id": "s2", "strict_consensus": False},
            {"sample_id": "s3", "strict_consensus": False},
        ]
        observed = subject.select_worklist(blind, consensus)
        expected_ids = sorted(["s2", "s3"], key=subject.rank)
        self.assertEqual([row["sample_id"] for row in observed], expected_ids)

    def test_missing_blind_row_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "absent"):
            subject.select_worklist({}, [{"sample_id": "missing", "strict_consensus": False}])


if __name__ == "__main__":
    unittest.main()
