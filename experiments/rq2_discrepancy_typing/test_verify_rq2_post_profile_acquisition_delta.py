#!/usr/bin/env python3

from __future__ import annotations

import unittest
from datetime import datetime, timezone

import verify_rq2_post_profile_acquisition_delta as target


class IndependentDeltaTests(unittest.TestCase):
    def test_independent_delta_requires_exact_sequence_content(self) -> None:
        freeze = datetime(2026, 7, 18, 17, 22, tzinfo=timezone.utc)
        previous = {
            "a": {"source_id": "a", "published": "2026-07-18T16:00:00Z"}
        }
        current = {
            "a": {"source_id": "a", "published": "2026-07-18T16:00:00Z"},
            "b": {"source_id": "b", "published": "2026-07-18T18:00:00Z"},
        }
        observed = target.delta(previous, current, freeze)
        self.assertEqual(observed["added_ids"], ["b"])
        self.assertEqual(observed["added_after_profile_ids"], ["b"])
        self.assertEqual(observed["changed_count"], 0)


if __name__ == "__main__":
    unittest.main()
