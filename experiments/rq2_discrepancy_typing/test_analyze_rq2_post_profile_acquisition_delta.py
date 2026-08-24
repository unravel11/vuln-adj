#!/usr/bin/env python3

from __future__ import annotations

import unittest
from datetime import datetime, timezone

import analyze_rq2_post_profile_acquisition_delta as target


class RecordDeltaTests(unittest.TestCase):
    def test_counts_additions_changes_and_post_freeze_rows(self) -> None:
        freeze = datetime(2026, 7, 18, 17, 22, tzinfo=timezone.utc)
        previous = {
            "a": {"source_id": "a", "published": "2026-07-18T16:00:00Z"},
            "b": {"source_id": "b", "published": "2026-07-18T16:00:00Z"},
        }
        current = {
            "b": {"source_id": "b", "published": "2026-07-18T18:00:00Z"},
            "c": {"source_id": "c", "published": "2026-07-18T19:00:00Z"},
        }
        observed = target.record_delta(previous, current, freeze)
        self.assertEqual(observed["added_ids"], ["c"])
        self.assertEqual(observed["removed_ids"], ["a"])
        self.assertEqual(observed["changed_ids"], ["b"])
        self.assertEqual(observed["published_after_profile_ids"], ["b", "c"])
        self.assertEqual(observed["added_after_profile_ids"], ["c"])

    def test_invalid_timestamp_is_not_counted(self) -> None:
        freeze = datetime(2026, 7, 18, tzinfo=timezone.utc)
        observed = target.record_delta(
            {},
            {"a": {"source_id": "a", "published": "not-a-time"}},
            freeze,
        )
        self.assertEqual(observed["added_count"], 1)
        self.assertEqual(observed["published_after_profile_count"], 0)


if __name__ == "__main__":
    unittest.main()
