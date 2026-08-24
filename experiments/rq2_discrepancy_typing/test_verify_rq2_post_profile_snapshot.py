import json
import tempfile
import unittest
from pathlib import Path

import verify_rq2_post_profile_snapshot as target


class IndependentTierTests(unittest.TestCase):
    def test_tier_size_boundaries(self):
        self.assertEqual(target.tier_size(0), 0)
        self.assertEqual(target.tier_size(25), 5)
        self.assertEqual(target.tier_size(249), 20)
        self.assertEqual(target.tier_size(250), 50)

    def test_timestamp_rejects_invalid_value(self):
        self.assertIsNone(target.timestamp("not-a-time"))

    def test_iter_jsonl_preserves_unicode_line_separator_inside_string(self):
        rows = [
            {"cve_id": "CVE-2026-0001", "text": "before\u2028after"},
            {"cve_id": "CVE-2026-0002", "text": "plain"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text(
                "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                encoding="utf-8",
            )

            self.assertEqual(list(target.iter_jsonl(path)), rows)


if __name__ == "__main__":
    unittest.main()
