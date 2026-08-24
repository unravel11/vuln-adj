import json
import tempfile
import unittest
from pathlib import Path

import build_rq2_post_profile_snapshot as target


class TierTests(unittest.TestCase):
    def test_adaptive_tiers(self):
        self.assertEqual(target.adaptive_rows_per_field(24), 0)
        self.assertEqual(target.adaptive_rows_per_field(25), 5)
        self.assertEqual(target.adaptive_rows_per_field(100), 20)
        self.assertEqual(target.adaptive_rows_per_field(250), 50)

    def test_parse_time_normalizes_utc(self):
        self.assertEqual(
            target.parse_time("2026-07-19T00:00:00Z").isoformat(),
            "2026-07-19T00:00:00+00:00",
        )


class AvailabilityTests(unittest.TestCase):
    def test_strict_tier_requires_both_sources_after_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seal = root / "seal.json"
            old = root / "old.jsonl"
            aligned = root / "aligned.jsonl"
            views = root / "views.jsonl"
            seal.write_text(json.dumps({"sealed_at_ns": 1_000_000_000}) + "\n")
            old.write_text("")
            rows = [
                {
                    "cve_id": "CVE-2026-1",
                    "nvd": {"published": "1970-01-01T00:00:02Z"},
                    "ghsa": [{"published": "1970-01-01T00:00:03Z"}],
                },
                {
                    "cve_id": "CVE-2026-2",
                    "nvd": {"published": "1970-01-01T00:00:02Z"},
                    "ghsa": [{"published": "1970-01-01T00:00:00Z"}],
                },
            ]
            aligned.write_text("".join(json.dumps(row) + "\n" for row in rows))
            discrepancy = {
                field: {"status": "equivalent"}
                for field in ("severity", "published", "references", "affected_versions", "cwe_ids")
            }
            views.write_text(
                "".join(
                    json.dumps({"cve_id": row["cve_id"], "field_discrepancies": discrepancy}) + "\n"
                    for row in rows
                )
            )
            result = target.availability_analysis(aligned, views, old, seal)
            self.assertEqual(result["strict_event_time_unique_cves"], 1)
            self.assertEqual(result["snapshot_external_unique_cves"], 2)
            self.assertEqual(result["selected_tier_for_next_stage"], "none")


if __name__ == "__main__":
    unittest.main()
