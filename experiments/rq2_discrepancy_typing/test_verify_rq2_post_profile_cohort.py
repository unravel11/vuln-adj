import unittest
from datetime import datetime, timezone

import verify_rq2_post_profile_cohort as target


class VerifyPostProfileCohortTests(unittest.TestCase):
    def test_independent_external_eligibility_excludes_old_and_multi_ghsa(self):
        aligned = {
            "CVE-2026-0001": {"ghsa": [{}]},
            "CVE-2026-0002": {"ghsa": [{}]},
            "CVE-2026-0003": {"ghsa": [{}, {}]},
        }
        eligible = target.independent_eligible(
            aligned,
            {"CVE-2026-0002"},
            "snapshot_external",
            datetime(2026, 7, 18, tzinfo=timezone.utc),
        )
        self.assertEqual(eligible, {"CVE-2026-0001"})

    def test_parse_time_normalizes_naive_timestamp_to_utc(self):
        parsed = target.parse_time("2026-07-19T01:02:03")
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertEqual(parsed.isoformat(), "2026-07-19T01:02:03+00:00")


if __name__ == "__main__":
    unittest.main()
