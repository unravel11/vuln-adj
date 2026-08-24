import unittest
from datetime import datetime, timezone

import build_rq2_post_profile_cohort as target


class BuildPostProfileCohortTests(unittest.TestCase):
    def test_single_ghsa_rows_excludes_unmatched_aligned_records(self):
        rows = [
            {"cve_id": "CVE-2026-0001", "ghsa": []},
            {"cve_id": "CVE-2026-0002", "ghsa": [{}]},
        ]
        self.assertEqual(
            target.single_ghsa_rows(rows),
            [{"cve_id": "CVE-2026-0002", "ghsa": [{}]}],
        )

    def test_snapshot_external_eligibility_requires_new_2026_cve(self):
        aligned = {
            "CVE-2026-0001": {"ghsa": [{}]},
            "CVE-2026-0002": {"ghsa": [{}, {}]},
            "CVE-2025-9999": {"ghsa": [{}]},
        }
        eligible = target.eligible_cves(
            aligned,
            {"CVE-2026-0003"},
            "snapshot_external",
            datetime(2026, 7, 18, tzinfo=timezone.utc),
        )
        self.assertEqual(eligible, {"CVE-2026-0001"})

    def test_strict_eligibility_requires_both_sources_after_freeze(self):
        aligned = {
            "CVE-2026-0001": {
                "nvd": {"published": "2026-07-19T00:00:00Z"},
                "ghsa": [{"published": "2026-07-19T00:01:00Z"}],
            },
            "CVE-2026-0002": {
                "nvd": {"published": "2026-07-19T00:00:00Z"},
                "ghsa": [{"published": "2026-07-17T00:00:00Z"}],
            },
        }
        eligible = target.eligible_cves(
            aligned,
            set(),
            "strict_event_time",
            datetime(2026, 7, 18, tzinfo=timezone.utc),
        )
        self.assertEqual(eligible, {"CVE-2026-0001"})

    def test_profile_difference_counts_are_against_current(self):
        rows = [
            {
                "current": "factual_conflict",
                "reference_resource_identity_original_v1": "incomplete",
                "reference_resource_identity_audited_v1": "factual_conflict",
                "cwe_taxonomy_v1": "factual_conflict",
                "combined_original_v1": "incomplete",
                "combined_audited_v1": "factual_conflict",
            }
        ]
        counts = target.selected_profile_difference_counts(rows)
        self.assertEqual(counts["reference_resource_identity_original_v1"], 1)
        self.assertEqual(counts["combined_original_v1"], 1)
        self.assertEqual(counts["combined_audited_v1"], 0)

    def test_boundary_forbids_time_confirmation_and_human_label(self):
        self.assertEqual(target.BOUNDARY["selected_tier"], "snapshot_external")
        self.assertIs(target.BOUNDARY["strict_event_time_claim_allowed"], False)
        self.assertIs(target.BOUNDARY["label_is_human"], False)


if __name__ == "__main__":
    unittest.main()
