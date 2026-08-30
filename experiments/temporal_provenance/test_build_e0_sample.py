import unittest

import build_e0_sample as target


def row(cve_id, nvd_published, ghsa_published, reviewed=True, outcome_marker=None):
    return {
        "cve_id": cve_id,
        "nvd": {"published": nvd_published, "outcome_marker": outcome_marker},
        "ghsa": [
            {
                "source_id": "GHSA-xxxx-xxxx-xxxx",
                "published": ghsa_published,
                "outcome_marker": outcome_marker,
                "source_specific": {
                    "github_reviewed": reviewed,
                    "relative_path": "advisories/github-reviewed/2023/01/GHSA.json",
                },
            }
        ],
    }


class EligibilityTests(unittest.TestCase):
    def test_requires_both_sources_published_by_cutoff_and_reviewed(self):
        self.assertTrue(
            target.eligible_row(
                row("CVE-2023-0001", "2023-01-01T00:00:00Z", "2023-02-01T00:00:00Z")
            )
        )
        self.assertFalse(
            target.eligible_row(
                row("CVE-2023-0002", "2023-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
            )
        )
        self.assertFalse(
            target.eligible_row(
                row(
                    "CVE-2023-0003",
                    "2023-01-01T00:00:00Z",
                    "2023-02-01T00:00:00Z",
                    reviewed=False,
                )
            )
        )

    def test_selection_is_outcome_independent(self):
        rows_a = [
            row(
                f"CVE-2023-{number:04d}",
                "2023-01-01T00:00:00Z",
                "2023-02-01T00:00:00Z",
                outcome_marker="A",
            )
            for number in range(1, 11)
        ]
        rows_b = [
            row(
                f"CVE-2023-{number:04d}",
                "2023-01-01T00:00:00Z",
                "2023-02-01T00:00:00Z",
                outcome_marker="opposite",
            )
            for number in range(1, 11)
        ]
        selected_a = [item["cve_id"] for item in target.build_manifest(rows_a, 5)["rows"]]
        selected_b = [item["cve_id"] for item in target.build_manifest(rows_b, 5)["rows"]]
        self.assertEqual(selected_a, selected_b)

    def test_partial_status_when_universe_is_too_small(self):
        manifest = target.build_manifest(
            [
                row(
                    "CVE-2023-0001",
                    "2023-01-01T00:00:00Z",
                    "2023-02-01T00:00:00Z",
                )
            ],
            sample_size=2,
        )
        self.assertEqual(manifest["status"], "partial_source_universe")
        self.assertEqual(manifest["selected_cves"], 1)


if __name__ == "__main__":
    unittest.main()

