import tempfile
import unittest
from pathlib import Path

from verify_ghsa_merged_pr_manifest import (
    VerificationError,
    compare_censuses,
    parse_utc,
    rebuild_pulls,
    validate_pulls_request,
    validate_search_request,
)


class CensusVerifierTests(unittest.TestCase):
    def test_three_identical_censuses_pass(self):
        rows = {1: "2024-01-01T00:00:00Z", 2: "2025-12-31T23:59:59Z"}
        self.assertEqual(compare_censuses(rows, dict(rows), dict(rows)), [])

    def test_set_difference_fails(self):
        self.assertEqual(
            compare_censuses(
                {1: "2024-01-01T00:00:00Z"},
                {1: "2024-01-01T00:00:00Z", 2: "2024-01-02T00:00:00Z"},
                {1: "2024-01-01T00:00:00Z"},
            ),
            ["PR-number sets differ"],
        )

    def test_merged_time_difference_fails(self):
        errors = compare_censuses(
            {1: "2024-01-01T00:00:00Z"},
            {1: "2024-01-01T00:00:01Z"},
            {1: "2024-01-01T00:00:00Z"},
        )
        self.assertEqual(errors, ["merged_at differs for PR 1"])

    def test_utc_parser_rejects_naive_time(self):
        with self.assertRaises(VerificationError):
            parse_utc("2024-01-01T00:00:00")

    def test_search_request_requires_frozen_query(self):
        metadata = {
            "url": (
                "https://api.github.com/search/issues?"
                "q=repo%3Agithub%2Fadvisory-database+is%3Apr+is%3Amerged+"
                "merged%3A2024-01-01..2024-01-31&sort=created&order=asc&"
                "per_page=100&page=1"
            )
        }
        validate_search_request(
            metadata,
            start_day="2024-01-01",
            end_day="2024-01-31",
            page=1,
            per_page=100,
        )

    def test_pulls_request_requires_frozen_query(self):
        repository_id = validate_pulls_request(
            {
                "url": (
                    "https://api.github.com/repositories/458364565/pulls?"
                    "state=closed&sort=created&direction=asc&per_page=100&page=7"
                )
            },
            page=7,
            expected_repository_id=458364565,
        )
        self.assertEqual(repository_id, 458364565)

    def test_first_pulls_request_requires_owner_name_path(self):
        repository_id = validate_pulls_request(
            {
                "url": (
                    "https://api.github.com/repos/github/advisory-database/pulls?"
                    "state=closed&sort=created&direction=asc&per_page=100&page=1"
                )
            },
            page=1,
        )
        self.assertIsNone(repository_id)

    def test_later_pulls_request_rejects_repository_id_change(self):
        with self.assertRaisesRegex(VerificationError, "repository ID changed"):
            validate_pulls_request(
                {
                    "url": (
                        "https://api.github.com/repositories/458364566/pulls?"
                        "state=closed&sort=created&direction=asc&per_page=100&page=3"
                    )
                },
                page=3,
                expected_repository_id=458364565,
            )

    def test_pulls_rebuild_rejects_zero_request_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                VerificationError, "no retained request evidence"
            ):
                rebuild_pulls(
                    Path(directory),
                    {
                        "stage": "pulls",
                        "status": "traversal_complete",
                        "pages": 0,
                        "page_summaries": [],
                    },
                    parse_utc("2024-01-01T00:00:00Z"),
                    parse_utc("2026-01-01T00:00:00Z"),
                    "run-id",
                    "unauthenticated_public",
                )


if __name__ == "__main__":
    unittest.main()
