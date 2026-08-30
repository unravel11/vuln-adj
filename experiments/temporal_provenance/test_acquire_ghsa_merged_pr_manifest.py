import json
import tempfile
import unittest
import urllib.parse
from datetime import date
from pathlib import Path

import acquire_ghsa_merged_pr_manifest as target
from temporal_provenance_lib import parse_utc


def search_item(number: int, merged_at: str) -> dict:
    return {
        "number": number,
        "created_at": "2023-01-01T00:00:00Z",
        "pull_request": {"merged_at": merged_at},
    }


def pull_item(number: int, merged_at: str) -> dict:
    return {
        "number": number,
        "created_at": "2023-01-01T00:00:00Z",
        "merged_at": merged_at,
    }


class ShardTests(unittest.TestCase):
    def test_frozen_window_has_24_nonoverlapping_months(self):
        shards = target.month_shards(
            parse_utc(target.DEFAULT_START), parse_utc(target.DEFAULT_END)
        )
        self.assertEqual(len(shards), 24)
        self.assertEqual(shards[0].start_day, date(2024, 1, 1))
        self.assertEqual(shards[0].end_day, date(2024, 1, 31))
        self.assertEqual(shards[-1].start_day, date(2025, 12, 1))
        self.assertEqual(shards[-1].end_day, date(2025, 12, 31))

    def test_day_split_preserves_every_day(self):
        parent = target.SearchShard("2024-02", date(2024, 2, 1), date(2024, 2, 29))
        days = target.day_shards(parent)
        self.assertEqual(len(days), 29)
        self.assertTrue(all(row.start_day == row.end_day for row in days))


class URLTests(unittest.TestCase):
    def test_search_url_freezes_query_sort_and_page(self):
        url = target.build_search_url(date(2024, 1, 1), date(2024, 1, 31), 2)
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/search/issues")
        self.assertEqual(query["sort"], ["created"])
        self.assertEqual(query["order"], ["asc"])
        self.assertEqual(query["page"], ["2"])
        self.assertIn("merged:2024-01-01..2024-01-31", query["q"][0])

    def test_pulls_url_is_closed_created_ascending(self):
        url = target.build_pulls_url(7)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(
            query,
            {
                "state": ["closed"],
                "sort": ["created"],
                "direction": ["asc"],
                "per_page": ["100"],
                "page": ["7"],
            },
        )

    def test_link_parser_keeps_relations(self):
        parsed = target.parse_link_header(
            '<https://api.github.com/example?page=2>; rel="next", '
            '<https://api.github.com/example?page=9>; rel="last"'
        )
        self.assertEqual(parsed["next"], "https://api.github.com/example?page=2")
        self.assertEqual(parsed["last"], "https://api.github.com/example?page=9")


class PopulationTests(unittest.TestCase):
    def test_window_is_exact_and_end_exclusive(self):
        start = parse_utc(target.DEFAULT_START)
        end = parse_utc(target.DEFAULT_END)
        self.assertTrue(target.in_window("2024-01-01T00:00:00Z", start, end))
        self.assertTrue(target.in_window("2025-12-31T23:59:59Z", start, end))
        self.assertFalse(target.in_window("2026-01-01T00:00:00Z", start, end))

    def test_three_way_comparison_requires_numbers_and_times(self):
        s1 = {1: search_item(1, "2025-01-01T00:00:00Z")}
        pulls = {1: pull_item(1, "2025-01-01T00:00:00Z")}
        s2 = {1: search_item(1, "2025-01-01T00:00:00Z")}
        self.assertEqual(target.compare_censuses(s1, pulls, s2)["status"], "complete")

        pulls[2] = pull_item(2, "2025-01-02T00:00:00Z")
        result = target.compare_censuses(s1, pulls, s2)
        self.assertEqual(result["status"], "manifest_incomplete")
        self.assertEqual(result["set_differences"]["missing_from_search_pass_1"], [2])

    def test_three_way_comparison_detects_merged_time_mismatch(self):
        s1 = {1: search_item(1, "2025-01-01T00:00:00Z")}
        pulls = {1: pull_item(1, "2025-01-01T00:00:01Z")}
        s2 = {1: search_item(1, "2025-01-01T00:00:00Z")}
        result = target.compare_censuses(s1, pulls, s2)
        self.assertEqual(result["status"], "manifest_incomplete")
        self.assertEqual(result["merged_at_mismatch_pr_numbers"], [1])

    def test_created_order_rejects_pagination_drift(self):
        rows = [
            {"created_at": "2025-01-02T00:00:00Z"},
            {"created_at": "2025-01-01T00:00:00Z"},
        ]
        with self.assertRaises(target.AcquisitionError):
            target.validate_created_order(rows)


class RawEvidenceTests(unittest.TestCase):
    def test_attempt_metadata_never_serializes_token(self):
        with tempfile.TemporaryDirectory() as directory:
            acquirer = target.GithubAcquirer(
                Path(directory),
                timeout=1,
                max_attempts=1,
                max_rate_wait=1,
                request_delay=0,
            )
            self.assertNotIn("Authorization", target.SELECTED_HEADERS)
            self.assertIn(acquirer.auth_mode, {"authenticated_public", "unauthenticated_public"})

    def test_resume_rejects_a_different_request_url(self):
        with tempfile.TemporaryDirectory() as directory:
            acquirer = target.GithubAcquirer(
                Path(directory),
                timeout=1,
                max_attempts=1,
                max_rate_wait=1,
                request_delay=0,
            )
            request_dir = Path(directory) / "stage" / "request"
            request_dir.mkdir(parents=True)
            body = b"{}"
            (request_dir / "attempt_001.body").write_bytes(body)
            metadata = {
                "url": "https://api.github.com/old",
                "api_version": target.API_VERSION,
            }
            (request_dir / "attempt_001.json").write_text(json.dumps(metadata))
            success = {
                "body_file": "attempt_001.body",
                "metadata_file": "attempt_001.json",
                "body_sha256": target.sha256_bytes(body),
            }
            (request_dir / "success.json").write_text(json.dumps(success))
            with self.assertRaises(target.AcquisitionError):
                acquirer._load_success(request_dir, "https://api.github.com/new")


if __name__ == "__main__":
    unittest.main()
