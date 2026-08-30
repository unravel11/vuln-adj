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


class FakeAcquirer:
    def __init__(self, responses: dict[str, tuple[object, dict]]):
        self.responses = responses

    def get_json(self, stage: str, request_id: str, url: str):
        del stage, url
        return self.responses[request_id]


def response_metadata(request_id: str, link: str | None = None) -> dict:
    headers = {"x-github-request-id": request_id}
    if link is not None:
        headers["link"] = link
    return {
        "observed_at": "2026-08-30T18:00:00+00:00",
        "received_at": "2026-08-30T18:00:01+00:00",
        "response_headers": headers,
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

    def test_pulls_link_url_rejects_wrong_next_page(self):
        with self.assertRaises(target.AcquisitionError):
            target.validate_pulls_page_url(target.build_pulls_url(3), 2)

    def test_pulls_link_url_accepts_and_returns_canonical_repository_id(self):
        url = (
            "https://api.github.com/repositories/458364565/pulls?"
            "state=closed&sort=created&direction=asc&per_page=100&page=2"
        )
        self.assertEqual(target.validate_pulls_page_url(url, 2), 458364565)

    def test_pulls_link_url_rejects_repository_id_change(self):
        url = (
            "https://api.github.com/repositories/458364566/pulls?"
            "state=closed&sort=created&direction=asc&per_page=100&page=3"
        )
        with self.assertRaisesRegex(target.AcquisitionError, "repository ID changed"):
            target.validate_pulls_page_url(url, 3, 458364565)


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
        self.assertEqual(
            target.compare_censuses(s1, pulls, s2)["status"],
            target.RECONCILED_STATUS,
        )

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

    def test_search_rejects_total_count_drift_after_page_one(self):
        shard = target.SearchShard("2024-01", date(2024, 1, 1), date(2024, 1, 31))
        page1 = {
            "total_count": 101,
            "incomplete_results": False,
            "items": [search_item(number, "2024-01-02T00:00:00Z") for number in range(1, 101)],
        }
        page2 = {
            "total_count": 999,
            "incomplete_results": False,
            "items": [search_item(101, "2024-01-02T00:00:00Z")],
        }
        acquirer = FakeAcquirer(
            {
                "2024-01_page_001": (page1, response_metadata("request-1")),
                "2024-01_page_002": (page2, response_metadata("request-2")),
            }
        )
        with self.assertRaisesRegex(target.AcquisitionError, "total changed"):
            target.acquire_search_shard(acquirer, "search_pass_1", shard)

    def test_pulls_rejects_duplicate_across_pages(self):
        page2_url = (
            "https://api.github.com/repositories/458364565/pulls?"
            "state=closed&sort=created&direction=asc&per_page=100&page=2"
        )
        page1_meta = response_metadata(
            "request-1", f'<{page2_url}>; rel="next"'
        )
        duplicate = pull_item(1, "2024-02-01T00:00:00Z")
        acquirer = FakeAcquirer(
            {
                "page_001": ([duplicate], page1_meta),
                "page_002": ([duplicate], response_metadata("request-2")),
            }
        )
        with self.assertRaisesRegex(target.AcquisitionError, "duplicate PR"):
            target.acquire_pulls_census(
                acquirer,
                "pulls",
                parse_utc(target.DEFAULT_START),
                parse_utc(target.DEFAULT_END),
            )

    def test_pulls_rejects_empty_first_page(self):
        acquirer = FakeAcquirer(
            {"page_001": ([], response_metadata("request-1"))}
        )
        with self.assertRaisesRegex(target.AcquisitionError, "empty Pulls page"):
            target.acquire_pulls_census(
                acquirer,
                "pulls",
                parse_utc(target.DEFAULT_START),
                parse_utc(target.DEFAULT_END),
            )

    def test_pulls_rejects_empty_page_promised_by_next_link(self):
        page2_url = (
            "https://api.github.com/repositories/458364565/pulls?"
            "state=closed&sort=created&direction=asc&per_page=100&page=2"
        )
        acquirer = FakeAcquirer(
            {
                "page_001": (
                    [pull_item(1, "2024-02-01T00:00:00Z")],
                    response_metadata(
                        "request-1", f'<{page2_url}>; rel="next"'
                    ),
                ),
                "page_002": ([], response_metadata("request-2")),
            }
        )
        with self.assertRaisesRegex(target.AcquisitionError, "empty Pulls page"):
            target.acquire_pulls_census(
                acquirer,
                "pulls",
                parse_utc(target.DEFAULT_START),
                parse_utc(target.DEFAULT_END),
            )


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
            self.assertEqual(acquirer.request_headers["Cache-Control"], "no-cache")
            self.assertEqual(acquirer.request_headers["Pragma"], "no-cache")

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
                "stage": "stage",
                "request_id": "request",
                "url": "https://api.github.com/old",
                "api_version": target.API_VERSION,
                "auth_mode": acquirer.auth_mode,
                "run_id": acquirer.run_id,
                "body_sha256": target.sha256_bytes(body),
            }
            (request_dir / "attempt_001.json").write_text(json.dumps(metadata))
            success = {
                "body_file": "attempt_001.body",
                "metadata_file": "attempt_001.json",
                "body_sha256": target.sha256_bytes(body),
            }
            (request_dir / "success.json").write_text(json.dumps(success))
            with self.assertRaises(target.AcquisitionError):
                acquirer._load_success(
                    request_dir,
                    "stage",
                    "request",
                    "https://api.github.com/new",
                )

    def test_rate_wait_uses_server_date_when_host_clock_differs(self):
        with tempfile.TemporaryDirectory() as directory:
            acquirer = target.GithubAcquirer(
                Path(directory),
                timeout=1,
                max_attempts=1,
                max_rate_wait=55,
                request_delay=0,
            )
            wait, reset, response_epoch = acquirer._rate_wait(
                {
                    "date": "Sun, 30 Aug 2026 17:45:59 GMT",
                    "x-ratelimit-reset": "1788112000",
                }
            )
            self.assertEqual(reset - response_epoch, 41)
            self.assertEqual(wait, 43)

    def test_missing_rate_wait_header_requires_sixty_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            acquirer = target.GithubAcquirer(
                Path(directory),
                timeout=1,
                max_attempts=1,
                max_rate_wait=55,
                request_delay=0,
            )
            wait, reset, _ = acquirer._rate_wait({})
            self.assertEqual((wait, reset), (60, None))

    def test_secondary_403_is_a_rate_limit_even_with_remaining_core(self):
        self.assertEqual(
            target.rate_limit_kind(
                403,
                {"x-ratelimit-remaining": "42"},
                b'{"message":"You have exceeded a secondary rate limit."}',
            ),
            "secondary",
        )

    def test_secondary_rate_limit_ignores_core_reset_without_retry_after(self):
        self.assertEqual(
            target.secondary_rate_wait({"x-ratelimit-reset": "1788112000"}),
            60,
        )

    def test_secondary_rate_limit_honors_retry_after(self):
        self.assertEqual(target.secondary_rate_wait({"retry-after": "10"}), 11)

    def test_raw_root_rejects_auth_mode_change(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_root = Path(directory)
            acquirer = target.GithubAcquirer(
                raw_root,
                timeout=1,
                max_attempts=1,
                max_rate_wait=1,
                request_delay=0,
            )
            identity_path = raw_root / "acquisition_identity.json"
            identity = json.loads(identity_path.read_text())
            identity["auth_mode"] = (
                "authenticated_public"
                if acquirer.auth_mode == "unauthenticated_public"
                else "unauthenticated_public"
            )
            identity_path.write_text(json.dumps(identity))
            with self.assertRaisesRegex(target.AcquisitionError, "auth_mode"):
                target.GithubAcquirer(
                    raw_root,
                    timeout=1,
                    max_attempts=1,
                    max_rate_wait=1,
                    request_delay=0,
                )


if __name__ == "__main__":
    unittest.main()
