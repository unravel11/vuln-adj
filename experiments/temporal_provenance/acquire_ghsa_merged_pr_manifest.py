#!/usr/bin/env python3
"""Acquire and reconcile the frozen GHSA merged-PR observable population.

This stage acquires only the census manifest. It does not inspect advisory
field diffs, map PRs to main, or produce downstream outcomes.
"""

from __future__ import annotations

import argparse
import calendar
import email.utils
import json
import math
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from temporal_provenance_lib import canonical_json, parse_utc, sha256_bytes


API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
REPOSITORY = "github/advisory-database"
DEFAULT_START = "2024-01-01T00:00:00Z"
DEFAULT_END = "2026-01-01T00:00:00Z"
USER_AGENT = "vuln-adj-temporal-provenance-pilot-v1/1.0"
SELECTED_HEADERS = {
    "content-type",
    "date",
    "etag",
    "github-authentication-token-expiration",
    "link",
    "retry-after",
    "x-github-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
    "x-ratelimit-used",
}


class AcquisitionError(RuntimeError):
    """A request or response cannot support a complete manifest."""


class RateLimitPause(AcquisitionError):
    """The run must be resumed after a rate-limit reset."""

    def __init__(self, message: str, reset_epoch: int | None = None):
        super().__init__(message)
        self.reset_epoch = reset_epoch


@dataclass(frozen=True)
class SearchShard:
    shard_id: str
    start_day: date
    end_day: date


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument("--end", default=DEFAULT_END)
    parser.add_argument(
        "--raw-root",
        default="data/raw/temporal_provenance/pilot_v1/ghsa_merged_pr_census",
    )
    parser.add_argument(
        "--output-dir",
        default="data/processed/temporal_provenance/pilot_v1/ghsa_merged_pr_census",
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=12,
        help="Total append-only attempt ceiling per request across resumed runs.",
    )
    parser.add_argument(
        "--max-rate-wait",
        type=int,
        default=55,
        help="Maximum seconds to sleep inside one run before exiting resumably.",
    )
    parser.add_argument("--request-delay", type=float, default=0.5)
    return parser.parse_args()


def month_shards(start: datetime, end: datetime) -> list[SearchShard]:
    if start >= end:
        raise ValueError("start must precede end")
    cursor = date(start.year, start.month, 1)
    end_day_exclusive = end.date()
    shards: list[SearchShard] = []
    while cursor < end_day_exclusive:
        last_day = calendar.monthrange(cursor.year, cursor.month)[1]
        month_end = date(cursor.year, cursor.month, last_day)
        shard_start = max(cursor, start.date())
        shard_end = min(month_end, end_day_exclusive - timedelta(days=1))
        if shard_start <= shard_end:
            shards.append(
                SearchShard(
                    shard_id=f"{shard_start:%Y-%m}",
                    start_day=shard_start,
                    end_day=shard_end,
                )
            )
        if cursor.month == 12:
            cursor = date(cursor.year + 1, 1, 1)
        else:
            cursor = date(cursor.year, cursor.month + 1, 1)
    return shards


def day_shards(parent: SearchShard) -> list[SearchShard]:
    output = []
    cursor = parent.start_day
    while cursor <= parent.end_day:
        output.append(
            SearchShard(
                shard_id=f"{parent.shard_id}-{cursor:%d}",
                start_day=cursor,
                end_day=cursor,
            )
        )
        cursor += timedelta(days=1)
    return output


def search_query(start_day: date, end_day: date) -> str:
    return (
        f"repo:{REPOSITORY} is:pr is:merged "
        f"merged:{start_day.isoformat()}..{end_day.isoformat()}"
    )


def build_search_url(
    start_day: date, end_day: date, page: int, per_page: int = 100
) -> str:
    query = urllib.parse.urlencode(
        {
            "q": search_query(start_day, end_day),
            "sort": "created",
            "order": "asc",
            "per_page": per_page,
            "page": page,
        }
    )
    return f"{API_ROOT}/search/issues?{query}"


def build_pulls_url(page: int, per_page: int = 100) -> str:
    query = urllib.parse.urlencode(
        {
            "state": "closed",
            "sort": "created",
            "direction": "asc",
            "per_page": per_page,
            "page": page,
        }
    )
    return f"{API_ROOT}/repos/{REPOSITORY}/pulls?{query}"


def safe_request_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    if not cleaned:
        raise ValueError("empty request ID")
    return cleaned


def selected_headers(headers: Any) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in SELECTED_HEADERS
    }


def parse_link_header(value: str | None) -> dict[str, str]:
    links: dict[str, str] = {}
    if not value:
        return links
    for part in value.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*$', part)
        if match:
            links[match.group(2)] = match.group(1)
    return links


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


class GithubAcquirer:
    def __init__(
        self,
        raw_root: Path,
        *,
        timeout: int,
        max_attempts: int,
        max_rate_wait: int,
        request_delay: float,
    ) -> None:
        self.raw_root = raw_root
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.max_rate_wait = max_rate_wait
        self.request_delay = request_delay
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.auth_mode = "authenticated_public" if token else "unauthenticated_public"
        self.request_headers = {
            "Accept": "application/vnd.github+json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if token:
            self.request_headers["Authorization"] = f"Bearer {token}"

    def _request_dir(self, stage: str, request_id: str) -> Path:
        return self.raw_root / safe_request_id(stage) / safe_request_id(request_id)

    def _load_success(
        self, request_dir: Path, expected_url: str
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        success_path = request_dir / "success.json"
        if not success_path.exists():
            return None
        success = json.loads(success_path.read_text(encoding="utf-8"))
        body_path = request_dir / success["body_file"]
        metadata_path = request_dir / success["metadata_file"]
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("url") != expected_url or metadata.get("api_version") != API_VERSION:
            raise AcquisitionError(f"resume request identity mismatch: {metadata_path}")
        body = body_path.read_bytes()
        if sha256_bytes(body) != success["body_sha256"]:
            raise AcquisitionError(f"resume digest mismatch: {body_path}")
        return json.loads(body), metadata

    def _next_attempt(self, request_dir: Path) -> int:
        attempts = []
        for path in request_dir.glob("attempt_*.json"):
            match = re.fullmatch(r"attempt_(\d+)\.json", path.name)
            if match:
                attempts.append(int(match.group(1)))
        return max(attempts, default=0) + 1

    def _response_epoch(self, headers: dict[str, str]) -> int:
        server_date = headers.get("date")
        if server_date:
            try:
                parsed = email.utils.parsedate_to_datetime(server_date)
                return int(parsed.timestamp())
            except (TypeError, ValueError, OverflowError):
                pass
        return int(time.time())

    def _rate_wait(
        self, headers: dict[str, str]
    ) -> tuple[int, int | None, int]:
        response_epoch = self._response_epoch(headers)
        retry_after = headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            wait = int(retry_after) + 1
            return wait, None, response_epoch
        reset = headers.get("x-ratelimit-reset")
        reset_epoch = int(reset) if reset and reset.isdigit() else None
        if reset_epoch is None:
            return 5, None, response_epoch
        return max(1, reset_epoch - response_epoch + 2), reset_epoch, response_epoch

    def get_json(self, stage: str, request_id: str, url: str) -> tuple[Any, dict[str, Any]]:
        request_dir = self._request_dir(stage, request_id)
        resumed = self._load_success(request_dir, url)
        if resumed is not None:
            return resumed

        last_error: str | None = None
        first_attempt = self._next_attempt(request_dir)
        attempts_remaining = self.max_attempts - first_attempt + 1
        if attempts_remaining <= 0:
            raise AcquisitionError(
                f"request exhausted the frozen attempt limit: {request_id}"
            )
        for local_attempt in range(min(attempts_remaining, 4)):
            attempt = self._next_attempt(request_dir)
            observed_at = utc_now()
            status: int | None = None
            body = b""
            headers: dict[str, str] = {}
            error_type: str | None = None
            try:
                request = urllib.request.Request(url, headers=self.request_headers)
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    status = response.status
                    body = response.read()
                    headers = selected_headers(response.headers)
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read()
                headers = selected_headers(exc.headers)
                error_type = "HTTPError"
                last_error = f"HTTP {status}"
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                error_type = type(exc).__name__
                last_error = str(exc)

            request_dir.mkdir(parents=True, exist_ok=True)
            body_name = f"attempt_{attempt:03d}.body"
            metadata_name = f"attempt_{attempt:03d}.json"
            atomic_write(request_dir / body_name, body)
            metadata = {
                "schema_version": "ghsa-merged-pr-request-attempt-v1",
                "stage": stage,
                "request_id": request_id,
                "url": url,
                "api_version": API_VERSION,
                "auth_mode": self.auth_mode,
                "observed_at": observed_at,
                "attempt": attempt,
                "status": status,
                "error_type": error_type,
                "response_headers": headers,
                "body_file": body_name,
                "body_sha256": sha256_bytes(body),
                "body_bytes": len(body),
            }
            atomic_write(
                request_dir / metadata_name,
                (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )

            if status == 200:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError as exc:
                    last_error = f"invalid JSON: {exc}"
                else:
                    success = {
                        "body_file": body_name,
                        "metadata_file": metadata_name,
                        "body_sha256": sha256_bytes(body),
                    }
                    atomic_write(
                        request_dir / "success.json",
                        (json.dumps(success, indent=2, sort_keys=True) + "\n").encode(
                            "utf-8"
                        ),
                    )
                    if self.request_delay:
                        time.sleep(self.request_delay)
                    return payload, metadata

            rate_limited = status == 429 or (
                status == 403
                and headers.get("x-ratelimit-remaining") == "0"
            )
            if rate_limited:
                wait, reset_epoch, response_epoch = self._rate_wait(headers)
                if reset_epoch is not None and reset_epoch <= response_epoch:
                    raise RateLimitPause(
                        "rate-limit response carried a stale/past server reset; "
                        "resume with a fresh no-cache request",
                        reset_epoch=reset_epoch,
                    )
                if wait > self.max_rate_wait:
                    raise RateLimitPause(
                        f"rate limit requires {wait}s wait; resume this run later",
                        reset_epoch=reset_epoch,
                    )
                time.sleep(wait)
            elif local_attempt + 1 < self.max_attempts:
                time.sleep((2, 5, 15)[min(local_attempt, 2)])

        raise AcquisitionError(
            f"request failed after {self.max_attempts} attempts: {request_id}: {last_error}"
        )


def item_merged_at(item: dict[str, Any], source: str) -> str | None:
    if source == "search":
        pull = item.get("pull_request") or {}
        value = pull.get("merged_at")
    else:
        value = item.get("merged_at")
    return value if isinstance(value, str) else None


def item_number(item: dict[str, Any]) -> int:
    number = item.get("number")
    if not isinstance(number, int):
        raise AcquisitionError("GitHub item without integer PR number")
    return number


def in_window(value: str | None, start: datetime, end: datetime) -> bool:
    return value is not None and start <= parse_utc(value) < end


def add_unique(
    rows: dict[int, dict[str, Any]], item: dict[str, Any], source: str
) -> None:
    number = item_number(item)
    merged_at = item_merged_at(item, source)
    if merged_at is None:
        raise AcquisitionError(f"merged item lacks merged_at: PR {number}")
    existing = rows.get(number)
    if existing is not None and item_merged_at(existing, source) != merged_at:
        raise AcquisitionError(f"duplicate PR with conflicting merged_at: {number}")
    rows[number] = item


def acquire_search_shard(
    acquirer: GithubAcquirer,
    stage: str,
    shard: SearchShard,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    page1, page1_meta = acquirer.get_json(
        stage,
        f"{shard.shard_id}_page_001",
        build_search_url(shard.start_day, shard.end_day, 1),
    )
    if not isinstance(page1, dict):
        raise AcquisitionError(f"search response is not an object: {shard.shard_id}")
    total_count = page1.get("total_count")
    incomplete = page1.get("incomplete_results")
    if not isinstance(total_count, int) or not isinstance(incomplete, bool):
        raise AcquisitionError(f"search metadata missing: {shard.shard_id}")
    if total_count > 1000:
        raise AcquisitionError(f"search shard exceeds 1000: {shard.shard_id}")
    pages = max(1, math.ceil(total_count / 100))
    rows: dict[int, dict[str, Any]] = {}
    page_payloads = [page1]
    for page in range(2, pages + 1):
        payload, _ = acquirer.get_json(
            stage,
            f"{shard.shard_id}_page_{page:03d}",
            build_search_url(shard.start_day, shard.end_day, page),
        )
        if not isinstance(payload, dict):
            raise AcquisitionError(f"search page is not an object: {shard.shard_id}/{page}")
        page_payloads.append(payload)
    for payload in page_payloads:
        if payload.get("incomplete_results") is not False:
            raise AcquisitionError(f"incomplete search response: {shard.shard_id}")
        items = payload.get("items")
        if not isinstance(items, list):
            raise AcquisitionError(f"search items missing: {shard.shard_id}")
        for item in items:
            if not isinstance(item, dict):
                raise AcquisitionError(f"non-object search item: {shard.shard_id}")
            add_unique(rows, item, "search")
    if len(rows) != total_count:
        raise AcquisitionError(
            f"search shard count mismatch {shard.shard_id}: "
            f"unique={len(rows)} total={total_count}"
        )
    return rows, {
        "shard_id": shard.shard_id,
        "start_day": shard.start_day.isoformat(),
        "end_day": shard.end_day.isoformat(),
        "reported_total": total_count,
        "unique_items": len(rows),
        "pages": pages,
        "incomplete_results": incomplete,
        "first_observed_at": page1_meta["observed_at"],
    }


def acquire_search_pass(
    acquirer: GithubAcquirer,
    stage: str,
    start: datetime,
    end: datetime,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    all_rows: dict[int, dict[str, Any]] = {}
    shard_summaries = []
    overlap_numbers: set[int] = set()
    for month in month_shards(start, end):
        page1, _ = acquirer.get_json(
            stage,
            f"{month.shard_id}_page_001",
            build_search_url(month.start_day, month.end_day, 1),
        )
        total = page1.get("total_count") if isinstance(page1, dict) else None
        shards = day_shards(month) if isinstance(total, int) and total > 1000 else [month]
        for shard in shards:
            rows, summary = acquire_search_shard(acquirer, stage, shard)
            overlap_numbers.update(set(all_rows).intersection(rows))
            all_rows.update(rows)
            shard_summaries.append(summary)

    filtered = {
        number: item
        for number, item in all_rows.items()
        if in_window(item_merged_at(item, "search"), start, end)
    }
    whole_start = start.date()
    whole_end = end.date() - timedelta(days=1)
    whole, whole_meta = acquirer.get_json(
        stage,
        "whole_window_page_001",
        build_search_url(whole_start, whole_end, 1, per_page=1),
    )
    whole_total = whole.get("total_count") if isinstance(whole, dict) else None
    whole_incomplete = whole.get("incomplete_results") if isinstance(whole, dict) else None
    if whole_incomplete is not False or not isinstance(whole_total, int):
        raise AcquisitionError(f"whole-window search metadata invalid: {stage}")
    if overlap_numbers:
        raise AcquisitionError(f"search shards overlap in {stage}: {len(overlap_numbers)}")
    if len(filtered) != whole_total:
        raise AcquisitionError(
            f"search union mismatch {stage}: unique={len(filtered)} whole={whole_total}"
        )
    return filtered, {
        "stage": stage,
        "status": "complete",
        "items": len(filtered),
        "whole_window_total": whole_total,
        "whole_window_observed_at": whole_meta["observed_at"],
        "shards": shard_summaries,
        "overlap_pr_numbers": [],
    }


def created_at(item: dict[str, Any]) -> datetime:
    value = item.get("created_at")
    if not isinstance(value, str):
        raise AcquisitionError("pull item lacks created_at")
    return parse_utc(value)


def validate_created_order(items: Iterable[dict[str, Any]]) -> tuple[datetime, datetime]:
    parsed = [created_at(item) for item in items]
    if not parsed:
        raise AcquisitionError("empty pulls page before terminal pagination")
    if parsed != sorted(parsed):
        raise AcquisitionError("pulls page is not ordered by created_at")
    return parsed[0], parsed[-1]


def acquire_pulls_census(
    acquirer: GithubAcquirer,
    stage: str,
    start: datetime,
    end: datetime,
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    page = 1
    previous_last: datetime | None = None
    page_summaries = []
    stopped_reason: str | None = None
    while True:
        payload, metadata = acquirer.get_json(
            stage,
            f"page_{page:03d}",
            build_pulls_url(page),
        )
        if not isinstance(payload, list):
            raise AcquisitionError(f"pulls response is not a list: page {page}")
        if not payload:
            stopped_reason = "empty_page"
            break
        if any(not isinstance(item, dict) for item in payload):
            raise AcquisitionError(f"non-object pull item: page {page}")
        first_created, last_created = validate_created_order(payload)
        if previous_last is not None and first_created < previous_last:
            raise AcquisitionError(f"cross-page created_at order violation: page {page}")
        previous_last = last_created
        for item in payload:
            if in_window(item_merged_at(item, "pulls"), start, end):
                add_unique(rows, item, "pulls")
        links = parse_link_header(metadata["response_headers"].get("link"))
        page_summaries.append(
            {
                "page": page,
                "items": len(payload),
                "first_created_at": first_created.isoformat(),
                "last_created_at": last_created.isoformat(),
                "has_next": "next" in links,
                "observed_at": metadata["observed_at"],
            }
        )
        if last_created >= end:
            stopped_reason = "created_at_cutoff_reached"
            break
        if "next" not in links:
            stopped_reason = "pagination_exhausted"
            break
        page += 1
    return rows, {
        "stage": stage,
        "status": "complete",
        "items": len(rows),
        "pages": len(page_summaries),
        "stopped_reason": stopped_reason,
        "page_summaries": page_summaries,
    }


def compact_search_row(item: dict[str, Any]) -> dict[str, Any]:
    pull = item.get("pull_request") or {}
    user = item.get("user") or {}
    body = item.get("body")
    return {
        "pr_number": item_number(item),
        "merged_at": item_merged_at(item, "search"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "closed_at": item.get("closed_at"),
        "author_login": user.get("login"),
        "html_url": item.get("html_url"),
        "api_url": item.get("url"),
        "pull_api_url": pull.get("url"),
        "diff_url": pull.get("diff_url"),
        "patch_url": pull.get("patch_url"),
        "title": item.get("title"),
        "body_sha256": sha256_bytes((body or "").encode("utf-8")),
        "body_has_affected_products": isinstance(body, str)
        and "affected products" in body.lower(),
        "body_has_references": isinstance(body, str) and "references" in body.lower(),
    }


def compare_censuses(
    search1: dict[int, dict[str, Any]],
    pulls: dict[int, dict[str, Any]],
    search2: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    sets = [set(search1), set(pulls), set(search2)]
    union = set.union(*sets)
    intersection = set.intersection(*sets)
    merged_at_mismatches = []
    for number in sorted(intersection):
        values = {
            item_merged_at(search1[number], "search"),
            item_merged_at(pulls[number], "pulls"),
            item_merged_at(search2[number], "search"),
        }
        if len(values) != 1:
            merged_at_mismatches.append(number)
    differences = {
        "search_pass_1_only": sorted(sets[0] - sets[1] - sets[2]),
        "pulls_only": sorted(sets[1] - sets[0] - sets[2]),
        "search_pass_2_only": sorted(sets[2] - sets[0] - sets[1]),
        "missing_from_search_pass_1": sorted(union - sets[0]),
        "missing_from_pulls": sorted(union - sets[1]),
        "missing_from_search_pass_2": sorted(union - sets[2]),
    }
    complete = (
        sets[0] == sets[1] == sets[2]
        and not merged_at_mismatches
        and all(not values for values in differences.values())
    )
    return {
        "status": "complete" if complete else "manifest_incomplete",
        "search_pass_1_count": len(search1),
        "pulls_count": len(pulls),
        "search_pass_2_count": len(search2),
        "union_count": len(union),
        "intersection_count": len(intersection),
        "merged_at_mismatch_pr_numbers": merged_at_mismatches,
        "set_differences": differences,
    }


def aggregate_attempts(raw_root: Path) -> list[dict[str, Any]]:
    attempts = []
    for path in sorted(raw_root.glob("**/attempt_*.json")):
        row = json.loads(path.read_text(encoding="utf-8"))
        row["metadata_path"] = str(path)
        attempts.append(row)
    return attempts


def write_run_state(output_dir: Path, state: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(
        output_dir / "run_state.json",
        (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def main() -> int:
    args = parse_args()
    start = parse_utc(args.start)
    end = parse_utc(args.end)
    if start.isoformat() != parse_utc(DEFAULT_START).isoformat() or end.isoformat() != parse_utc(
        DEFAULT_END
    ).isoformat():
        raise ValueError("the frozen census interval cannot be changed")
    raw_root = Path(args.raw_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    acquirer = GithubAcquirer(
        raw_root,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        max_rate_wait=args.max_rate_wait,
        request_delay=args.request_delay,
    )
    started_at = utc_now()
    try:
        search1, search1_summary = acquire_search_pass(
            acquirer, "search_pass_1", start, end
        )
        pulls, pulls_summary = acquire_pulls_census(acquirer, "pulls", start, end)
        search2, search2_summary = acquire_search_pass(
            acquirer, "search_pass_2", start, end
        )
    except RateLimitPause as exc:
        state = {
            "schema_version": "ghsa-merged-pr-census-run-state-v1",
            "status": "rate_limited_resumable",
            "started_at": started_at,
            "stopped_at": utc_now(),
            "auth_mode": acquirer.auth_mode,
            "message": str(exc),
            "reset_epoch": exc.reset_epoch,
            "raw_root": str(raw_root),
        }
        write_run_state(output_dir, state)
        print(json.dumps(state, indent=2))
        return 3
    except AcquisitionError as exc:
        state = {
            "schema_version": "ghsa-merged-pr-census-run-state-v1",
            "status": "acquisition_error",
            "started_at": started_at,
            "stopped_at": utc_now(),
            "auth_mode": acquirer.auth_mode,
            "message": str(exc),
            "raw_root": str(raw_root),
        }
        write_run_state(output_dir, state)
        print(json.dumps(state, indent=2), file=sys.stderr)
        return 4

    comparison = compare_censuses(search1, pulls, search2)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows_path = output_dir / "merged_prs.jsonl"
    row_bytes = b"".join(
        (canonical_json(compact_search_row(search1[number])) + "\n").encode("utf-8")
        for number in sorted(search1)
    )
    atomic_write(rows_path, row_bytes)
    attempts = aggregate_attempts(raw_root)
    attempts_path = output_dir / "attempts.jsonl"
    atomic_write(
        attempts_path,
        b"".join((canonical_json(row) + "\n").encode("utf-8") for row in attempts),
    )
    manifest = {
        "schema_version": "ghsa-merged-pr-observable-census-v1",
        "status": comparison["status"],
        "repository": REPOSITORY,
        "api_version": API_VERSION,
        "auth_mode": acquirer.auth_mode,
        "window": {"start": DEFAULT_START, "end_exclusive": DEFAULT_END},
        "started_at": started_at,
        "completed_at": utc_now(),
        "raw_root": str(raw_root),
        "search_pass_1": search1_summary,
        "pulls": pulls_summary,
        "search_pass_2": search2_summary,
        "comparison": comparison,
        "rows": {
            "path": str(rows_path),
            "sha256": sha256_bytes(row_bytes),
            "records": len(search1),
        },
        "attempts": {"path": str(attempts_path), "records": len(attempts)},
        "claim_ceiling": (
            "This is the acquisition-visible public merged-PR population under "
            "two GitHub REST routes, not a field-change, correction, or truth count."
        ),
    }
    manifest_path = output_dir / "manifest.json"
    atomic_write(
        manifest_path,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    write_run_state(
        output_dir,
        {
            "schema_version": "ghsa-merged-pr-census-run-state-v1",
            "status": comparison["status"],
            "completed_at": manifest["completed_at"],
            "manifest": str(manifest_path),
        },
    )
    print(
        f"GHSA merged-PR census {comparison['status']}: "
        f"search1={len(search1)} pulls={len(pulls)} search2={len(search2)}"
    )
    print(f"Manifest: {manifest_path}")
    return 0 if comparison["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
