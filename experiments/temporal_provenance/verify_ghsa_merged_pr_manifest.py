#!/usr/bin/env python3
"""Independently rebuild and verify the GHSA merged-PR census manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EXPECTED_SCHEMA = "ghsa-merged-pr-observable-census-v1"
EXPECTED_REPOSITORY = "github/advisory-database"
EXPECTED_API_VERSION = "2022-11-28"
EXPECTED_START = "2024-01-01T00:00:00Z"
EXPECTED_END = "2026-01-01T00:00:00Z"


class VerificationError(RuntimeError):
    """The retained evidence cannot reproduce the reported census."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=(
            "data/processed/temporal_provenance/pilot_v1/"
            "ghsa_merged_pr_census/manifest.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=(
            "results/temporal_provenance/pilot_v1/ghsa_merged_pr_census/"
            "independent_verification.json"
        ),
    )
    return parser.parse_args()


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise VerificationError(f"timestamp has no timezone: {value}")
    return parsed.astimezone(timezone.utc)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read JSON: {path}: {exc}") from exc


def load_success(request_dir: Path) -> tuple[Any, dict[str, Any]]:
    success_path = request_dir / "success.json"
    success = load_json(success_path)
    if not isinstance(success, dict):
        raise VerificationError(f"success pointer is not an object: {success_path}")
    body_path = request_dir / str(success.get("body_file"))
    metadata_path = request_dir / str(success.get("metadata_file"))
    metadata = load_json(metadata_path)
    if not isinstance(metadata, dict):
        raise VerificationError(f"attempt metadata is not an object: {metadata_path}")
    try:
        body = body_path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read response body: {body_path}: {exc}") from exc
    digest = sha256_bytes(body)
    if digest != success.get("body_sha256") or digest != metadata.get("body_sha256"):
        raise VerificationError(f"response digest mismatch: {request_dir}")
    if metadata.get("status") != 200:
        raise VerificationError(f"successful pointer targets non-200 attempt: {request_dir}")
    if metadata.get("api_version") != EXPECTED_API_VERSION:
        raise VerificationError(f"API version mismatch: {request_dir}")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid response JSON: {body_path}: {exc}") from exc
    return payload, metadata


def merged_at(item: dict[str, Any], source: str) -> str:
    value = (
        (item.get("pull_request") or {}).get("merged_at")
        if source == "search"
        else item.get("merged_at")
    )
    if not isinstance(value, str):
        raise VerificationError(f"{source} item lacks merged_at")
    return value


def pr_number(item: dict[str, Any]) -> int:
    value = item.get("number")
    if not isinstance(value, int):
        raise VerificationError("item lacks integer PR number")
    return value


def in_window(value: str, start: datetime, end: datetime) -> bool:
    return start <= parse_utc(value) < end


def add_row(
    rows: dict[int, str], item: dict[str, Any], source: str, *, context: str
) -> None:
    number = pr_number(item)
    timestamp = merged_at(item, source)
    previous = rows.get(number)
    if previous is not None and previous != timestamp:
        raise VerificationError(f"conflicting duplicate PR {number}: {context}")
    rows[number] = timestamp


def request_url(metadata: dict[str, Any], expected_path: str) -> dict[str, list[str]]:
    url = metadata.get("url")
    if not isinstance(url, str):
        raise VerificationError("request metadata lacks URL")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com":
        raise VerificationError(f"unexpected request origin: {url}")
    if parsed.path != expected_path:
        raise VerificationError(f"unexpected request path: {url}")
    return urllib.parse.parse_qs(parsed.query)


def validate_search_request(
    metadata: dict[str, Any],
    *,
    start_day: str,
    end_day: str,
    page: int,
    per_page: int,
) -> None:
    query = request_url(metadata, "/search/issues")
    expected = {
        "q": [
            f"repo:{EXPECTED_REPOSITORY} is:pr is:merged "
            f"merged:{start_day}..{end_day}"
        ],
        "sort": ["created"],
        "order": ["asc"],
        "per_page": [str(per_page)],
        "page": [str(page)],
    }
    if query != expected:
        raise VerificationError(f"search request query mismatch: {metadata.get('url')}")


def validate_pulls_request(metadata: dict[str, Any], *, page: int) -> None:
    query = request_url(metadata, f"/repos/{EXPECTED_REPOSITORY}/pulls")
    expected = {
        "state": ["closed"],
        "sort": ["created"],
        "direction": ["asc"],
        "per_page": ["100"],
        "page": [str(page)],
    }
    if query != expected:
        raise VerificationError(f"pulls request query mismatch: {metadata.get('url')}")


def rebuild_search(
    raw_root: Path,
    summary: dict[str, Any],
    start: datetime,
    end: datetime,
) -> dict[int, str]:
    stage = summary.get("stage")
    if stage not in {"search_pass_1", "search_pass_2"}:
        raise VerificationError(f"invalid search stage: {stage}")
    rows: dict[int, str] = {}
    for shard in summary.get("shards") or []:
        shard_id = shard.get("shard_id")
        pages = shard.get("pages")
        if not isinstance(shard_id, str) or not isinstance(pages, int) or pages < 1:
            raise VerificationError(f"invalid shard summary: {shard}")
        start_day = shard.get("start_day")
        end_day = shard.get("end_day")
        if not isinstance(start_day, str) or not isinstance(end_day, str):
            raise VerificationError(f"shard dates missing: {shard_id}")
        shard_rows: dict[int, str] = {}
        reported_total: int | None = None
        for page in range(1, pages + 1):
            request_dir = raw_root / stage / f"{shard_id}_page_{page:03d}"
            payload, metadata = load_success(request_dir)
            validate_search_request(
                metadata,
                start_day=start_day,
                end_day=end_day,
                page=page,
                per_page=100,
            )
            if not isinstance(payload, dict) or payload.get("incomplete_results") is not False:
                raise VerificationError(f"invalid/incomplete search payload: {request_dir}")
            total = payload.get("total_count")
            items = payload.get("items")
            if not isinstance(total, int) or not isinstance(items, list):
                raise VerificationError(f"search metadata/items missing: {request_dir}")
            if reported_total is None:
                reported_total = total
            elif total != reported_total:
                raise VerificationError(f"search total changed within shard: {shard_id}")
            for item in items:
                if not isinstance(item, dict):
                    raise VerificationError(f"non-object search item: {request_dir}")
                add_row(shard_rows, item, "search", context=str(request_dir))
        if len(shard_rows) != reported_total:
            raise VerificationError(
                f"search shard count mismatch {shard_id}: "
                f"unique={len(shard_rows)} total={reported_total}"
            )
        if reported_total != shard.get("reported_total"):
            raise VerificationError(f"manifest shard total mismatch: {shard_id}")
        overlap = set(rows).intersection(shard_rows)
        if overlap:
            raise VerificationError(f"search shards overlap: {sorted(overlap)[:5]}")
        rows.update(shard_rows)

    rows = {
        number: timestamp
        for number, timestamp in rows.items()
        if in_window(timestamp, start, end)
    }
    whole_payload, whole_metadata = load_success(
        raw_root / stage / "whole_window_page_001"
    )
    validate_search_request(
        whole_metadata,
        start_day=EXPECTED_START[:10],
        end_day="2025-12-31",
        page=1,
        per_page=1,
    )
    if (
        not isinstance(whole_payload, dict)
        or whole_payload.get("incomplete_results") is not False
        or whole_payload.get("total_count") != len(rows)
    ):
        raise VerificationError(f"whole-window search mismatch: {stage}")
    if len(rows) != summary.get("items") or len(rows) != summary.get("whole_window_total"):
        raise VerificationError(f"search summary count mismatch: {stage}")
    return rows


def rebuild_pulls(
    raw_root: Path,
    summary: dict[str, Any],
    start: datetime,
    end: datetime,
) -> dict[int, str]:
    if summary.get("stage") != "pulls":
        raise VerificationError("invalid pulls stage")
    page_summaries = summary.get("page_summaries") or []
    if len(page_summaries) != summary.get("pages"):
        raise VerificationError("pulls page-summary count mismatch")
    rows: dict[int, str] = {}
    previous_created: datetime | None = None
    for expected_page, page_summary in enumerate(page_summaries, 1):
        if page_summary.get("page") != expected_page:
            raise VerificationError("pulls pages are not contiguous")
        request_dir = raw_root / "pulls" / f"page_{expected_page:03d}"
        payload, metadata = load_success(request_dir)
        validate_pulls_request(metadata, page=expected_page)
        if not isinstance(payload, list) or not payload:
            raise VerificationError(f"invalid pulls payload: {request_dir}")
        created_values = []
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("created_at"), str):
                raise VerificationError(f"invalid pulls item: {request_dir}")
            created_values.append(parse_utc(item["created_at"]))
            timestamp = merged_at(item, "pulls") if item.get("merged_at") else None
            if timestamp is not None and in_window(timestamp, start, end):
                add_row(rows, item, "pulls", context=str(request_dir))
        if created_values != sorted(created_values):
            raise VerificationError(f"pulls page order violation: {request_dir}")
        if previous_created is not None and created_values[0] < previous_created:
            raise VerificationError(f"pulls cross-page order violation: {request_dir}")
        previous_created = created_values[-1]
    if len(rows) != summary.get("items"):
        raise VerificationError("pulls summary count mismatch")
    return rows


def compare_censuses(*censuses: dict[int, str]) -> list[str]:
    if len(censuses) != 3:
        raise ValueError("exactly three censuses are required")
    errors: list[str] = []
    union = set().union(*(set(rows) for rows in censuses))
    if not all(set(rows) == union for rows in censuses):
        errors.append("PR-number sets differ")
    for number in sorted(set.intersection(*(set(rows) for rows in censuses))):
        if len({rows[number] for rows in censuses}) != 1:
            errors.append(f"merged_at differs for PR {number}")
    return errors


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise VerificationError(f"non-object JSONL row: {path}:{line_number}")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read JSONL: {path}: {exc}") from exc
    return rows


def verify(manifest_path: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        raise VerificationError("manifest is not an object")
    expected = {
        "schema_version": EXPECTED_SCHEMA,
        "status": "complete",
        "repository": EXPECTED_REPOSITORY,
        "api_version": EXPECTED_API_VERSION,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise VerificationError(f"manifest {key} mismatch")
    if manifest.get("window") != {
        "start": EXPECTED_START,
        "end_exclusive": EXPECTED_END,
    }:
        raise VerificationError("manifest window mismatch")

    start = parse_utc(EXPECTED_START)
    end = parse_utc(EXPECTED_END)
    raw_root = Path(str(manifest.get("raw_root")))
    search1 = rebuild_search(raw_root, manifest["search_pass_1"], start, end)
    pulls = rebuild_pulls(raw_root, manifest["pulls"], start, end)
    search2 = rebuild_search(raw_root, manifest["search_pass_2"], start, end)
    comparison_errors = compare_censuses(search1, pulls, search2)
    if comparison_errors:
        raise VerificationError("; ".join(comparison_errors))

    rows_meta = manifest.get("rows") or {}
    rows_path = Path(str(rows_meta.get("path")))
    try:
        rows_bytes = rows_path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"cannot read compact rows: {rows_path}: {exc}") from exc
    if sha256_bytes(rows_bytes) != rows_meta.get("sha256"):
        raise VerificationError("compact-row digest mismatch")
    compact_rows = read_jsonl(rows_path)
    compact_map: dict[int, str] = {}
    for row in compact_rows:
        number = row.get("pr_number")
        timestamp = row.get("merged_at")
        if not isinstance(number, int) or not isinstance(timestamp, str):
            raise VerificationError("compact row lacks PR number/merged_at")
        if number in compact_map:
            raise VerificationError(f"duplicate compact PR row: {number}")
        compact_map[number] = timestamp
    if compact_map != search1 or len(compact_rows) != rows_meta.get("records"):
        raise VerificationError("compact rows do not reproduce search pass 1")

    attempts_meta = manifest.get("attempts") or {}
    attempts_path = Path(str(attempts_meta.get("path")))
    attempts = read_jsonl(attempts_path)
    raw_attempts = []
    for path in sorted(raw_root.glob("**/attempt_*.json")):
        value = load_json(path)
        if not isinstance(value, dict):
            raise VerificationError(f"raw attempt is not an object: {path}")
        value["metadata_path"] = str(path)
        raw_attempts.append(value)
    if len(attempts) != attempts_meta.get("records") or attempts != raw_attempts:
        raise VerificationError("attempt ledger does not reproduce raw metadata")

    return {
        "schema_version": "ghsa-merged-pr-census-independent-verification-v1",
        "status": "pass",
        "manifest": str(manifest_path.resolve()),
        "records": len(search1),
        "search_pass_1_records": len(search1),
        "pulls_records": len(pulls),
        "search_pass_2_records": len(search2),
        "attempt_records": len(attempts),
        "checks": [
            "raw_success_pointer_and_digest",
            "search_shard_counts_and_completeness",
            "whole_window_search_count",
            "pulls_page_contiguity_and_created_order",
            "three_way_pr_number_and_merged_at_identity",
            "compact_row_digest_and_identity",
            "attempt_ledger_count",
        ],
        "claim_ceiling": (
            "Mechanical reproduction of the acquisition-visible merged-PR census; "
            "not a field-change, correction, acceptance-semantics, or truth check."
        ),
    }


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main() -> int:
    args = parse_args()
    try:
        result = verify(Path(args.manifest))
    except VerificationError as exc:
        result = {
            "schema_version": "ghsa-merged-pr-census-independent-verification-v1",
            "status": "fail",
            "error": str(exc),
        }
        atomic_write(Path(args.output), result)
        print(json.dumps(result, indent=2), flush=True)
        return 1
    atomic_write(Path(args.output), result)
    print(json.dumps(result, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
