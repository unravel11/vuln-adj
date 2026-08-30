#!/usr/bin/env python3
"""Independently rebuild and verify the GHSA merged-PR reconciled-set manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


EXPECTED_SCHEMA = "ghsa-merged-pr-endpoint-visible-set-v2"
EXPECTED_STATUS = "three_pass_reconciled_endpoint_visible_set"
EXPECTED_MANIFEST_STATUS = (
    "reconciliation_complete_pending_independent_verification"
)
EXPECTED_REPOSITORY = "github/advisory-database"
EXPECTED_API_VERSION = "2022-11-28"
EXPECTED_START = "2024-01-01T00:00:00Z"
EXPECTED_END = "2026-01-01T00:00:00Z"


class VerificationError(RuntimeError):
    """The retained evidence cannot reproduce the reported reconciled set."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=(
            "data/processed/temporal_provenance/pilot_v1/"
            "ghsa_merged_pr_reconciled_v2/manifest.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=(
            "results/temporal_provenance/pilot_v1/ghsa_merged_pr_reconciled_v2/"
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


def load_success(
    request_dir: Path,
    *,
    stage: str,
    request_id: str,
    run_id: str,
    auth_mode: str,
) -> tuple[Any, dict[str, Any]]:
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
    identity = {
        "stage": stage,
        "request_id": request_id,
        "run_id": run_id,
        "auth_mode": auth_mode,
    }
    if any(metadata.get(key) != value for key, value in identity.items()):
        raise VerificationError(f"request identity mismatch: {request_dir}")
    if not isinstance(metadata.get("received_at"), str):
        raise VerificationError(f"response receive time missing: {request_dir}")
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
    rows: dict[int, str],
    item: dict[str, Any],
    source: str,
    *,
    context: str,
    reject_duplicate: bool = False,
) -> None:
    number = pr_number(item)
    timestamp = merged_at(item, source)
    previous = rows.get(number)
    if previous is not None:
        if previous != timestamp:
            raise VerificationError(f"conflicting duplicate PR {number}: {context}")
        if reject_duplicate:
            raise VerificationError(f"duplicate PR across pagination: {number}")
    rows[number] = timestamp


def parse_link_header(value: str | None) -> dict[str, str]:
    links: dict[str, str] = {}
    if not value:
        return links
    for part in value.split(","):
        match = re.match(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*$', part)
        if match:
            links[match.group(2)] = match.group(1)
    return links


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


def validate_pulls_request(
    metadata: dict[str, Any],
    *,
    page: int,
    expected_repository_id: int | None = None,
) -> int | None:
    url = metadata.get("url")
    if not isinstance(url, str):
        raise VerificationError("request metadata lacks URL")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com":
        raise VerificationError(f"unexpected request origin: {url}")
    repository_id: int | None = None
    if page == 1:
        expected_path = f"/repos/{EXPECTED_REPOSITORY}/pulls"
        if parsed.path != expected_path:
            raise VerificationError(f"unexpected first Pulls request path: {url}")
    else:
        path_match = re.fullmatch(r"/repositories/(\d+)/pulls", parsed.path)
        if path_match is None:
            raise VerificationError(f"unexpected canonical Pulls request path: {url}")
        repository_id = int(path_match.group(1))
        if (
            expected_repository_id is not None
            and repository_id != expected_repository_id
        ):
            raise VerificationError(
                "Pulls canonical repository ID changed: "
                f"{expected_repository_id} -> {repository_id}"
            )
    query = urllib.parse.parse_qs(parsed.query)
    expected = {
        "state": ["closed"],
        "sort": ["created"],
        "direction": ["asc"],
        "per_page": ["100"],
        "page": [str(page)],
    }
    if query != expected:
        raise VerificationError(f"pulls request query mismatch: {url}")
    return repository_id


def rebuild_search(
    raw_root: Path,
    summary: dict[str, Any],
    start: datetime,
    end: datetime,
    run_id: str,
    auth_mode: str,
) -> tuple[dict[int, str], list[str]]:
    stage = summary.get("stage")
    if stage not in {"search_pass_1", "search_pass_2"}:
        raise VerificationError(f"invalid search stage: {stage}")
    if summary.get("status") != "traversal_complete":
        raise VerificationError(f"search traversal status mismatch: {stage}")
    rows: dict[int, str] = {}
    github_request_ids: list[str] = []
    for probe in summary.get("split_probe_summaries") or []:
        shard_id = probe.get("shard_id")
        start_day = probe.get("start_day")
        end_day = probe.get("end_day")
        if not all(isinstance(value, str) for value in (shard_id, start_day, end_day)):
            raise VerificationError(f"invalid monthly split probe: {probe}")
        request_id = f"{shard_id}_page_001"
        request_dir = raw_root / stage / request_id
        payload, metadata = load_success(
            request_dir,
            stage=stage,
            request_id=request_id,
            run_id=run_id,
            auth_mode=auth_mode,
        )
        validate_search_request(
            metadata,
            start_day=start_day,
            end_day=end_day,
            page=1,
            per_page=100,
        )
        if (
            not isinstance(payload, dict)
            or payload.get("incomplete_results") is not False
            or payload.get("total_count") != probe.get("reported_total")
            or not isinstance(payload.get("total_count"), int)
            or payload["total_count"] <= 1000
        ):
            raise VerificationError(f"invalid monthly split probe: {request_dir}")
        request_id_header = (metadata.get("response_headers") or {}).get(
            "x-github-request-id"
        )
        if (
            not isinstance(request_id_header, str)
            or request_id_header != probe.get("github_request_id")
        ):
            raise VerificationError(f"split-probe request ID mismatch: {request_dir}")
        github_request_ids.append(request_id_header)
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
            request_id = f"{shard_id}_page_{page:03d}"
            payload, metadata = load_success(
                request_dir,
                stage=stage,
                request_id=request_id,
                run_id=run_id,
                auth_mode=auth_mode,
            )
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
                add_row(
                    shard_rows,
                    item,
                    "search",
                    context=str(request_dir),
                    reject_duplicate=True,
                )
            request_id_header = (metadata.get("response_headers") or {}).get(
                "x-github-request-id"
            )
            if not isinstance(request_id_header, str) or not request_id_header:
                raise VerificationError(f"GitHub request ID missing: {request_dir}")
            github_request_ids.append(request_id_header)
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
        raw_root / stage / "whole_window_page_001",
        stage=stage,
        request_id="whole_window_page_001",
        run_id=run_id,
        auth_mode=auth_mode,
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
    whole_request_id = (whole_metadata.get("response_headers") or {}).get(
        "x-github-request-id"
    )
    if not isinstance(whole_request_id, str) or not whole_request_id:
        raise VerificationError(f"whole-window GitHub request ID missing: {stage}")
    github_request_ids.append(whole_request_id)
    if github_request_ids != summary.get("github_request_ids"):
        raise VerificationError(f"search request-ID ledger mismatch: {stage}")
    if len(github_request_ids) != len(set(github_request_ids)):
        raise VerificationError(f"duplicate GitHub request ID: {stage}")
    return rows, github_request_ids


def rebuild_pulls(
    raw_root: Path,
    summary: dict[str, Any],
    start: datetime,
    end: datetime,
    run_id: str,
    auth_mode: str,
) -> tuple[dict[int, str], list[str]]:
    if summary.get("stage") != "pulls":
        raise VerificationError("invalid pulls stage")
    if summary.get("status") != "traversal_complete":
        raise VerificationError("pulls traversal status mismatch")
    page_summaries = summary.get("page_summaries") or []
    if not page_summaries or summary.get("pages", 0) < 1:
        raise VerificationError("Pulls traversal has no retained request evidence")
    if len(page_summaries) != summary.get("pages"):
        raise VerificationError("pulls page-summary count mismatch")
    rows: dict[int, str] = {}
    seen_all_pr_numbers: set[int] = set()
    raw_items = 0
    github_request_ids: list[str] = []
    expected_link_url: str | None = None
    repository_numeric_id: int | None = None
    previous_created: datetime | None = None
    for expected_page, page_summary in enumerate(page_summaries, 1):
        if page_summary.get("page") != expected_page:
            raise VerificationError("pulls pages are not contiguous")
        request_dir = raw_root / "pulls" / f"page_{expected_page:03d}"
        payload, metadata = load_success(
            request_dir,
            stage="pulls",
            request_id=f"page_{expected_page:03d}",
            run_id=run_id,
            auth_mode=auth_mode,
        )
        if expected_link_url is not None and metadata.get("url") != expected_link_url:
            raise VerificationError(f"Pulls Link URL was not followed: {request_dir}")
        observed_repository_id = validate_pulls_request(
            metadata,
            page=expected_page,
            expected_repository_id=repository_numeric_id,
        )
        if observed_repository_id is not None:
            repository_numeric_id = observed_repository_id
        if not isinstance(payload, list) or not payload:
            raise VerificationError(f"invalid pulls payload: {request_dir}")
        created_values = []
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("created_at"), str):
                raise VerificationError(f"invalid pulls item: {request_dir}")
            created_values.append(parse_utc(item["created_at"]))
            number = pr_number(item)
            raw_items += 1
            if number in seen_all_pr_numbers:
                raise VerificationError(f"duplicate PR across Pulls pages: {number}")
            seen_all_pr_numbers.add(number)
            timestamp = merged_at(item, "pulls") if item.get("merged_at") else None
            if timestamp is not None and in_window(timestamp, start, end):
                add_row(
                    rows,
                    item,
                    "pulls",
                    context=str(request_dir),
                    reject_duplicate=True,
                )
        if created_values != sorted(created_values):
            raise VerificationError(f"pulls page order violation: {request_dir}")
        if previous_created is not None and created_values[0] < previous_created:
            raise VerificationError(f"pulls cross-page order violation: {request_dir}")
        previous_created = created_values[-1]
        headers = metadata.get("response_headers") or {}
        request_id_header = headers.get("x-github-request-id")
        if not isinstance(request_id_header, str) or not request_id_header:
            raise VerificationError(f"Pulls GitHub request ID missing: {request_dir}")
        github_request_ids.append(request_id_header)
        links = parse_link_header(headers.get("link"))
        if page_summary.get("items") != len(payload):
            raise VerificationError(f"Pulls page item count mismatch: {request_dir}")
        if page_summary.get("has_next") != ("next" in links):
            raise VerificationError(f"Pulls Link summary mismatch: {request_dir}")
        if expected_page < len(page_summaries):
            if "next" not in links:
                raise VerificationError(f"Pulls pagination ended early: {request_dir}")
            expected_link_url = links["next"]
        else:
            stopped_reason = summary.get("stopped_reason")
            if stopped_reason == "created_at_cutoff_reached":
                if created_values[-1] < end:
                    raise VerificationError("Pulls cutoff stop precedes frozen end")
            elif stopped_reason == "pagination_exhausted":
                if "next" in links:
                    raise VerificationError("Pulls claims exhaustion despite next Link")
            else:
                raise VerificationError(f"unexpected Pulls stop reason: {stopped_reason}")
    if len(rows) != summary.get("items"):
        raise VerificationError("pulls summary count mismatch")
    if raw_items != summary.get("raw_items") or len(seen_all_pr_numbers) != summary.get(
        "unique_raw_pr_numbers"
    ):
        raise VerificationError("pulls raw/unique count mismatch")
    if github_request_ids != summary.get("github_request_ids"):
        raise VerificationError("Pulls request-ID ledger mismatch")
    if len(github_request_ids) != len(set(github_request_ids)):
        raise VerificationError("duplicate Pulls GitHub request ID")
    if repository_numeric_id != summary.get("repository_numeric_id"):
        raise VerificationError("Pulls canonical repository-ID summary mismatch")
    return rows, github_request_ids


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
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot read manifest snapshot: {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise VerificationError("manifest is not an object")
    expected = {
        "schema_version": EXPECTED_SCHEMA,
        "status": EXPECTED_MANIFEST_STATUS,
        "reconciliation_status": EXPECTED_STATUS,
        "verification_status": "pending",
        "downstream_eligible": False,
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
    run_id = manifest.get("run_id")
    auth_mode = manifest.get("auth_mode")
    if not isinstance(run_id, str) or auth_mode not in {
        "authenticated_public",
        "unauthenticated_public",
    }:
        raise VerificationError("manifest run identity/auth mode missing")
    identity = load_json(raw_root / "acquisition_identity.json")
    if (
        not isinstance(identity, dict)
        or identity.get("run_id") != run_id
        or identity.get("auth_mode") != auth_mode
        or identity.get("repository") != EXPECTED_REPOSITORY
        or identity.get("api_version") != EXPECTED_API_VERSION
        or identity.get("window") != manifest.get("window")
    ):
        raise VerificationError("raw-root acquisition identity mismatch")
    search1, search1_request_ids = rebuild_search(
        raw_root, manifest["search_pass_1"], start, end, run_id, auth_mode
    )
    pulls, pulls_request_ids = rebuild_pulls(
        raw_root, manifest["pulls"], start, end, run_id, auth_mode
    )
    search2, search2_request_ids = rebuild_search(
        raw_root, manifest["search_pass_2"], start, end, run_id, auth_mode
    )
    if not search1_request_ids or not pulls_request_ids or not search2_request_ids:
        raise VerificationError(
            "each traversal must retain at least one GitHub request ID"
        )
    comparison_errors = compare_censuses(search1, pulls, search2)
    if comparison_errors:
        raise VerificationError("; ".join(comparison_errors))
    all_request_ids = search1_request_ids + pulls_request_ids + search2_request_ids
    if len(all_request_ids) != len(set(all_request_ids)):
        raise VerificationError("traversals do not have distinct GitHub request IDs")

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
        "schema_version": "ghsa-merged-pr-reconciled-independent-verification-v2",
        "status": "pass",
        "downstream_eligible": True,
        "manifest": str(manifest_path.resolve()),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "run_id": run_id,
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
            "Mechanical reproduction of the three-pass endpoint-visible reconciled "
            "set; not proof of exhaustive public history or a field-change, "
            "correction, acceptance-semantics, or truth check."
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
            "schema_version": "ghsa-merged-pr-reconciled-independent-verification-v2",
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
