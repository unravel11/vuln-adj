#!/usr/bin/env python3
"""Build RQ3 annotation inputs with fetched evidence text."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = "data/annotations/rq3/silver_v2"
DEFAULT_CACHE_DIR = "data/evidence_cache/rq3/url_cache"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_MAX_BYTES = 1_500_000
DEFAULT_MAX_TEXT_CHARS = 5000


class EvidenceHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.skip_depth = 0
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.meta_dates: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        if tag == "title":
            self.in_title = True
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip_depth += 1
        if tag == "meta":
            key = (
                attrs_dict.get("property")
                or attrs_dict.get("name")
                or attrs_dict.get("itemprop")
                or ""
            ).lower()
            if key in {
                "article:published_time",
                "article:modified_time",
                "date",
                "dc.date",
                "dc.date.issued",
                "pubdate",
                "publishdate",
                "timestamp",
            }:
                content = attrs_dict.get("content", "").strip()
                if content:
                    self.meta_dates.append(content)
        if tag == "time":
            datetime_value = attrs_dict.get("datetime", "").strip()
            if datetime_value:
                self.meta_dates.append(datetime_value)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "noscript", "svg"} and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data: str) -> None:
        text = normalize_whitespace(data)
        if not text:
            return
        if self.in_title:
            self.title_parts.append(text)
        if self.skip_depth == 0:
            self.text_parts.append(text)


@dataclass(frozen=True)
class FetchConfig:
    timeout_seconds: int
    max_bytes: int
    max_text_chars: int
    sleep_seconds: float
    refresh: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch URL evidence and enrich RQ3 annotation samples."
    )
    parser.add_argument("input_path", help="Phase D/RQ3 sample JSONL.")
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for evidence-enriched JSONL and manifest.",
    )
    parser.add_argument(
        "--cache-dir",
        default=DEFAULT_CACHE_DIR,
        help="Directory for per-URL evidence cache records.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Maximum response bytes kept for text extraction.",
    )
    parser.add_argument(
        "--max-text-chars",
        type=int,
        default=DEFAULT_MAX_TEXT_CHARS,
        help="Maximum extracted body characters stored per URL.",
    )
    parser.add_argument(
        "--sleep-seconds",
        type=float,
        default=0.2,
        help="Delay after uncached fetches.",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Refetch URLs even when a cache record exists.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from a valid existing output or temp JSONL by sample_id.",
    )
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_resume_rows(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    rows: dict[str, dict] = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                print(f"Ignoring invalid resume suffix in {path} at line {line_number}")
                break
            sample_id = row.get("sample_id")
            if sample_id:
                rows[sample_id] = row
    return rows


def write_jsonl_rows(path: Path, rows: Iterable[dict], mode: str = "w") -> None:
    with path.open(mode, encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def unique_urls(row: dict) -> list[str]:
    urls: list[str] = []
    for context_key in ("nvd_context", "ghsa_context"):
        references = row.get(context_key, {}).get("references") or []
        if isinstance(references, list):
            urls.extend(str(url).strip() for url in references if str(url).strip())
    return list(dict.fromkeys(urls))


def cache_path_for_url(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest}.json"


def detect_charset(content_type: str | None) -> str:
    if not content_type:
        return "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type, re.IGNORECASE)
    if match:
        return match.group(1).strip("\"'")
    return "utf-8"


def extract_date(text: str, parser: EvidenceHTMLParser) -> str | None:
    if parser.meta_dates:
        return parser.meta_dates[0]
    match = re.search(r"\b(20[0-3][0-9]-[01][0-9]-[0-3][0-9])\b", text)
    if match:
        return match.group(1)
    return None


def parse_html(url: str, body: bytes, content_type: str | None, max_text_chars: int) -> dict:
    charset = detect_charset(content_type)
    html = body.decode(charset, errors="replace")
    parser = EvidenceHTMLParser()
    parser.feed(html)
    body_text = normalize_whitespace(" ".join(parser.text_parts))
    return {
        "url": url,
        "host": urlparse(url).netloc.lower(),
        "title": normalize_whitespace(" ".join(parser.title_parts)),
        "published": extract_date(body_text, parser),
        "text_snippet": body_text[:max_text_chars],
    }


def build_error_record(url: str, status: str, detail: str) -> dict:
    return {
        "url": url,
        "host": urlparse(url).netloc.lower(),
        "title": "",
        "published": None,
        "text_snippet": "",
        "fetch_status": status,
        "fetch_detail": detail[:300],
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def fetch_url(url: str, config: FetchConfig) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return build_error_record(url, "unsupported_scheme", parsed.scheme)

    request = Request(
        url,
        headers={
            "User-Agent": "vuln-adj-rq3-evidence-fetcher/0.1",
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
        },
    )
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=config.timeout_seconds, context=context) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read(config.max_bytes + 1)
            truncated = len(body) > config.max_bytes
            body = body[: config.max_bytes]
            if not (
                content_type.startswith("text/")
                or "html" in content_type
                or "xml" in content_type
            ):
                return build_error_record(url, "skipped_non_text", content_type)
            try:
                parsed_record = parse_html(url, body, content_type, config.max_text_chars)
            except Exception as exc:
                return build_error_record(
                    url,
                    "parse_error",
                    f"{type(exc).__name__}: {exc}",
                )
            parsed_record.update(
                {
                    "fetch_status": "ok",
                    "fetch_detail": f"HTTP {response.status}; content_type={content_type}; truncated={truncated}",
                    "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            return parsed_record
    except HTTPError as exc:
        return build_error_record(url, f"http_{exc.code}", str(exc))
    except URLError as exc:
        return build_error_record(url, "url_error", str(exc.reason))
    except TimeoutError as exc:
        return build_error_record(url, "timeout", str(exc))
    except Exception as exc:
        return build_error_record(url, "fetch_error", f"{type(exc).__name__}: {exc}")


def load_or_fetch(url: str, cache_dir: Path, config: FetchConfig) -> tuple[dict, bool]:
    path = cache_path_for_url(cache_dir, url)
    if path.exists() and not config.refresh:
        return json.loads(path.read_text(encoding="utf-8")), True

    record = fetch_url(url, config)
    path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if config.sleep_seconds:
        time.sleep(config.sleep_seconds)
    return record, False


def enrich_row(row: dict, evidence_records: list[dict]) -> dict:
    enriched = dict(row)
    enriched["evidence_context"] = {
        "candidate_url_count": len(evidence_records),
        "records": evidence_records,
    }
    return enriched


def main() -> int:
    args = parse_args()
    input_path = resolve_path(args.input_path)
    output_dir = resolve_path(args.output_dir)
    cache_dir = resolve_path(args.cache_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    config = FetchConfig(
        timeout_seconds=args.timeout_seconds,
        max_bytes=args.max_bytes,
        max_text_chars=args.max_text_chars,
        sleep_seconds=args.sleep_seconds,
        refresh=args.refresh,
    )

    output_path = output_dir / f"{input_path.stem}.evidence.jsonl"
    temp_output_path = output_path.with_suffix(output_path.suffix + ".tmp")
    rows = list(iter_jsonl(input_path))
    url_cache_hits = 0
    url_fetches = 0
    status_counts: dict[str, int] = {}

    completed_rows: dict[str, dict] = {}
    if args.resume:
        completed_rows.update(load_resume_rows(output_path))
        completed_rows.update(load_resume_rows(temp_output_path))

    if completed_rows:
        write_jsonl_rows(
            temp_output_path,
            (completed_rows[row["sample_id"]] for row in rows if row["sample_id"] in completed_rows),
        )

    output_mode = "a" if completed_rows else "w"
    with temp_output_path.open(output_mode, encoding="utf-8") as handle:
        for row in rows:
            sample_id = row["sample_id"]
            if sample_id in completed_rows:
                for record in completed_rows[sample_id].get("evidence_context", {}).get("records", []):
                    status = record.get("fetch_status", "unknown")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    url_cache_hits += 1
                continue
            evidence_records = []
            for url in unique_urls(row):
                record, from_cache = load_or_fetch(url, cache_dir, config)
                if from_cache:
                    url_cache_hits += 1
                else:
                    url_fetches += 1
                status = record.get("fetch_status", "unknown")
                status_counts[status] = status_counts.get(status, 0) + 1
                evidence_records.append(record)
            handle.write(json.dumps(enrich_row(row, evidence_records), ensure_ascii=False) + "\n")

    completed_sample_ids = {
        row["sample_id"] for row in load_resume_rows(temp_output_path).values()
    }
    expected_sample_ids = {row["sample_id"] for row in rows}
    if completed_sample_ids != expected_sample_ids:
        missing = sorted(expected_sample_ids - completed_sample_ids)
        raise RuntimeError(
            "Evidence build did not complete all rows; "
            f"completed={len(completed_sample_ids)}, expected={len(expected_sample_ids)}, "
            f"first_missing={missing[:5]}"
        )

    temp_output_path.replace(output_path)

    manifest = {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "cache_dir": str(cache_dir),
        "row_count": len(rows),
        "url_cache_hits": url_cache_hits,
        "url_fetches": url_fetches,
        "fetch_status_counts": dict(sorted(status_counts.items())),
        "max_text_chars": args.max_text_chars,
    }
    manifest_path = output_dir / f"{input_path.stem}.evidence_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Evidence-enriched samples: {output_path}")
    print(f"Evidence manifest:         {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
