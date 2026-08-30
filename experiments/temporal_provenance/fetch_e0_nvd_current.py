#!/usr/bin/env python3
"""Fetch the official current NVD records for the sealed E0 sample."""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from temporal_provenance_lib import canonical_json, project_nvd_record, sha256_bytes


ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0/"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        default="experiments/temporal_provenance/e0_sample_v1.json",
    )
    parser.add_argument(
        "--raw-output",
        default="data/raw/temporal_provenance/pilot_v1/nvd_api/current_e0.json",
    )
    parser.add_argument(
        "--output-dir",
        default="data/processed/temporal_provenance/pilot_v1/e0_nvd_current",
    )
    return parser.parse_args()


def build_url(cve_ids: list[str]) -> str:
    if not cve_ids or len(cve_ids) > 100:
        raise ValueError("cveIds batch must contain 1..100 IDs")
    query = urllib.parse.urlencode({"cveIds": ",".join(sorted(cve_ids))})
    return ENDPOINT + "?" + query


def fetch(url: str, attempts: int = 3) -> tuple[bytes, dict[str, str]]:
    headers = {
        "User-Agent": "vuln-adj-temporal-provenance-pilot-v1/1.0",
        "Accept": "application/json",
    }
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    last_error: Exception | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read()
                response_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
                return raw, response_headers
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(6 * (attempt + 1))
    assert last_error is not None
    raise RuntimeError(f"NVD request failed after {attempts} attempts: {last_error}")


def parse_records(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = {}
    for wrapper in payload.get("vulnerabilities") or []:
        record = wrapper.get("cve") or {}
        cve_id = record.get("id")
        if not isinstance(cve_id, str):
            raise ValueError("NVD response includes a record without an ID")
        if cve_id in records:
            raise ValueError(f"Duplicate NVD record: {cve_id}")
        records[cve_id] = record
    return records


def main() -> int:
    args = parse_args()
    sample_path = Path(args.sample).resolve()
    raw_output = Path(args.raw_output).resolve()
    output_dir = Path(args.output_dir).resolve()
    sample = json.loads(sample_path.read_text(encoding="utf-8"))
    if sample.get("status") != "sealed" or sample.get("selected_cves") != 100:
        raise ValueError("E0 sample must be sealed with exactly 100 CVEs")
    cve_ids = [row["cve_id"] for row in sample["rows"]]
    url = build_url(cve_ids)
    observed_at = datetime.now(timezone.utc).isoformat()
    raw, response_headers = fetch(url)
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    raw_output.write_bytes(raw)
    payload = json.loads(raw)
    records = parse_records(payload)
    missing = sorted(set(cve_ids) - set(records))
    unexpected = sorted(set(records) - set(cve_ids))

    output_dir.mkdir(parents=True, exist_ok=True)
    records_path = output_dir / "records.jsonl"
    with records_path.open("w", encoding="utf-8") as handle:
        for cve_id in sorted(records):
            handle.write(
                canonical_json(
                    {
                        "source": "nvd_official_api",
                        "observed_at": observed_at,
                        "cve_id": cve_id,
                        "raw_record_sha256": sha256_bytes(
                            canonical_json(records[cve_id]).encode("utf-8")
                        ),
                        "projection": project_nvd_record(records[cve_id]),
                    }
                )
                + "\n"
            )
    manifest = {
        "schema_version": "temporal-provenance-e0-nvd-current-v1",
        "status": "complete" if not missing and not unexpected else "incomplete",
        "endpoint": ENDPOINT,
        "request_parameter": "cveIds",
        "requested_cves": len(cve_ids),
        "returned_cves": len(records),
        "missing_cves": missing,
        "unexpected_cves": unexpected,
        "observed_at": observed_at,
        "raw_response": {
            "path": str(raw_output),
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
        },
        "response_metadata": {
            "timestamp": payload.get("timestamp"),
            "total_results": payload.get("totalResults"),
            "results_per_page": payload.get("resultsPerPage"),
            "headers": {
                key: value
                for key, value in response_headers.items()
                if key in {"content-type", "last-modified", "etag", "date"}
            },
        },
        "records_file": "records.jsonl",
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"NVD current {manifest['status']}: "
        f"requested={len(cve_ids)} returned={len(records)}"
    )
    print(f"Manifest: {manifest_path}")
    return 0 if manifest["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())

