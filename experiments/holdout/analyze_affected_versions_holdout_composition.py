#!/usr/bin/env python3
"""Compare label-free input composition for development and holdout cohorts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/rq3_adjudication"))

from affected_versions_semantic_baseline import package_profile  # noqa: E402


DEFAULT_DEVELOPMENT = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_HOLDOUT = (
    "data/annotations/holdout/affected_versions_v1/evidence/"
    "source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development", default=DEFAULT_DEVELOPMENT)
    parser.add_argument("--holdout", default=DEFAULT_HOLDOUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 100 or len({row.get("cve_id") for row in rows}) != 100:
        raise ValueError(f"{path}: expected 100 unique CVEs")
    return rows


def cohort_stats(rows: list[dict]) -> dict:
    years = Counter()
    packages = Counter()
    nvd_spans = Counter()
    ghsa_spans = Counter()
    fetch_status = Counter()
    url_counts = []
    usable_counts = []
    for row in rows:
        match = re.match(r"CVE-(\d{4})-", row["cve_id"])
        years[match.group(1) if match else "unknown"] += 1
        packages[package_profile(row)["category"]] += 1
        nvd_spans[len(row.get("nvd_value") or [])] += 1
        ghsa_spans[len(row.get("ghsa_value") or [])] += 1
        records = row.get("evidence_context", {}).get("records", [])
        url_counts.append(len(records))
        usable = 0
        for record in records:
            status = record.get("fetch_status", "unknown")
            fetch_status[status] += 1
            usable += status == "ok" and bool(record.get("text_snippet"))
        usable_counts.append(usable)
    return {
        "rows": len(rows),
        "year_counts": dict(sorted(years.items())),
        "package_profile_counts": dict(sorted(packages.items())),
        "nvd_span_count_distribution": dict(sorted(nvd_spans.items())),
        "ghsa_span_count_distribution": dict(sorted(ghsa_spans.items())),
        "evidence_fetch_status_counts": dict(sorted(fetch_status.items())),
        "rows_with_usable_evidence": sum(count > 0 for count in usable_counts),
        "total_urls": sum(url_counts),
        "total_usable_records": sum(usable_counts),
        "mean_urls_per_row": sum(url_counts) / len(rows),
        "mean_usable_records_per_row": sum(usable_counts) / len(rows),
    }


def main() -> int:
    args = parse_args()
    development_path = resolve(args.development)
    holdout_path = resolve(args.holdout)
    output_dir = resolve(args.output_dir)
    development = load(development_path)
    holdout = load(holdout_path)
    overlap = {row["cve_id"] for row in development} & {row["cve_id"] for row in holdout}
    if overlap:
        raise ValueError(f"development/holdout CVE overlap: {sorted(overlap)[:5]}")
    artifact = {
        "artifact_type": "affected_versions_holdout_input_composition_v1",
        "analysis_uses_labels": False,
        "development_holdout_cve_overlap": 0,
        "development": cohort_stats(development),
        "holdout": cohort_stats(holdout),
        "inputs": {
            "development": {"path": str(development_path), "sha256": sha256(development_path)},
            "holdout": {"path": str(holdout_path), "sha256": sha256(holdout_path)},
        },
        "caution": "Both cohorts are conditional on the deterministic factual-conflict candidate miner.",
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_input_composition.json"
    output_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
