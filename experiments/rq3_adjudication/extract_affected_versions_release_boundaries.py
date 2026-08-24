#!/usr/bin/env python3
"""Extract gold-blind affected-version release-boundary features."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from affected_versions_release_boundary import extract_release_boundary_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/release_boundary"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    seen = set()
    with input_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in seen:
                raise ValueError(f"{input_path}:{line_number}: missing/duplicate sample_id")
            seen.add(sample_id)
            rows.append(extract_release_boundary_features(row))
    if len(rows) != 100:
        raise ValueError(f"expected 100 rows, found {len(rows)}")

    jsonl_path = output_dir / "affected_versions_release_boundary_features.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "artifact_type": "affected_versions_release_boundary_features",
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "rows": len(rows),
        "label_is_human": False,
        "feature_extraction_uses_gold": False,
        "eligible_for_human_gold_claim": False,
        "prediction_counts": dict(sorted(Counter(r["predicted_source"] for r in rows).items())),
        "reason_counts": dict(sorted(Counter(r["prediction_reason"] for r in rows).items())),
        "rows_with_evidence_claims": sum(bool(r["evidence_claims"]) for r in rows),
        "rows_with_any_support": sum(
            any(r["source_profiles"][s]["support_events"] for s in ("nvd", "ghsa"))
            for r in rows
        ),
        "rows_with_any_contradiction": sum(
            any(r["source_profiles"][s]["contradiction_events"] for s in ("nvd", "ghsa"))
            for r in rows
        ),
        "caution": (
            "Gold-blind lexical and interval diagnostic. It does not construct a "
            "release graph and is not human validation."
        ),
    }
    summary_path = output_dir / "affected_versions_release_boundary_features_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
