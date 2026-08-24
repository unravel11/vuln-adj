#!/usr/bin/env python3
"""Build the label- and method-blind affected_versions v2 reviewer worklist."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from build_affected_versions_blind_worklist import ALLOWED_KEYS, blind_row, forbidden_keys


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    "data/annotations/holdout/affected_versions_v2/evidence/"
    "source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/affected_versions_v2/blind"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-rows", type=int, default=100)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


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
    rows = []
    seen = set()
    with input_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = blind_row(json.loads(line))
            sample_id = row["sample_id"]
            if sample_id in seen:
                raise ValueError(f"{input_path}:{line_number}: duplicate sample_id")
            if not sample_id.startswith("affected_versions_holdout_v2:"):
                raise ValueError(f"{sample_id}: not a v2 sample")
            seen.add(sample_id)
            rows.append(row)
    if len(rows) != args.expected_rows:
        raise ValueError(f"expected {args.expected_rows} rows, found {len(rows)}")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_v2_blind_worklist.jsonl"
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    written_rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if any(set(row) != set(ALLOWED_KEYS) for row in written_rows):
        raise ValueError("written blind worklist has unexpected top-level keys")
    remaining_forbidden = [
        path for row in written_rows for path in forbidden_keys(row)
    ]
    if remaining_forbidden:
        raise ValueError(f"written blind worklist contains forbidden keys {remaining_forbidden[:3]}")
    manifest = {
        "artifact_type": "affected_versions_holdout_blind_worklist_v2",
        "contains_labels": bool(
            [path for path in remaining_forbidden if "gold" in path or "annotation" in path]
        ),
        "contains_method_predictions": bool(
            [path for path in remaining_forbidden if "prediction" in path]
        ),
        "contains_prior_candidates": bool(
            [path for path in remaining_forbidden if "candidate" in path or "baseline" in path]
        ),
        "rows": len(rows),
        "allowed_top_level_keys": list(ALLOWED_KEYS),
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {output_path}")
    print(f"Wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
