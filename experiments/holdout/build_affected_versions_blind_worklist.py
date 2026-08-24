#!/usr/bin/env python3
"""Build a label- and method-blind reviewer worklist from frozen evidence rows."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    "data/annotations/holdout/affected_versions_v1/evidence/"
    "source_rows.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "data/annotations/holdout/affected_versions_v1/blind"
ALLOWED_KEYS = (
    "sample_id",
    "cve_id",
    "nvd_source_id",
    "ghsa_source_id",
    "field",
    "nvd_value",
    "ghsa_value",
    "nvd_context",
    "ghsa_context",
    "evidence_context",
)
FORBIDDEN_KEY_PARTS = ("annotation", "baseline", "candidate", "gold", "prediction", "silver")


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


def forbidden_keys(value: object, prefix: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if any(part in lowered for part in FORBIDDEN_KEY_PARTS):
                found.append(path)
            found.extend(forbidden_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(forbidden_keys(child, f"{prefix}[{index}]"))
    return found


def blind_row(row: dict) -> dict:
    missing = [key for key in ALLOWED_KEYS if key not in row]
    if missing:
        raise ValueError(f"{row.get('sample_id')}: missing reviewer fields {missing}")
    blinded = {key: row[key] for key in ALLOWED_KEYS}
    evidence_context = row["evidence_context"]
    records = evidence_context.get("records") if isinstance(evidence_context, dict) else None
    if not isinstance(records, list):
        raise ValueError(f"{row.get('sample_id')}: evidence records must be a list")
    blinded["evidence_context"] = {"url_count": len(records), "records": records}
    forbidden = forbidden_keys(blinded)
    if forbidden:
        raise ValueError(f"{row.get('sample_id')}: forbidden keys remain {forbidden[:5]}")
    return blinded


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
            seen.add(sample_id)
            rows.append(row)
    if len(rows) != args.expected_rows:
        raise ValueError(f"expected {args.expected_rows} rows, found {len(rows)}")

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_blind_worklist.jsonl"
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest = {
        "artifact_type": "affected_versions_holdout_blind_worklist_v1",
        "contains_labels": False,
        "contains_method_predictions": False,
        "contains_prior_candidates": False,
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
