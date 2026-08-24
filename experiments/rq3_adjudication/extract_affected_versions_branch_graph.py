#!/usr/bin/env python3
"""Extract gold-blind affected-version branch/release-graph features."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from affected_versions_branch_graph import extract_branch_graph_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/branch_graph"


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
            rows.append(extract_branch_graph_features(row))
    if len(rows) != 100:
        raise ValueError(f"expected 100 rows, found {len(rows)}")

    jsonl_path = output_dir / "affected_versions_branch_graph_features.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    flag_counts = Counter()
    event_counts = Counter()
    for row in rows:
        flag_counts.update(row["capability_flags"])
        event_counts.update(row["structural_event_counts"])
    summary = {
        "artifact_type": "affected_versions_branch_graph_features",
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "rows": len(rows),
        "label_is_human": False,
        "feature_extraction_uses_gold": False,
        "eligible_for_human_gold_claim": False,
        "prediction_counts": dict(
            sorted(Counter(row["predicted_source"] for row in rows).items())
        ),
        "base_prediction_counts": dict(
            sorted(
                Counter(
                    row["base_release_boundary_prediction"] for row in rows
                ).items()
            )
        ),
        "changed_from_release_boundary": sum(
            row["predicted_source"] != row["base_release_boundary_prediction"]
            for row in rows
        ),
        "capability_flag_counts": dict(sorted(flag_counts.items())),
        "structural_event_counts": dict(sorted(event_counts.items())),
        "caution": (
            "Gold-blind exploratory representation. Leading numeric ordinals are "
            "used only for opaque interval exception checks; the representation "
            "does not establish ecosystem-specific release ordering or source authority."
        ),
    }
    summary_path = output_dir / "affected_versions_branch_graph_features_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {jsonl_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
