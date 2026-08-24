#!/usr/bin/env python3
"""Extract selection-aware artifact-bound graph features for 100 RQ3 rows."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from affected_versions_artifact_graph import extract_artifact_graph_features


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/"
    "evidence_overlay/affected_versions_source_evidence_overlay.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/artifact_graph"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    input_path = resolve(args.input)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    with input_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            source = json.loads(line)
            feature = extract_artifact_graph_features(source)
            if not feature.get("sample_id"):
                raise ValueError(f"{input_path}:{line_number}: missing sample_id")
            rows.append(feature)
    if len(rows) != 100 or len({row["sample_id"] for row in rows}) != 100:
        raise ValueError("artifact graph requires 100 unique input rows")

    output_path = output_dir / "affected_versions_artifact_graph_features.jsonl"
    summary_path = output_dir / "affected_versions_artifact_graph_features_summary.json"
    with output_path.open("w", encoding="utf-8") as handle:
        for row in sorted(rows, key=lambda item: item["sample_id"]):
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "artifact_type": "affected_versions_artifact_graph_features",
        "rows": len(rows),
        "feature_extraction_uses_gold_labels": False,
        "feature_input_selection_uses_ai_gold_status": True,
        "eligible_for_independent_holdout_claim": False,
        "input": {"path": str(input_path), "sha256": sha256(input_path)},
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "prediction_counts": dict(
            sorted(Counter(row["predicted_source"] for row in rows).items())
        ),
        "base_prediction_counts": dict(
            sorted(
                Counter(row["base_branch_graph_prediction"] for row in rows).items()
            )
        ),
        "changed_rows": sum(row["prediction_changed"] for row in rows),
        "changed_sample_ids": sorted(
            row["sample_id"] for row in rows if row["prediction_changed"]
        ),
        "caution": (
            "The feature rule does not read labels, but evidence rows were "
            "refreshed because of prior AI-gold status. Results are selection-aware."
        ),
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
