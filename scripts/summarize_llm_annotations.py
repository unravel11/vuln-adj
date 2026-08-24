#!/usr/bin/env python3
"""Summarize Phase D LLM draft annotations."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize LLM draft annotation JSONL files.")
    parser.add_argument("paths", nargs="+", help="LLM draft JSONL files.")
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def summarize(path: Path) -> dict:
    label_counts = Counter()
    false_positive_counts = Counter()
    source_counts = Counter()
    confidence_counts = Counter()
    total = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            ann = row["llm_annotation"]
            total += 1
            label_counts[ann["llm_label"]] += 1
            false_positive_counts[ann["is_baseline_false_positive"]] += 1
            source_counts[ann["adjudicated_source"]] += 1
            confidence_counts[ann["confidence"]] += 1
    return {
        "path": str(path),
        "total": total,
        "llm_label": dict(sorted(label_counts.items())),
        "is_baseline_false_positive": dict(sorted(false_positive_counts.items())),
        "adjudicated_source": dict(sorted(source_counts.items())),
        "confidence": dict(sorted(confidence_counts.items())),
    }


def main() -> int:
    args = parse_args()
    result = {"files": [summarize(resolve_path(path)) for path in args.paths]}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
