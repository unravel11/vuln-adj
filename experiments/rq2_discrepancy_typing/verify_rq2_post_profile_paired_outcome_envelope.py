#!/usr/bin/env python3
"""Independently verify the RQ2 post-profile paired outcome envelope."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/paired_outcome_envelope_v1"
)
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", default=DEFAULT_RESULT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def checked(entry: dict, name: str) -> Path:
    path = Path(entry.get("path", ""))
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise ValueError(f"{name} path/hash mismatch")
    return path


def recompute(source_rows: list[dict], prediction_rows: list[dict]) -> dict:
    if len(source_rows) != 250 or len(prediction_rows) != 250:
        raise ValueError("expected 250 source and prediction rows")
    if [row.get("sample_id") for row in source_rows] != [
        row.get("sample_id") for row in prediction_rows
    ]:
        raise ValueError("source/prediction order drift")
    differences = []
    field_counts = Counter(row["field"] for row in source_rows)
    field_differences = Counter()
    for source, prediction in zip(source_rows, prediction_rows):
        current = prediction["current"]
        candidate = prediction["cwe_taxonomy_v1"]
        if current == candidate:
            continue
        field_differences[source["field"]] += 1
        differences.append(
            {
                "sample_id": source["sample_id"],
                "cve_id": source["cve_id"],
                "field": source["field"],
                "current_prediction": current,
                "candidate_prediction": candidate,
            }
        )
    delta_counts = Counter()
    for assignment in itertools.product(LABELS, repeat=len(differences)):
        delta = sum(
            int(label == row["candidate_prediction"])
            - int(label == row["current_prediction"])
            for row, label in zip(differences, assignment)
        )
        delta_counts[delta] += 1
    return {
        "differences": differences,
        "delta_counts": {
            str(delta): delta_counts[delta]
            for delta in range(-len(differences), len(differences) + 1)
        },
        "candidate_better": sum(
            count for delta, count in delta_counts.items() if delta > 0
        ),
        "current_better": sum(
            count for delta, count in delta_counts.items() if delta < 0
        ),
        "tied": delta_counts[0],
        "per_field_differences": dict(field_differences),
        "field_counts": dict(field_counts),
    }


def main() -> int:
    args = parse_args()
    result_dir = resolve(args.result_dir)
    manifest_path = result_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("artifact_type") != "rq2_post_profile_paired_outcome_envelope_manifest_v1":
        raise ValueError("unexpected manifest artifact_type")
    inputs = manifest.get("inputs") or {}
    outputs = manifest.get("outputs") or {}
    sealed_path = checked(inputs.get("sealed_manifest") or {}, "sealed manifest")
    source_path = checked(inputs.get("source_rows") or {}, "source rows")
    prediction_path = checked(inputs.get("predictions") or {}, "predictions")
    checked(inputs.get("contract") or {}, "contract")
    checked(inputs.get("analyzer") or {}, "analyzer")
    verifier_path = checked(inputs.get("verifier") or {}, "verifier")
    if verifier_path != Path(__file__).resolve():
        raise ValueError("manifest is not bound to this verifier")
    analysis_path = checked(outputs.get("analysis") or {}, "analysis")
    checked(outputs.get("markdown") or {}, "markdown")
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    for key, path in (("source_rows", source_path), ("predictions", prediction_path)):
        entry = (sealed.get("outputs") or {}).get(key) or {}
        if Path(entry.get("path", "")) != path or entry.get("sha256") != sha256(path):
            raise ValueError(f"sealed manifest no longer binds {key}")
    source_rows = list(iter_jsonl(source_path))
    prediction_rows = list(iter_jsonl(prediction_path))
    expected = recompute(source_rows, prediction_rows)
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    envelope = analysis.get("outcome_envelope") or {}
    if analysis.get("difference_rows") != expected["differences"]:
        raise ValueError("difference rows do not recompute")
    if envelope.get("paired_delta_assignment_counts") != expected["delta_counts"]:
        raise ValueError("paired delta counts do not recompute")
    if (
        envelope.get("candidate_better_assignments") != expected["candidate_better"]
        or envelope.get("current_better_assignments") != expected["current_better"]
        or envelope.get("tied_assignments") != expected["tied"]
    ):
        raise ValueError("assignment direction totals do not recompute")
    if analysis.get("rows") != 250 or analysis.get("prediction_difference_rows") != 3:
        raise ValueError("unexpected cohort/difference counts")
    if analysis.get("identical_prediction_rows") != 247:
        raise ValueError("unexpected equal-prediction count")
    if analysis.get("maximum_absolute_accuracy_difference") != 3 / 250:
        raise ValueError("unexpected full-cohort accuracy envelope")
    for field, count in expected["field_counts"].items():
        field_result = (analysis.get("per_field") or {}).get(field) or {}
        difference_count = expected["per_field_differences"].get(field, 0)
        if field_result != {
            "rows": count,
            "prediction_difference_rows": difference_count,
            "maximum_absolute_accuracy_difference": difference_count / count,
        }:
            raise ValueError(f"{field}: per-field envelope drift")
    boundary = manifest.get("claim_boundary") or {}
    if boundary != {
        "label_is_human": False,
        "uses_any_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_gain_claim": False,
        "candidate_promotion_allowed": False,
    }:
        raise ValueError("claim boundary drift")
    print(
        "Verified paired outcome envelope: rows=250 differences=3 "
        "assignments=125 max_abs_accuracy_delta=0.0120"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
