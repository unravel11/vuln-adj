#!/usr/bin/env python3
"""Enumerate the label-free paired outcome envelope for sealed RQ2 profiles."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_DIR = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_OUTPUT_DIR = (
    "results/holdout/rq2_post_profile_snapshot_v1/paired_outcome_envelope_v1"
)
DEFAULT_CONTRACT = (
    "docs/annotation_guidelines/"
    "rq2_post_profile_paired_outcome_envelope_contract_v1.md"
)
CURRENT_METHOD = "current"
CANDIDATE_METHOD = "cwe_taxonomy_v1"
EXPECTED_ROWS = 250
EXPECTED_ROWS_PER_FIELD = 50
EXPECTED_DIFFERENCES = 3
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--contract", default=DEFAULT_CONTRACT)
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
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def checked_output(manifest: dict, key: str) -> Path:
    entry = (manifest.get("outputs") or {}).get(key) or {}
    path = Path(entry.get("path", ""))
    if not path.is_file() or sha256(path) != entry.get("sha256"):
        raise ValueError(f"sealed manifest output/hash mismatch for {key}")
    return path


def load_bound_rows(base_dir: Path) -> tuple[Path, Path, Path, list[dict], list[dict]]:
    sealed_path = base_dir / "manifest.sealed.json"
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    if sealed.get("artifact_type") != "rq2_post_profile_snapshot_cohort_v1_manifest":
        raise ValueError("unexpected sealed cohort artifact_type")
    if sealed.get("selected_rows") != EXPECTED_ROWS:
        raise ValueError("sealed cohort must contain 250 rows")
    source_path = checked_output(sealed, "source_rows")
    prediction_path = checked_output(sealed, "predictions")
    source_rows = list(iter_jsonl(source_path))
    prediction_rows = list(iter_jsonl(prediction_path))
    if len(source_rows) != EXPECTED_ROWS or len(prediction_rows) != EXPECTED_ROWS:
        raise ValueError("expected 250 source and prediction rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    prediction_ids = [row.get("sample_id") for row in prediction_rows]
    if source_ids != prediction_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source/prediction IDs must be unique and ordered identically")
    field_counts = Counter(row.get("field") for row in source_rows)
    if set(field_counts.values()) != {EXPECTED_ROWS_PER_FIELD}:
        raise ValueError("expected 50 source rows per field")
    for source, prediction in zip(source_rows, prediction_rows):
        if (
            source.get("cve_id") != prediction.get("cve_id")
            or source.get("field") != prediction.get("field")
        ):
            raise ValueError(f"{source.get('sample_id')}: source/prediction drift")
        for method in (CURRENT_METHOD, CANDIDATE_METHOD):
            if prediction.get(method) not in LABELS:
                raise ValueError(
                    f"{source.get('sample_id')}: invalid sealed {method} label"
                )
    return sealed_path, source_path, prediction_path, source_rows, prediction_rows


def enumerate_assignment_deltas(differences: list[dict]) -> dict:
    delta_counts = Counter()
    candidate_better = current_better = tied = 0
    for labels in itertools.product(LABELS, repeat=len(differences)):
        delta = 0
        for row, label in zip(differences, labels):
            delta += int(label == row["candidate_prediction"])
            delta -= int(label == row["current_prediction"])
        delta_counts[delta] += 1
        candidate_better += delta > 0
        current_better += delta < 0
        tied += delta == 0
    return {
        "total_assignments": len(LABELS) ** len(differences),
        "paired_delta_assignment_counts": {
            str(delta): delta_counts[delta]
            for delta in range(-len(differences), len(differences) + 1)
        },
        "candidate_better_assignments": candidate_better,
        "current_better_assignments": current_better,
        "tied_assignments": tied,
        "assignment_counts_are_probabilities": False,
    }


def compute_analysis(source_rows: list[dict], prediction_rows: list[dict]) -> dict:
    differences = []
    field_counts = Counter(row["field"] for row in source_rows)
    field_differences = Counter()
    for source, prediction in zip(source_rows, prediction_rows):
        current = prediction[CURRENT_METHOD]
        candidate = prediction[CANDIDATE_METHOD]
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
    if len(differences) != EXPECTED_DIFFERENCES:
        raise ValueError(
            f"expected {EXPECTED_DIFFERENCES} sealed differences, found {len(differences)}"
        )
    envelope = enumerate_assignment_deltas(differences)
    per_field = {}
    for field in sorted(field_counts):
        count = field_differences[field]
        per_field[field] = {
            "rows": field_counts[field],
            "prediction_difference_rows": count,
            "maximum_absolute_accuracy_difference": count / field_counts[field],
        }
    return {
        "artifact_type": "rq2_post_profile_paired_outcome_envelope_v1",
        "label_source": "complete_enumeration_without_labels",
        "label_is_human": False,
        "uses_reviewer_labels": False,
        "uses_consensus_labels": False,
        "uses_evidence_secondary_labels": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_gain_claim": False,
        "strict_event_time_claim_allowed": False,
        "candidate_promotion_allowed": False,
        "production_default_changed": False,
        "current_method": CURRENT_METHOD,
        "candidate_method": CANDIDATE_METHOD,
        "rows": len(source_rows),
        "identical_prediction_rows": len(source_rows) - len(differences),
        "prediction_difference_rows": len(differences),
        "maximum_absolute_accuracy_difference": len(differences) / len(source_rows),
        "difference_rows": differences,
        "label_universe": list(LABELS),
        "outcome_envelope": envelope,
        "per_field": per_field,
        "human_review_implications": {
            "difference_rows_determine_paired_sign": True,
            "all_difference_rows_suffice_for_exact_paired_delta": True,
            "two_same_direction_wins_guarantee_paired_sign": True,
            "full_250_review_required_for_absolute_accuracy": True,
            "full_250_review_required_for_macro_f1": True,
            "external_identity_verification_required": True,
        },
        "interpretation": (
            "The assignment counts enumerate logical label cases and are not probabilities. "
            "Only three sealed rows can change the paired current-versus-CWE result, so "
            "the absolute full-cohort accuracy difference is bounded by 3/250=0.012 in "
            "either direction. Real-person review is still required."
        ),
    }


def render_markdown(analysis: dict) -> str:
    envelope = analysis["outcome_envelope"]
    lines = [
        "# RQ2 Post-profile Paired-outcome Envelope",
        "",
        f"- Sealed rows: `{analysis['rows']}`",
        f"- Equal predictions: `{analysis['identical_prediction_rows']}`",
        f"- Different predictions: `{analysis['prediction_difference_rows']}`",
        "- Maximum absolute full-cohort accuracy difference: "
        f"`{analysis['maximum_absolute_accuracy_difference']:.4f}`",
        f"- Complete logical assignments: `{envelope['total_assignments']}`",
        f"- Candidate-better assignments: `{envelope['candidate_better_assignments']}`",
        f"- Current-better assignments: `{envelope['current_better_assignments']}`",
        f"- Tied assignments: `{envelope['tied_assignments']}`",
        "",
        "| Paired delta | Logical assignments |",
        "|---:|---:|",
    ]
    for delta, count in envelope["paired_delta_assignment_counts"].items():
        lines.append(f"| {delta} | {count} |")
    lines.extend(
        [
            "",
            "These are logical assignment counts, not probabilities. The diagnostic reads "
            "no reviewer, consensus, evidence-secondary, or human label. It cannot support "
            "a human-gold, accuracy, confirmatory-gain, or promotion claim.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    output_dir = resolve(args.output_dir)
    contract_path = resolve(args.contract)
    analyzer_path = Path(__file__).resolve()
    verifier_path = analyzer_path.with_name(
        "verify_rq2_post_profile_paired_outcome_envelope.py"
    )
    if not contract_path.is_file() or not verifier_path.is_file():
        raise FileNotFoundError("contract or verifier is missing")
    sealed_path, source_path, prediction_path, source_rows, prediction_rows = (
        load_bound_rows(base_dir)
    )
    analysis = compute_analysis(source_rows, prediction_rows)
    analysis_path = output_dir / "analysis.json"
    markdown_path = output_dir / "summary.md"
    manifest_path = output_dir / "manifest.json"
    existing = [path for path in (analysis_path, markdown_path, manifest_path) if path.exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing outputs: {existing}")
    output_dir.mkdir(parents=True, exist_ok=True)
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    manifest = {
        "artifact_type": "rq2_post_profile_paired_outcome_envelope_manifest_v1",
        "inputs": {
            "sealed_manifest": {"path": str(sealed_path), "sha256": sha256(sealed_path)},
            "source_rows": {"path": str(source_path), "sha256": sha256(source_path)},
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
            "contract": {"path": str(contract_path), "sha256": sha256(contract_path)},
            "analyzer": {"path": str(analyzer_path), "sha256": sha256(analyzer_path)},
            "verifier": {"path": str(verifier_path), "sha256": sha256(verifier_path)},
        },
        "outputs": {
            "analysis": {"path": str(analysis_path), "sha256": sha256(analysis_path)},
            "markdown": {"path": str(markdown_path), "sha256": sha256(markdown_path)},
        },
        "claim_boundary": {
            "label_is_human": False,
            "uses_any_labels": False,
            "eligible_for_human_gold_claim": False,
            "eligible_for_confirmatory_gain_claim": False,
            "candidate_promotion_allowed": False,
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Paired outcome envelope: "
        f"differences={analysis['prediction_difference_rows']} "
        f"assignments={analysis['outcome_envelope']['total_assignments']} "
        f"max_abs_accuracy_delta={analysis['maximum_absolute_accuracy_difference']:.4f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
