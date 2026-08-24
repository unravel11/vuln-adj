#!/usr/bin/env python3
"""Diagnose post-hoc RQ2 holdout failure modes without changing the baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = "data/annotations/holdout/rq2_typing_v1/source_rows.jsonl"
DEFAULT_CONSENSUS = "results/holdout/rq2_typing_v1/dual_review_consensus.jsonl"
DEFAULT_OUTPUT_DIR = "results/holdout/rq2_typing_v1"
EXPECTED_ROWS = 1250
EXPECTED_ROWS_PER_FIELD = 250
SEVERITY_CANONICAL_MAP = {"MODERATE": "MEDIUM"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=DEFAULT_SOURCE)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def canonical_severity(value: dict | None) -> str | None:
    label = str((value or {}).get("label") or "").upper() or None
    return SEVERITY_CANONICAL_MAP.get(label, label)


def vector_relation(left: dict | None, right: dict | None) -> str:
    left_vector = str((left or {}).get("vector") or "")
    right_vector = str((right or {}).get("vector") or "")
    if not left_vector or not right_vector:
        return "one_or_both_missing"
    if left_vector == right_vector:
        return "exact"
    if left_vector.startswith(f"{right_vector}/") or right_vector.startswith(
        f"{left_vector}/"
    ):
        return "strict_prefix"
    return "different"


def score_relation(left: dict | None, right: dict | None) -> str:
    left_score = (left or {}).get("score")
    right_score = (right or {}).get("score")
    if left_score is None and right_score is None:
        return "both_missing"
    if left_score is None or right_score is None:
        return "one_missing"
    return "equal" if left_score == right_score else "different"


def is_unbounded_affected_record(value: dict) -> bool:
    absent = {None, "", 0, "0", "*", "-"}
    range_keys = (
        "introduced",
        "fixed",
        "version",
        "version_start_including",
        "version_start_excluding",
        "version_end_including",
        "version_end_excluding",
    )
    return bool(value.get("vulnerable", True)) and all(
        value.get(key) in absent for key in range_keys
    )


def is_unbounded_affected_claim(values: object) -> bool:
    return bool(values) and isinstance(values, list) and all(
        isinstance(value, dict) and is_unbounded_affected_record(value)
        for value in values
    )


def post_hoc_candidate(row: dict) -> tuple[str, str]:
    baseline = row["baseline_status"]
    if row["field"] == "severity":
        nvd_severity = canonical_severity(row.get("nvd_value"))
        ghsa_severity = canonical_severity(row.get("ghsa_value"))
    else:
        nvd_severity = ghsa_severity = None
    if nvd_severity is not None and nvd_severity == ghsa_severity:
        relation = vector_relation(row.get("nvd_value"), row.get("ghsa_value"))
        if relation == "different":
            return (
                "factual_conflict",
                "same canonical label but materially different supplied CVSS vectors",
            )
        if score_relation(row.get("nvd_value"), row.get("ghsa_value")) == "one_missing":
            return (
                "incomplete",
                "same canonical severity claim with a score present on only one side",
            )

    if (
        row["field"] == "affected_versions"
        and baseline == "equivalent"
        and bool(row.get("nvd_value")) != bool(row.get("ghsa_value"))
        and (
            is_unbounded_affected_claim(row.get("nvd_value"))
            or is_unbounded_affected_claim(row.get("ghsa_value"))
        )
    ):
        return (
            "incomplete",
            "one-sided unbounded affected claim was erased by span normalization",
        )
    return baseline, "unchanged"


def counter_dict(values) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def transition_counter(values) -> dict[str, int]:
    return counter_dict(" -> ".join(parts) for parts in values)


def accuracy(correct: int, rows: int) -> float | None:
    return correct / rows if rows else None


def analyze(source_rows: list[dict], consensus_rows: list[dict]) -> tuple[dict, list[dict]]:
    if len(source_rows) != EXPECTED_ROWS or len(consensus_rows) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} source and consensus rows")
    source_ids = [row.get("sample_id") for row in source_rows]
    consensus_ids = [row.get("sample_id") for row in consensus_rows]
    if source_ids != consensus_ids or len(set(source_ids)) != EXPECTED_ROWS:
        raise ValueError("source and consensus sample IDs must be unique and ordered identically")
    field_counts = Counter(row.get("field") for row in source_rows)
    if set(field_counts.values()) != {EXPECTED_ROWS_PER_FIELD}:
        raise ValueError("expected 250 rows for every holdout field")

    joined = list(zip(source_rows, consensus_rows))
    strict = [(row, consensus) for row, consensus in joined if consensus.get("strict_consensus")]
    strict_disagreements = [
        (row, consensus)
        for row, consensus in strict
        if row["baseline_status"] != consensus["consensus_label"]
    ]
    severity = [(row, consensus) for row, consensus in joined if row["field"] == "severity"]
    severity_strict_disagreements = [
        (row, consensus)
        for row, consensus in strict_disagreements
        if row["field"] == "severity"
    ]
    affected = [
        (row, consensus)
        for row, consensus in joined
        if row["field"] == "affected_versions"
    ]
    affected_strict_disagreements = [
        (row, consensus)
        for row, consensus in strict_disagreements
        if row["field"] == "affected_versions"
    ]

    diagnostics = []
    for row, consensus in joined:
        candidate, reason = post_hoc_candidate(row)
        if candidate == row["baseline_status"]:
            continue
        diagnostics.append(
            {
                "artifact_type": "rq2_typing_post_hoc_diagnostic_case",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "sample_id": row["sample_id"],
                "cve_id": row["cve_id"],
                "field": row["field"],
                "baseline_status": row["baseline_status"],
                "post_hoc_candidate_status": candidate,
                "strict_consensus": bool(consensus.get("strict_consensus")),
                "non_human_consensus_label": consensus.get("consensus_label"),
                "diagnostic_reason": reason,
            }
        )

    baseline_correct = sum(
        row["baseline_status"] == consensus["consensus_label"]
        for row, consensus in strict
    )
    candidate_correct = sum(
        post_hoc_candidate(row)[0] == consensus["consensus_label"]
        for row, consensus in strict
    )
    field_fit = {}
    for field in sorted(field_counts):
        field_rows = [(row, c) for row, c in strict if row["field"] == field]
        baseline_field_correct = sum(
            row["baseline_status"] == consensus["consensus_label"]
            for row, consensus in field_rows
        )
        candidate_field_correct = sum(
            post_hoc_candidate(row)[0] == consensus["consensus_label"]
            for row, consensus in field_rows
        )
        field_fit[field] = {
            "strict_rows": len(field_rows),
            "baseline_correct": baseline_field_correct,
            "baseline_accuracy": accuracy(baseline_field_correct, len(field_rows)),
            "post_hoc_candidate_correct": candidate_field_correct,
            "post_hoc_candidate_accuracy": accuracy(
                candidate_field_correct, len(field_rows)
            ),
            "post_hoc_correct_delta": candidate_field_correct - baseline_field_correct,
        }

    severity_label_vector_score = []
    for row, _consensus in severity_strict_disagreements:
        severity_label_vector_score.append(
            (
                "canonical_equal"
                if canonical_severity(row.get("nvd_value"))
                == canonical_severity(row.get("ghsa_value"))
                else "canonical_different",
                vector_relation(row.get("nvd_value"), row.get("ghsa_value")),
                score_relation(row.get("nvd_value"), row.get("ghsa_value")),
            )
        )

    affected_raw_side = []
    for row, _consensus in affected:
        left = bool(row.get("nvd_value"))
        right = bool(row.get("ghsa_value"))
        side = "both_nonempty" if left and right else "both_empty" if not left and not right else "one_empty"
        affected_raw_side.append((row["baseline_status"], side))

    metrics = {
        "artifact_type": "rq2_typing_holdout_failure_mode_diagnostic",
        "analysis_boundary": {
            "label_is_human": False,
            "eligible_for_human_gold_claim": False,
            "post_hoc": True,
            "production_baseline_changed": False,
            "valid_for_confirmatory_performance_claim": False,
            "interpretation": (
                "The profile was derived after inspecting the same non-human dual-review "
                "holdout and measures diagnostic fit only."
            ),
        },
        "cohort": {
            "rows": len(joined),
            "unique_cves": len({row["cve_id"] for row, _ in joined}),
            "field_counts": dict(sorted(field_counts.items())),
            "strict_consensus_rows": len(strict),
            "strict_baseline_disagreements": len(strict_disagreements),
        },
        "severity": {
            "rows": len(severity),
            "strict_rows": sum(c.get("strict_consensus") for _, c in severity),
            "score_relation": counter_dict(
                score_relation(row.get("nvd_value"), row.get("ghsa_value"))
                for row, _ in severity
            ),
            "vector_relation": counter_dict(
                vector_relation(row.get("nvd_value"), row.get("ghsa_value"))
                for row, _ in severity
            ),
            "canonical_label_equal": sum(
                canonical_severity(row.get("nvd_value"))
                == canonical_severity(row.get("ghsa_value"))
                for row, _ in severity
            ),
            "strict_disagreements": len(severity_strict_disagreements),
            "strict_disagreement_transitions": transition_counter(
                (row["baseline_status"], consensus["consensus_label"])
                for row, consensus in severity_strict_disagreements
            ),
            "strict_disagreement_feature_patterns": transition_counter(
                pattern for pattern in severity_label_vector_score
            ),
            "construct_mismatch": (
                "The baseline compares canonical labels only, while the frozen review "
                "protocol also compares scores, vectors, and CVSS versions."
            ),
        },
        "affected_versions": {
            "rows": len(affected),
            "strict_rows": sum(c.get("strict_consensus") for _, c in affected),
            "baseline_by_raw_presence": transition_counter(affected_raw_side),
            "strict_disagreements": len(affected_strict_disagreements),
            "strict_disagreement_transitions": transition_counter(
                (row["baseline_status"], consensus["consensus_label"])
                for row, consensus in affected_strict_disagreements
            ),
            "one_sided_unbounded_equivalent_to_incomplete": sum(
                row["baseline_status"] == "equivalent"
                and consensus["consensus_label"] == "incomplete"
                and bool(row.get("nvd_value")) != bool(row.get("ghsa_value"))
                and (
                    is_unbounded_affected_claim(row.get("nvd_value"))
                    or is_unbounded_affected_claim(row.get("ghsa_value"))
                )
                for row, consensus in affected_strict_disagreements
            ),
            "projection_loss": (
                "normalize_affected_spans removes package-specific records whose only "
                "range marker is introduced=0 or an equivalent unbounded marker."
            ),
        },
        "post_hoc_diagnostic_fit": {
            "strict_rows": len(strict),
            "baseline_correct": baseline_correct,
            "baseline_accuracy": accuracy(baseline_correct, len(strict)),
            "post_hoc_candidate_correct": candidate_correct,
            "post_hoc_candidate_accuracy": accuracy(candidate_correct, len(strict)),
            "post_hoc_correct_delta": candidate_correct - baseline_correct,
            "changed_rows_all_consensus_states": len(diagnostics),
            "fields": field_fit,
        },
    }
    return metrics, diagnostics


def render_markdown(metrics: dict) -> str:
    severity = metrics["severity"]
    affected = metrics["affected_versions"]
    fit = metrics["post_hoc_diagnostic_fit"]
    return "\n".join(
        [
            "# RQ2 Typing Holdout Failure-Mode Diagnostic",
            "",
            "This is a post-hoc, non-human diagnostic. It is not confirmatory performance evidence and does not modify the production baseline.",
            "",
            "## Verified patterns",
            "",
            f"- Severity strict disagreements: `{severity['strict_disagreements']}`.",
            f"- Severity rows with one missing score: `{severity['score_relation'].get('one_missing', 0)}` / `{severity['rows']}`.",
            f"- Affected-version one-sided unbounded projection losses: `{affected['one_sided_unbounded_equivalent_to_incomplete']}`.",
            "- Severity disagreement is dominated by a construct mismatch: the baseline uses labels, while the review protocol also uses score/vector/version.",
            "- The affected-version loss is concrete: a non-empty package-specific unbounded claim can normalize to an empty span set.",
            "",
            "## Post-hoc fit boundary",
            "",
            f"- Baseline strict fit: `{fit['baseline_correct']}/{fit['strict_rows']}` (`{fit['baseline_accuracy']:.4f}`).",
            f"- Diagnostic strict fit: `{fit['post_hoc_candidate_correct']}/{fit['strict_rows']}` (`{fit['post_hoc_candidate_accuracy']:.4f}`).",
            f"- Diagnostic delta: `+{fit['post_hoc_correct_delta']}` rows.",
            "",
            "The diagnostic profile was derived from these same model-reviewed rows. Its fit must not be reported as a holdout improvement; a newly frozen cohort with real human labels is required.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    source_path = resolve(args.source)
    consensus_path = resolve(args.consensus)
    output_dir = resolve(args.output_dir)
    source_rows = list(iter_jsonl(source_path))
    consensus_rows = list(iter_jsonl(consensus_path))
    metrics, diagnostics = analyze(source_rows, consensus_rows)
    metrics["inputs"] = {
        "source_rows": {"path": str(source_path), "sha256": sha256(source_path)},
        "non_human_consensus": {
            "path": str(consensus_path),
            "sha256": sha256(consensus_path),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "typing_holdout_failure_mode_diagnostic.json"
    md_path = output_dir / "typing_holdout_failure_mode_diagnostic.md"
    rows_path = output_dir / "typing_holdout_failure_mode_cases.jsonl"
    json_path.write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(metrics), encoding="utf-8")
    with rows_path.open("w", encoding="utf-8") as handle:
        for row in diagnostics:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
