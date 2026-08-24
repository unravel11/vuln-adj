#!/usr/bin/env python3
"""Combine strict re-audits of prior determinate and prior abstain source rows."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASE_GOLD = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
DEFAULT_DETERMINATE_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/determinate_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_ABSTAIN_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit/uniform_strict"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-gold", default=DEFAULT_BASE_GOLD)
    parser.add_argument("--determinate-overlay", default=DEFAULT_DETERMINATE_OVERLAY)
    parser.add_argument("--abstain-overlay", default=DEFAULT_ABSTAIN_OVERLAY)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(f"{path}:{line_number}: duplicate/missing sample_id")
            rows[sample_id] = row
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    base_path = resolve(args.base_gold)
    determinate_path = resolve(args.determinate_overlay)
    abstain_path = resolve(args.abstain_overlay)
    output_dir = resolve(args.output_dir)
    base = load_jsonl(base_path)
    determinate = load_jsonl(determinate_path)
    abstain = load_jsonl(abstain_path)
    if len(base) != 100 or set(base) != set(determinate) or set(base) != set(abstain):
        raise ValueError("all uniform-overlay inputs must cover the same 100 rows")

    rows = []
    for sample_id in sorted(base):
        base_row = base[sample_id]
        prior_status = base_row.get("ai_gold_status")
        if prior_status == "final_determinate":
            selected = determinate[sample_id]
            expected_origins = {
                "dual_agent_strict_reaudit_selected_base",
                "unresolved_after_strict_selected_base_reaudit",
            }
            strict_cohort = "prior_final_determinate"
        else:
            selected = abstain[sample_id]
            expected_origins = {
                "dual_agent_strict_source_reaudit",
                "unresolved_after_source_reaudit",
            }
            strict_cohort = "prior_final_abstain"
        if selected.get("source_decision_origin") not in expected_origins:
            raise ValueError(
                f"{sample_id}: unexpected strict origin "
                f"{selected.get('source_decision_origin')}"
            )
        row = dict(selected)
        row["schema_version"] = "affected_versions_uniform_strict_source_overlay_v1"
        row["strict_reaudit_cohort"] = strict_cohort
        row["source_decision_origin"] = (
            "uniform_strict_original_determinate"
            if selected.get("source_gold_status") == "final_determinate"
            and strict_cohort == "prior_final_determinate"
            else "uniform_strict_prior_abstain_addition"
            if selected.get("source_gold_status") == "final_determinate"
            else "uniform_strict_unresolved"
        )
        row["label_is_human"] = False
        row["eligible_for_human_gold_claim"] = False
        row["eligible_for_final_paper_claim"] = False
        row["requires_human_signoff"] = True
        rows.append(row)

    determinate_rows = [
        row for row in rows if row.get("source_gold_status") == "final_determinate"
    ]
    original_accepted = [
        row
        for row in determinate_rows
        if row["strict_reaudit_cohort"] == "prior_final_determinate"
    ]
    additions = [
        row
        for row in determinate_rows
        if row["strict_reaudit_cohort"] == "prior_final_abstain"
    ]
    changed_original = [
        row
        for row in original_accepted
        if row.get("source_gold_label")
        != base[row["sample_id"]]["annotation"].get("adjudicated_source")
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "rq3_affected_versions_uniform_strict_source_overlay.jsonl"
    summary_path = output_dir / "rq3_affected_versions_uniform_strict_source_overlay_summary.json"
    write_jsonl(output_path, rows)
    summary = {
        "artifact_type": "affected_versions_uniform_strict_source_overlay",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "rows": len(rows),
        "determinate": len(determinate_rows),
        "abstain": len(rows) - len(determinate_rows),
        "coverage": len(determinate_rows) / len(rows),
        "original_40_strict_accepted": len(original_accepted),
        "prior_abstain_strict_additions": len(additions),
        "accepted_original_source_changes": len(changed_original),
        "source_counts": dict(
            sorted(Counter(row["source_gold_label"] for row in determinate_rows).items())
        ),
        "origin_counts": dict(
            sorted(Counter(row["source_decision_origin"] for row in rows).items())
        ),
        "inputs": {
            "base_gold": {"path": str(base_path), "sha256": sha256(base_path)},
            "determinate_overlay": {
                "path": str(determinate_path),
                "sha256": sha256(determinate_path),
            },
            "prior_abstain_overlay": {
                "path": str(abstain_path),
                "sha256": sha256(abstain_path),
            },
        },
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "cautions": [
            "Both strict reviewers are Codex agents, not human annotators.",
            "Only exact non-abstain agreement with no low-confidence decision is retained.",
            "The prior-abstain additions remain selection-aware because evidence refresh selection used prior AI status.",
        ],
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
