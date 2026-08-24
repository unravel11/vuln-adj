#!/usr/bin/env python3
"""Evaluate the task-separated predictor on already-unsealed development data."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from affected_versions_task_separated import predict_tasks


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEVELOPMENT = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_DEVELOPMENT_GOLD = (
    "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
)
DEFAULT_V1 = (
    "data/annotations/holdout/affected_versions_v1/evidence/source_rows.evidence.jsonl"
)
DEFAULT_V1_CONSENSUS = (
    "results/holdout/affected_versions_v1/affected_versions_holdout_consensus.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication/affected_versions_task_separated"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development", default=DEFAULT_DEVELOPMENT)
    parser.add_argument("--development-gold", default=DEFAULT_DEVELOPMENT_GOLD)
    parser.add_argument("--v1", default=DEFAULT_V1)
    parser.add_argument("--v1-consensus", default=DEFAULT_V1_CONSENSUS)
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


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def evaluate(name: str, inputs: list[dict], gold: dict[str, dict]) -> dict:
    rows = []
    for row in inputs:
        sample_id = row["sample_id"]
        if sample_id not in gold:
            continue
        prediction = predict_tasks(row)
        target = gold[sample_id]
        rows.append(
            {
                "sample_id": sample_id,
                "gold_type": target["discrepancy_label"],
                "gold_source": target["adjudicated_source"],
                "predicted_type": prediction["type"]["predicted_discrepancy_label"],
                "type_status": prediction["type"]["type_prediction_status"],
                "pipeline_source": prediction["source"]["predicted_source"],
                "source_head": prediction["source_head"]["predicted_source"],
            }
        )
    determinate = [row for row in rows if row["type_status"] == "determinate"]
    predicted_fc = [row for row in rows if row["predicted_type"] == "factual_conflict"]
    gold_fc = [row for row in rows if row["gold_type"] == "factual_conflict"]
    return {
        "name": name,
        "rows": len(rows),
        "gold_type_counts": dict(sorted(Counter(row["gold_type"] for row in rows).items())),
        "predicted_type_counts": dict(
            sorted(Counter(row["predicted_type"] for row in rows).items())
        ),
        "type_full_agreement": sum(
            row["gold_type"] == row["predicted_type"] for row in rows
        )
        / len(rows),
        "type_prediction_coverage": len(determinate) / len(rows),
        "type_selective_agreement": (
            sum(row["gold_type"] == row["predicted_type"] for row in determinate)
            / len(determinate)
            if determinate
            else None
        ),
        "type_selective_correct": sum(
            row["gold_type"] == row["predicted_type"] for row in determinate
        ),
        "type_determinate_rows": len(determinate),
        "predicted_fc_rows": len(predicted_fc),
        "predicted_fc_agree_with_gold_type": sum(
            row["gold_type"] == "factual_conflict" for row in predicted_fc
        ),
        "predicted_fc_source_agreement": sum(
            row["gold_type"] == "factual_conflict"
            and row["gold_source"] == row["pipeline_source"]
            for row in predicted_fc
        ),
        "gold_fc_rows": len(gold_fc),
        "source_head_determinate_on_gold_fc": sum(
            row["source_head"] not in {"abstain", "not_applicable"} for row in gold_fc
        ),
        "source_head_correct_on_gold_fc": sum(
            row["source_head"] not in {"abstain", "not_applicable"}
            and row["gold_source"] == row["source_head"]
            for row in gold_fc
        ),
        "source_head_selective_agreement_on_gold_fc": (
            sum(
                row["gold_source"] == row["source_head"]
                for row in gold_fc
                if row["source_head"] not in {"abstain", "not_applicable"}
            )
            / sum(
                row["source_head"] not in {"abstain", "not_applicable"}
                for row in gold_fc
            )
            if any(
                row["source_head"] not in {"abstain", "not_applicable"}
                for row in gold_fc
            )
            else None
        ),
    }


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Affected-Versions Task-Separated Development Diagnostic",
        "",
        "This is a post-hoc development diagnostic against non-human labels. It is not confirmatory or human-gold performance.",
        "",
        "| Cohort | Rows | Type coverage | Type selective agreement | Predicted FC type/source agreement | FC source-head coverage/agreement |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cohort in artifact["cohorts"]:
        lines.append(
            "| {name} | {rows} | {coverage:.4f} | {correct}/{determinate} | {fc_type}/{fc_rows}; {fc_source}/{fc_rows} | {source_correct}/{source_determinate}/{gold_fc} |".format(
                name=cohort["name"],
                rows=cohort["rows"],
                coverage=cohort["type_prediction_coverage"],
                correct=cohort["type_selective_correct"],
                determinate=cohort["type_determinate_rows"],
                fc_type=cohort["predicted_fc_agree_with_gold_type"],
                fc_source=cohort["predicted_fc_source_agreement"],
                fc_rows=cohort["predicted_fc_rows"],
                source_correct=cohort["source_head_correct_on_gold_fc"],
                source_determinate=cohort["source_head_determinate_on_gold_fc"],
                gold_fc=cohort["gold_fc_rows"],
            )
        )
    lines.extend(
        [
            "",
            "The method was selected after inspecting these cohorts. These values justify only freezing the candidate for v2; they do not establish expected holdout performance.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    development_path = resolve(args.development)
    development_gold_path = resolve(args.development_gold)
    v1_path = resolve(args.v1)
    v1_consensus_path = resolve(args.v1_consensus)
    output_dir = resolve(args.output_dir)

    development_gold_rows = load_jsonl(development_gold_path)
    development_gold = {
        row["annotation"]["sample_id"]: row["annotation"]
        for row in development_gold_rows
    }
    v1_consensus = {
        row["sample_id"]: row
        for row in load_jsonl(v1_consensus_path)
        if row["consensus_status"] == "strict_determinate"
    }
    cohorts = [
        evaluate("phase_d_ai_candidate", load_jsonl(development_path), development_gold),
        evaluate("v1_strict_dual_codex", load_jsonl(v1_path), v1_consensus),
    ]
    artifact = {
        "artifact_type": "affected_versions_task_separated_development_diagnostic_v1",
        "analysis_is_posthoc": True,
        "method_selected_after_inspecting_inputs": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "cohorts": cohorts,
        "inputs": {
            "development": {"path": str(development_path), "sha256": sha256(development_path)},
            "development_gold": {
                "path": str(development_gold_path),
                "sha256": sha256(development_gold_path),
            },
            "v1": {"path": str(v1_path), "sha256": sha256(v1_path)},
            "v1_consensus": {
                "path": str(v1_consensus_path),
                "sha256": sha256(v1_consensus_path),
            },
            "method": {
                "path": str(Path(__file__).with_name("affected_versions_task_separated.py")),
                "sha256": sha256(Path(__file__).with_name("affected_versions_task_separated.py")),
            },
        },
        "cautions": [
            "Both comparison targets are AI/Codex labels rather than human gold.",
            "The method was refined after inspecting both cohorts, so all values are development diagnostics.",
            "High selective agreement is conditional on very low prediction coverage.",
            "Only the untouched v2 cohort may test whether this selective behavior generalizes.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "development_diagnostic.json"
    md_path = output_dir / "development_diagnostic.md"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
