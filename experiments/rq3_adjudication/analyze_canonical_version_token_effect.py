#!/usr/bin/env python3
"""Compare raw and canonical version-token baselines on current diagnostics."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SILVER = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_CANDIDATE = (
    "results/expert_candidate_validation/rq3_expert_candidate_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"
METHOD_PAIRS = {
    "token": (
        "version_token_support_baseline",
        "canonical_version_token_support_baseline",
    ),
    "contextual_claim": (
        "contextual_version_claim_baseline",
        "contextual_canonical_version_claim_baseline",
    ),
    "package_gated_contextual_claim": (
        "package_gated_contextual_version_claim_baseline",
        "package_gated_contextual_canonical_version_claim_baseline",
    ),
    "package_gated_token": (
        "package_gated_token_baseline",
        "package_gated_canonical_token_baseline",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver-predictions", default=DEFAULT_SILVER)
    parser.add_argument("--candidate-predictions", default=DEFAULT_CANDIDATE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def load_methods(path: Path, *, field: str | None = None) -> dict[tuple[str, str], dict]:
    rows = {}
    methods = {method for pair in METHOD_PAIRS.values() for method in pair}
    for row in iter_jsonl(path):
        if field is not None and row.get("field") != field:
            continue
        if row.get("method") not in methods:
            continue
        key = (row["sample_id"], row["method"])
        if key in rows:
            raise ValueError(f"Duplicate prediction key in {path}: {key}")
        rows[key] = row
    return rows


def compare_pair(
    rows: dict[tuple[str, str], dict],
    raw_method: str,
    canonical_method: str,
    *,
    target_key: str,
) -> dict:
    raw_ids = {sample_id for sample_id, method in rows if method == raw_method}
    canonical_ids = {
        sample_id for sample_id, method in rows if method == canonical_method
    }
    if raw_ids != canonical_ids:
        raise ValueError(
            f"Method sample sets differ: {raw_method}={len(raw_ids)}, "
            f"{canonical_method}={len(canonical_ids)}"
        )

    outcomes = Counter()
    transitions = Counter()
    changed_cases = []
    for sample_id in sorted(raw_ids):
        raw = rows[(sample_id, raw_method)]
        canonical = rows[(sample_id, canonical_method)]
        target = raw[target_key]
        if canonical[target_key] != target:
            raise ValueError(f"Target mismatch for {sample_id}")
        raw_correct = raw["predicted_source"] == target
        canonical_correct = canonical["predicted_source"] == target
        if raw_correct and canonical_correct:
            outcomes["both_correct"] += 1
        elif raw_correct:
            outcomes["raw_only_correct"] += 1
        elif canonical_correct:
            outcomes["canonical_only_correct"] += 1
        else:
            outcomes["neither_correct"] += 1
        transition = f"{raw['predicted_source']}->{canonical['predicted_source']}"
        transitions[transition] += 1
        if raw["predicted_source"] != canonical["predicted_source"]:
            changed_cases.append(
                {
                    "sample_id": sample_id,
                    "cve_id": raw.get("cve_id"),
                    "target_source": target,
                    "raw_prediction": raw["predicted_source"],
                    "canonical_prediction": canonical["predicted_source"],
                    "raw_correct": raw_correct,
                    "canonical_correct": canonical_correct,
                }
            )

    sample_count = len(raw_ids)
    return {
        "sample_count": sample_count,
        "changed_count": len(changed_cases),
        "changed_rate": len(changed_cases) / sample_count if sample_count else 0.0,
        "raw_correct_count": outcomes["both_correct"] + outcomes["raw_only_correct"],
        "canonical_correct_count": (
            outcomes["both_correct"] + outcomes["canonical_only_correct"]
        ),
        "outcomes": dict(sorted(outcomes.items())),
        "transitions": dict(sorted(transitions.items())),
        "changed_cases": changed_cases,
    }


def analyze_dataset(
    path: Path,
    *,
    target_key: str,
    field: str | None = None,
) -> dict:
    rows = load_methods(path, field=field)
    return {
        name: compare_pair(
            rows,
            raw_method,
            canonical_method,
            target_key=target_key,
        )
        for name, (raw_method, canonical_method) in METHOD_PAIRS.items()
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# Canonical Version-Token Effect",
        "",
        "This diagnostic compares raw and canonical version-token matching. Silver labels are not human gold, and the expert-candidate subset was deliberately selected for high-information boundary cases.",
        "",
        "| Dataset | Pair | Samples | Changed | Raw correct | Canonical correct | Raw-only | Canonical-only |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for dataset, comparisons in summary["datasets"].items():
        for pair, values in comparisons.items():
            outcomes = values["outcomes"]
            lines.append(
                f"| {dataset} | {pair} | {values['sample_count']} | "
                f"{values['changed_count']} | {values['raw_correct_count']} | "
                f"{values['canonical_correct_count']} | "
                f"{outcomes.get('raw_only_correct', 0)} | "
                f"{outcomes.get('canonical_only_correct', 0)} |"
            )
    lines.extend(
        [
            "",
            "Interpretation: canonical matching is a representation-normalization ablation, not a semantic range adjudicator. Candidate-subset results must not be generalized to the 100-row sample or reported as human-gold performance.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    silver_path = resolve_path(args.silver_predictions)
    candidate_path = resolve_path(args.candidate_predictions)
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "artifact_type": "canonical_version_token_effect_diagnostic",
        "silver_label_is_gold": False,
        "candidate_label_is_human": False,
        "candidate_subset_is_representative": False,
        "inputs": {
            "silver_predictions": str(silver_path),
            "candidate_predictions": str(candidate_path),
        },
        "datasets": {
            "silver_v2": analyze_dataset(silver_path, target_key="silver_source"),
            "expert_candidate_targeted": analyze_dataset(
                candidate_path,
                target_key="candidate_source",
                field="affected_versions",
            ),
        },
    }
    json_path = output_dir / "canonical_version_token_effect.json"
    md_path = output_dir / "canonical_version_token_effect.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
