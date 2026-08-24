#!/usr/bin/env python3
"""Build the evidence-refresh inputs for affected-version source re-audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GOLD = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
DEFAULT_EVIDENCE = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_OUTPUT_DIR = (
    "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", default=DEFAULT_GOLD)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-rows", type=int, default=45)
    parser.add_argument(
        "--selection-mode",
        choices=("abstain_with_source_suggestion", "final_determinate"),
        default="abstain_with_source_suggestion",
    )
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


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(
                    f"{path}:{line_number}: missing or duplicate sample_id"
                )
            rows[sample_id] = row
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    gold_path = resolve(args.gold)
    evidence_path = resolve(args.evidence)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    gold = load_jsonl(gold_path)
    evidence = load_jsonl(evidence_path)
    if len(gold) != 100 or set(gold) != set(evidence):
        raise ValueError("gold and evidence must cover the same 100 sample IDs")
    if any(row.get("label_is_human") is not False for row in gold.values()):
        raise ValueError("source gold must preserve non-human provenance")

    if args.selection_mode == "abstain_with_source_suggestion":
        selected_ids = sorted(
            sample_id
            for sample_id, row in gold.items()
            if row.get("ai_gold_status") == "final_abstain"
            and row.get("annotation", {}).get("adjudicated_source") != "abstain"
        )
        selection_contract = (
            "ai_gold_status=final_abstain and adjudicated_source!=abstain"
        )
        caution = (
            "These rows have a prior non-abstain source value but an uncertain "
            "discrepancy label. Re-audit must not treat missing evidence for the "
            "other source as affirmative contradiction."
        )
    else:
        selected_ids = sorted(
            sample_id
            for sample_id, row in gold.items()
            if row.get("ai_gold_status") == "final_determinate"
        )
        selection_contract = "ai_gold_status=final_determinate"
        caution = (
            "These rows were previously determinate under a non-uniform AI "
            "adjudication process. The strict re-audit must independently verify "
            "source support and may abstain or change the prior source."
        )
    if len(selected_ids) != args.expected_rows:
        raise ValueError(
            f"expected {args.expected_rows} source-status re-audit rows, "
            f"found {len(selected_ids)}"
        )

    source_rows = []
    candidate_rows = []
    for sample_id in selected_ids:
        source = dict(evidence[sample_id])
        source.pop("evidence_context", None)
        source_rows.append(source)
        candidate_rows.append(gold[sample_id])

    source_path = output_dir / "source_rows.jsonl"
    candidate_path = output_dir / "candidate_rows.jsonl"
    write_jsonl(source_path, source_rows)
    write_jsonl(candidate_path, candidate_rows)

    manifest = {
        "artifact_type": "affected_versions_source_reaudit_inputs",
        "selection_contract": selection_contract,
        "selection_mode": args.selection_mode,
        "rows": len(selected_ids),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "gold_input": {"path": str(gold_path), "sha256": sha256(gold_path)},
        "evidence_input": {
            "path": str(evidence_path),
            "sha256": sha256(evidence_path),
        },
        "source_rows": {"path": str(source_path), "sha256": sha256(source_path)},
        "candidate_rows": {
            "path": str(candidate_path),
            "sha256": sha256(candidate_path),
        },
        "prior_source_counts": dict(
            sorted(
                Counter(
                    gold[sample_id]["annotation"]["adjudicated_source"]
                    for sample_id in selected_ids
                ).items()
            )
        ),
        "prior_confidence_counts": dict(
            sorted(
                Counter(
                    gold[sample_id]["annotation"]["confidence"]
                    for sample_id in selected_ids
                ).items()
            )
        ),
        "sample_ids": selected_ids,
        "caution": caution,
    }
    manifest_path = output_dir / "selection_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
