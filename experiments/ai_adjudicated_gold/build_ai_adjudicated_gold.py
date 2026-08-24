#!/usr/bin/env python3
"""Build provenance-preserving AI-adjudicated gold snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "ai_adjudicated_gold_v1"
DATASETS = {
    "rq2_primary": {
        "candidate": "data/annotations/expert_candidate/raw/rq2_primary.jsonl",
        "output": "data/annotations/ai_adjudicated_gold/rq2_primary.jsonl",
        "expected_rows": 300,
        "artifact_role": "ai_gold_primary",
    },
    "rq2_review": {
        "candidate": "data/annotations/expert_candidate/raw/rq2_review.jsonl",
        "output": "data/annotations/ai_adjudicated_gold/rq2_review.jsonl",
        "expected_rows": 60,
        "artifact_role": "ai_consistency_pass",
    },
    "rq3_severity": {
        "candidate": "data/annotations/expert_candidate/raw/rq3_severity.jsonl",
        "output": "data/annotations/ai_adjudicated_gold/rq3_severity.jsonl",
        "expected_rows": 80,
        "artifact_role": "ai_gold_primary",
    },
    "rq3_affected_versions": {
        "candidate": "data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl",
        "output": "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl",
        "expected_rows": 100,
        "artifact_role": "ai_gold_primary",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=sorted(DATASETS), required=True)
    parser.add_argument("--candidate-input")
    parser.add_argument("--adjudication-input")
    parser.add_argument("--required-worklist")
    parser.add_argument("--output")
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            yield row


def load_unique(path: Path, key: str = "sample_id") -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        value = row.get(key)
        if not value:
            raise ValueError(f"{path}: row missing {key}")
        if value in rows:
            raise ValueError(f"{path}: duplicate {key}={value}")
        rows[value] = row
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def compact_candidate(row: dict) -> dict:
    return {
        "schema_version": row.get("schema_version"),
        "candidate_status": row.get("candidate_status"),
        "label_is_human": row.get("label_is_human"),
        "annotator_type": row.get("annotator_type"),
        "annotator_id": row.get("annotator_id"),
        "model": row.get("model"),
        "api_route": row.get("api_route"),
        "pass_id": row.get("pass_id"),
        "generated_at": row.get("generated_at"),
    }


def main() -> int:
    args = parse_args()
    spec = DATASETS[args.dataset]
    candidate_path = resolve(args.candidate_input or spec["candidate"])
    output_path = resolve(args.output or spec["output"])
    adjudication_path = resolve(args.adjudication_input) if args.adjudication_input else None
    worklist_path = resolve(args.required_worklist) if args.required_worklist else None

    candidates = load_unique(candidate_path)
    if len(candidates) != spec["expected_rows"]:
        raise ValueError(
            f"{args.dataset}: expected {spec['expected_rows']} candidates, found {len(candidates)}"
        )
    for sample_id, row in candidates.items():
        if row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: candidate label_is_human must be false")
        if not isinstance(row.get("annotation"), dict):
            raise ValueError(f"{sample_id}: candidate annotation is missing")

    adjudications = load_unique(adjudication_path) if adjudication_path else {}
    if set(adjudications) - set(candidates):
        raise ValueError("adjudication contains unknown candidate identities")
    for sample_id, row in adjudications.items():
        if row.get("label_is_human") is not False:
            raise ValueError(f"{sample_id}: adjudication label_is_human must be false")
        if row.get("eligible_for_human_gold_claim") is not False:
            raise ValueError(
                f"{sample_id}: adjudication must reject human-gold eligibility"
            )

    worklist_ids = set()
    if worklist_path:
        worklist_ids = set(load_unique(worklist_path))
        if worklist_ids != set(adjudications):
            missing = sorted(worklist_ids - set(adjudications))
            extra = sorted(set(adjudications) - worklist_ids)
            raise ValueError(
                f"risk worklist coverage mismatch: missing={missing[:5]} extra={extra[:5]}"
            )

    output_rows = []
    changed_label = 0
    changed_source = 0
    generated_at = datetime.now(timezone.utc).isoformat()
    for sample_id, candidate in candidates.items():
        candidate_annotation = candidate["annotation"]
        adjudication = adjudications.get(sample_id)
        annotation = adjudication["annotation"] if adjudication else candidate_annotation
        if annotation.get("sample_id") != sample_id:
            raise ValueError(f"{sample_id}: selected annotation identity mismatch")
        changed_label += (
            annotation.get("discrepancy_label")
            != candidate_annotation.get("discrepancy_label")
        )
        changed_source += (
            annotation.get("adjudicated_source")
            != candidate_annotation.get("adjudicated_source")
        )
        is_abstain = annotation.get("discrepancy_label") == "uncertain" or (
            args.dataset.startswith("rq3_")
            and annotation.get("adjudicated_source") == "abstain"
        )
        if spec["artifact_role"] == "ai_consistency_pass":
            decision_origin = "same_model_consistency_pass"
        elif adjudication:
            decision_origin = "interactive_ai_adjudication"
        else:
            decision_origin = "single_pass_candidate_accepted"
        output_rows.append(
            {
                "schema_version": SCHEMA_VERSION,
                "dataset": args.dataset,
                "artifact_role": spec["artifact_role"],
                "ai_gold_status": "final_abstain" if is_abstain else "final_determinate",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "eligible_for_provisional_candidate_analysis": True,
                "requires_human_signoff": True,
                "independent_human_review": False,
                "generated_at": generated_at,
                "sample_id": sample_id,
                "original_sample_id": candidate.get("original_sample_id"),
                "cve_id": annotation.get("cve_id"),
                "field": annotation.get("field"),
                "baseline_status": candidate.get("baseline_status"),
                "decision_origin": decision_origin,
                "requires_additional_review": bool(
                    annotation.get("needs_human_review")
                ),
                "candidate_provenance": compact_candidate(candidate),
                "adjudication_provenance": (
                    {
                        "schema_version": adjudication.get("schema_version"),
                        "adjudicator_id": adjudication.get("adjudicator_id"),
                        "model": adjudication.get("model"),
                        "api_route": adjudication.get("api_route"),
                        "pass_id": adjudication.get("pass_id"),
                        "generated_at": adjudication.get("generated_at"),
                        "worklist_sha256": adjudication.get("worklist_sha256"),
                        "decisions_sha256": adjudication.get("decisions_sha256"),
                        "selection_reasons": adjudication.get("selection_reasons"),
                        "interactive_review_note": adjudication.get(
                            "interactive_review_note"
                        ),
                    }
                    if adjudication
                    else None
                ),
                "annotation": annotation,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in output_rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    label_counts = Counter(
        row["annotation"]["discrepancy_label"] for row in output_rows
    )
    source_counts = Counter(
        row["annotation"]["adjudicated_source"] for row in output_rows
    )
    origin_counts = Counter(row["decision_origin"] for row in output_rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "dataset": args.dataset,
        "artifact_role": spec["artifact_role"],
        "row_count": len(output_rows),
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_provisional_candidate_analysis": True,
        "human_signed_rows": 0,
        "candidate_input": str(candidate_path),
        "candidate_sha256": sha256(candidate_path),
        "adjudication_input": str(adjudication_path) if adjudication_path else None,
        "adjudication_sha256": sha256(adjudication_path) if adjudication_path else None,
        "required_worklist": str(worklist_path) if worklist_path else None,
        "required_worklist_sha256": sha256(worklist_path) if worklist_path else None,
        "risk_worklist_rows": len(worklist_ids),
        "risk_rows_adjudicated": len(adjudications),
        "changed_label_count": changed_label,
        "changed_source_count": changed_source,
        "requires_additional_review_count": sum(
            row["requires_additional_review"] for row in output_rows
        ),
        "label_counts": dict(sorted(label_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "decision_origin_counts": dict(sorted(origin_counts.items())),
        "output": str(output_path),
        "output_sha256": sha256(output_path),
        "cautions": [
            "This snapshot is AI-adjudicated gold, not human-gold.",
            "Interactive adjudication and prior candidates are not independent human annotations.",
            "Rows marked final_abstain intentionally preserve unresolved uncertainty.",
            "Human annotator, independent reviewer, and author sign-off remain required for a human-gold claim.",
        ],
    }
    manifest_path = output_path.with_suffix(".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
