#!/usr/bin/env python3
"""Build a no-human artifact manifest for the result-neutral JSS package."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


FILES = (
    ("frozen_input", "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"),
    ("deterministic_result", "results/jss/t1_routing_precheck_v1/analysis.json"),
    ("deterministic_result", "results/jss/t1_routing_precheck_v1/analysis.md"),
    ("deterministic_result", "results/jss/t1_routing_precheck_v1/manifest.json"),
    ("literature_audit", "docs/related_work_papers/literature_manifest.json"),
    ("literature_audit", "docs/RELATED_WORK_AND_BASELINE_AUDIT_20260825.md"),
    ("citation_contract", "paper/jss/CITATION_EVIDENCE_MAP_20260826.md"),
    ("table_contract", "paper/jss/TABLE_EVIDENCE_CONTRACT.md"),
    ("prose_audit", "paper/jss/ACADEMIC_PROSE_AUDIT_20260826.md"),
    ("paper_governance", "paper/jss/EVIDENCE_LEDGER.md"),
    ("paper_governance", "paper/jss/CLAIM_LEDGER.md"),
    ("paper_governance", "paper/jss/paper_state.json"),
    ("venue_check", "paper/jss/JSS_SUBMISSION_CHECKLIST_20260825.md"),
    ("zero_draft", "paper/jss/manuscript.md"),
    ("latex_source", "paper/jss/latex/main.tex"),
    ("latex_source", "paper/jss/latex/references.bib"),
    ("latex_source", "paper/jss/latex/TEMPLATE_PROVENANCE.md"),
    ("latex_source", "paper/jss/latex/README.md"),
    ("table_data", "paper/jss/latex/rq1_status_counts.csv"),
    ("table_data", "paper/jss/latex/rq2_strategy_actions.csv"),
    ("table_data", "paper/jss/latex/rq2_pairwise_disagreements.csv"),
    ("table_source", "paper/jss/latex/table_rq1_status_counts.tex"),
    ("table_source", "paper/jss/latex/table_rq2_strategy_actions.tex"),
    ("table_source", "paper/jss/latex/table_rq2_pairwise_disagreements.tex"),
    ("build_evidence", "paper/jss/latex/BUILD_REPORT.md"),
    ("reproducer", "experiments/paper_artifacts/build_jss_deterministic_tables.py"),
    ("reproducer", "experiments/paper_artifacts/build_jss_artifact_manifest.py"),
    ("validator", "experiments/paper_artifacts/validate_jss_no_human_package.py"),
)

FORBIDDEN_PATH_PARTS = (
    "t1_human_validation",
    "reviewer_",
    "calibration",
    "formal",
    "reason_return",
    "action_return",
    "private",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(repo_root: Path, output: Path, base_head: str) -> dict:
    entries = []
    for role, relative in FILES:
        if any(part in relative.lower() for part in FORBIDDEN_PATH_PARTS):
            raise ValueError(f"human/private path is forbidden in artifact manifest: {relative}")
        path = repo_root / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        entries.append(
            {
                "path": relative,
                "role": role,
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )

    payload = {
        "schema_version": "1",
        "artifact_type": "jss_no_human_zero_draft_package",
        "built_on": "2026-08-26",
        "base_authority_head": base_head,
        "base_head_semantics": (
            "clean upstream-synchronized authority before this no-human package; "
            "the final branch HEAD must be read from Git"
        ),
        "source_scope": {
            "rows": 8066,
            "fields": 4,
            "field_instances": 32264,
            "snapshot_and_pipeline_bounded": True,
        },
        "claim_boundary": {
            "contains_human_results": False,
            "human_labels": 0,
            "uses_ai_as_human_gold": False,
            "eligible_for_accuracy_claim": False,
            "eligible_for_policy_superiority_claim": False,
            "eligible_for_workload_reduction_claim": False,
            "submission_ready": False,
        },
        "excluded_material": [
            "all analyst returns and reviewer-private materials",
            "reason-stage packets",
            "calibration-2 packets",
            "formal packets",
            "AI/Codex candidate labels",
        ],
        "files": entries,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--output", type=Path, default=Path("paper/jss/ARTIFACT_MANIFEST.json")
    )
    parser.add_argument(
        "--base-head",
        default="2334ecf5c07608873a0438127344954175fb4d48",
        help="Verified clean/upstream-synchronized HEAD before the package was created.",
    )
    args = parser.parse_args()
    build(args.repo_root.resolve(), args.output, args.base_head)


if __name__ == "__main__":
    main()
