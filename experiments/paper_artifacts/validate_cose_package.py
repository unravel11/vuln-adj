#!/usr/bin/env python3
"""Validate and manifest the current COSE paper package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree as ET


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYTHON_EXECUTABLE = sys.executable
DEFAULT_OUTPUT = "results/paper_cose/cose_package_manifest.json"
INTERNAL_ONLY_BANNER = (
    "Internal planning file only. Do not include in a journal submission package; "
    "use only to prepare final submission-facing documents."
)
INTERNAL_PLANNING_FILES = (
    "paper/cose/cover_letter_draft.md",
    "paper/cose/submission_readiness.md",
)
METHOD_EXPLAINER_PATH = "paper/cose/method_explainer.html"
METHOD_FRAMEWORK_SVG_PATH = "paper/cose/figures/method_framework.svg"
METHOD_FRAMEWORK_PNG_PATH = "paper/cose/figures/method_framework.png"
METHOD_FRAMEWORK_LATEX_PNG_PATH = "paper/cose/latex/figures/method_framework.png"
PDF_CONTACT_SHEET_PATH = "results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.png"
PDF_CONTACT_SHEET_MANIFEST_PATH = (
    "results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.json"
)
VISUAL_CHECK_SCREENSHOTS = {
    "method_explainer_desktop": (
        "results/paper_cose/visual_checks/method_explainer_1440.png",
        (1440, 1600),
    ),
    "method_explainer_mobile": (
        "results/paper_cose/visual_checks/method_explainer_mobile.png",
        (390, 1400),
    ),
    "method_framework_svg": (
        "results/paper_cose/visual_checks/method_framework_svg.png",
        (1280, 980),
    ),
}
SUBMISSION_OUTPUT_FILES = (
    "paper/cose/full_draft.md",
    "paper/cose/latex/main.tex",
    "paper/cose/latex/README.md",
)
INTERNAL_LEAK_PATTERNS = (
    "cover_letter_draft.md",
    "submission_readiness.md",
    "Scope Risks",
    "consider whether COSE remains",
)

RQ1_FIELDS = {"severity", "affected_versions", "published", "references", "cwe_ids"}
DISCREPANCY_TYPES = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
CLAIM_PATTERNS = re.compile(
    r"(outperform|higher accuracy|macro-F1|performance|promising)", re.IGNORECASE
)
CLAIM_GUARDS = (
    "silver",
    "non-human",
    "not human gold",
    "not gold",
    "not gold-backed",
    "not validated",
    "not a validated",
    "does not support",
    "human gold",
    "gold set",
    "diagnostic",
    "label-free",
    "logical assignments",
    "not probabilities",
    "blank",
    "not used to report",
    "not as accuracy",
    "cannot",
    "should therefore keep",
    "does not prove",
    "limited by",
    "preliminary",
)
AFFECTED_RISKY_PATTERNS = re.compile(
    r"(accuracy|macro-F1|performance|mismatch|error|false positive|false-positive|semantic|version-range|validated|resolves|adjudicates)",
    re.IGNORECASE,
)
AFFECTED_GUARDS = (
    "silver",
    "non-human",
    "diagnostic",
    "not human gold",
    "not validated",
    "not a validated",
    "does not support",
    "token-support",
    "manual-audit",
    "manual audit",
    "not semantic",
    "not a semantic",
    "does not",
    "cannot",
    "prototype",
    "schema-sensitive",
    "structured vulnerability-record field",
    "additional range-compatibility rules",
    "evidence builder",
    "evidence source",
    "case sketches",
    "not a semantic version-range adjudicator",
    "not as a semantic",
)
METHOD_FRAMEWORK_REQUIRED_TEXT = (
    "Method Framework: Type First, Adjudicate Only Residual Conflicts",
    "Inputs, Field Scope, and Operational Contract",
    "Ordered field-specific rules",
    "Routing Contract: Discrepancy Type Determines the Next Action",
    "EQ / RD",
    "INC / TD",
    "FC only",
    "URL provenance, status, snippets",
    "Decision + audit handoff",
    "silver now; human audit pending",
)
METHOD_EXPLAINER_REQUIRED_IDS = (
    "framework",
    "novelty",
    "stages",
    "contract",
    "labels",
    "actions",
    "evidence",
    "comparison",
    "boundary",
)
METHOD_EXPLAINER_REQUIRED_TEXT = (
    "字段级差异先类型化",
    "操作合同",
    "Field view",
    "Procedure",
    "差异类型决定下一步动作",
    "相关工作边界",
    "证据与 abstention",
    "field-typing workflow",
    "当前写作边界",
    "silver-label prototype",
    "human-gold",
)
RQ3_AUDIT_SCHEMA_VERSION = "rq3_human_audit_v1"
RQ3_AUDIT_DATASETS = {
    "severity": {
        "expected_rows": 80,
        "evidence_path": "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
        "jsonl_path": "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
        "csv_path": "data/annotations/rq3/gold_audit/severity_adjudication_audit.csv",
        "metrics_paths": [
            "results/rq3_adjudication/severity_gold_audit_eval_metrics.json",
            "results/rq3_adjudication/severity_gold_audit_eval_metrics.md",
            "results/rq3_adjudication/severity_gold_audit_predictions.jsonl",
        ],
    },
    "affected_versions": {
        "expected_rows": 100,
        "evidence_path": "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        "jsonl_path": "data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.jsonl",
        "csv_path": "data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.csv",
        "metrics_paths": [
            "results/rq3_adjudication/affected_versions_gold_audit_eval_metrics.json",
            "results/rq3_adjudication/affected_versions_gold_audit_eval_metrics.md",
            "results/rq3_adjudication/affected_versions_gold_audit_predictions.jsonl",
        ],
    },
}
RQ3_AUDIT_MANIFEST = "data/annotations/rq3/gold_audit/sample_manifest.json"
RQ3_AUDIT_README = "data/annotations/rq3/gold_audit/README.md"
RQ2_TYPING_HUMAN_REVIEW_SPECS = {
    "typing_v1": {
        "path": "results/holdout/rq2_typing_v1/human_review/rq2_typing_human_review_readiness.json",
        "artifact_type": "rq2_typing_human_review_readiness",
        "expected_rows": 1250,
        "workflow_complete_key": "workflow_complete",
    },
    "post_profile_snapshot_v1": {
        "path": "results/holdout/rq2_post_profile_snapshot_v1/human_review/rq2_post_profile_human_review_readiness.json",
        "artifact_type": "rq2_post_profile_human_review_readiness",
        "expected_rows": 250,
        "workflow_complete_key": "file_workflow_complete",
    },
}
RQ2_POST_PROFILE_UNRESOLVED_EVIDENCE_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "unresolved_evidence_secondary_v1/manifest.json"
)
RQ2_POST_PROFILE_PAIRED_TEST_IDENTIFIABILITY_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "paired_test_identifiability_v1/manifest.json"
)
RQ2_POST_PROFILE_ELIGIBLE_UNIVERSE_CENSUS_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/"
    "eligible_universe_prediction_census_v1/manifest.json"
)
RQ2_POST_PROFILE_ACQUISITION_DELTA_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v2/"
    "acquisition_delta_v1_to_v2/manifest.json"
)
RQ2_POST_PROFILE_CWE_DIFFERENCE_MERGE_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "cwe_eligible_difference_evidence_v1/merge_manifest.json"
)
RQ2_POST_PROFILE_REFERENCE_DIFFERENCE_MERGE_MANIFEST = (
    "results/holdout/rq2_post_profile_snapshot_v1/review/"
    "reference_difference_partition_v2/merge_manifest.json"
)


GENERATOR_SPECS = [
    {
        "name": "rq1_figures",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_rq1_figures.py",
        ],
        "generator": "experiments/paper_artifacts/build_rq1_figures.py",
        "inputs": [
            "data/processed/bootstrap/discrepancies/field_discrepancy_stats.json",
        ],
        "outputs": [
            "paper/cose/tables/rq1_discrepancy_distribution.csv",
            "paper/cose/tables/rq1_discrepancy_distribution.md",
            "paper/cose/figures/rq1_discrepancy_heatmap.svg",
        ],
        "temp_args": lambda tmp: [
            "--figure-dir",
            str(tmp / "rq1_figures/figures"),
            "--table-dir",
            str(tmp / "rq1_figures/tables"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "rq1_figures/tables/rq1_discrepancy_distribution.csv",
            tmp / "rq1_figures/tables/rq1_discrepancy_distribution.md",
            tmp / "rq1_figures/figures/rq1_discrepancy_heatmap.svg",
        ],
    },
    {
        "name": "rq2_sample_coverage",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/rq2_discrepancy_typing/analyze_rq2_sample_coverage.py",
        ],
        "generator": "experiments/rq2_discrepancy_typing/analyze_rq2_sample_coverage.py",
        "inputs": [
            "data/annotations/rq2/discrepancy_typing_seed.jsonl",
            "data/annotations/rq2/sample_manifest.json",
            "data/annotations/rq2/consistency_review/discrepancy_typing_consistency_review.jsonl",
            "data/annotations/rq2/consistency_review/sample_manifest.json",
            "results/rq2_discrepancy_typing/rq2_typing_diagnostics.json",
        ],
        "outputs": [
            "results/rq2_discrepancy_typing/rq2_sample_coverage.json",
            "results/rq2_discrepancy_typing/rq2_sample_coverage.md",
        ],
        "temp_args": lambda tmp: [
            "--output-dir",
            str(tmp / "rq2_discrepancy_typing"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "rq2_discrepancy_typing/rq2_sample_coverage.json",
            tmp / "rq2_discrepancy_typing/rq2_sample_coverage.md",
        ],
    },
    {
        "name": "rq3_silver_sensitivity",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/rq3_adjudication/analyze_rq3_silver_sensitivity.py",
        ],
        "generator": "experiments/rq3_adjudication/analyze_rq3_silver_sensitivity.py",
        "inputs": [
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
            "data/annotations/rq3/silver_v2/llm_silver_v2/severity_fc_adjudication_seed.evidence.llm_draft.jsonl",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
            "data/annotations/rq3/silver_v2/llm_silver_v2/affected_versions_fc_manual_check.evidence.llm_draft.jsonl",
        ],
        "outputs": [
            "results/rq3_adjudication/rq3_silver_baseline_sensitivity.json",
            "results/rq3_adjudication/rq3_silver_baseline_sensitivity.md",
        ],
        "temp_args": lambda tmp: [
            "--output-dir",
            str(tmp / "rq3_adjudication"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "rq3_adjudication/rq3_silver_baseline_sensitivity.json",
            tmp / "rq3_adjudication/rq3_silver_baseline_sensitivity.md",
        ],
    },
    {
        "name": "evidence_source_reliability",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/rq3_adjudication/analyze_evidence_source_reliability.py",
        ],
        "generator": "experiments/rq3_adjudication/analyze_evidence_source_reliability.py",
        "inputs": [
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
            "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
            "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl",
        ],
        "outputs": [
            "results/rq3_adjudication/evidence_source_reliability.json",
            "results/rq3_adjudication/evidence_source_reliability.md",
        ],
        "temp_args": lambda tmp: [
            "--output-dir",
            str(tmp / "rq3_adjudication"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "rq3_adjudication/evidence_source_reliability.json",
            tmp / "rq3_adjudication/evidence_source_reliability.md",
        ],
    },
    {
        "name": "rq3_human_audit_readiness",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/rq3_adjudication/analyze_rq3_human_audit_readiness.py",
        ],
        "generator": "experiments/rq3_adjudication/analyze_rq3_human_audit_readiness.py",
        "inputs": [
            "data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl",
            "data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.jsonl",
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
        ],
        "outputs": [
            "results/rq3_adjudication/rq3_human_audit_readiness.json",
            "results/rq3_adjudication/rq3_human_audit_readiness.md",
        ],
        "temp_args": lambda tmp: [
            "--output-dir",
            str(tmp / "rq3_adjudication"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "rq3_adjudication/rq3_human_audit_readiness.json",
            tmp / "rq3_adjudication/rq3_human_audit_readiness.md",
        ],
    },
    {
        "name": "cose_tables",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_cose_tables.py",
        ],
        "generator": "experiments/paper_artifacts/build_cose_tables.py",
        "inputs": [
            "data/processed/bootstrap/discrepancies/field_discrepancy_stats.json",
            "results/rq1_discrepancy_distribution/bootstrap_field_coverage_summary.json",
            "results/rq2_discrepancy_typing/rq2_typing_diagnostics.json",
            "results/rq2_discrepancy_typing/rq2_sample_coverage.json",
            "results/rq3_adjudication/severity_silver_v2_eval_metrics.json",
            "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
            "results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json",
            "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl",
            "results/rq3_adjudication/rq3_silver_error_modes.json",
            "results/rq3_adjudication/affected_versions_alignment_diagnostics.json",
            "results/rq3_adjudication/rq3_silver_baseline_sensitivity.json",
            "results/rq3_adjudication/evidence_source_reliability.json",
            "results/rq3_adjudication/rq3_human_audit_readiness.json",
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence_manifest.json",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence_manifest.json",
            "data/annotations/rq3/silver_v2/llm_silver_v2/affected_versions_fc_manual_check.evidence.llm_draft.jsonl",
        ],
        "outputs": [
            "results/paper_cose/cose_artifact_tables.json",
            "results/paper_cose/cose_artifact_tables.md",
        ],
        "temp_args": lambda tmp: ["--output-dir", str(tmp / "paper_cose")],
        "temp_outputs": lambda tmp: [
            tmp / "paper_cose/cose_artifact_tables.json",
            tmp / "paper_cose/cose_artifact_tables.md",
        ],
    },
    {
        "name": "cose_case_studies",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_cose_case_studies.py",
        ],
        "generator": "experiments/paper_artifacts/build_cose_case_studies.py",
        "inputs": [
            "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl",
            "data/annotations/rq3/silver_v2/llm_silver_v2/severity_fc_adjudication_seed.evidence.llm_draft.jsonl",
            "results/rq3_adjudication/severity_silver_v2_predictions.jsonl",
            "results/rq3_adjudication/rq3_silver_error_modes.json",
            "results/rq3_adjudication/affected_versions_alignment_diagnostics.json",
            "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl",
            "data/annotations/rq3/silver_v2/llm_silver_v2/affected_versions_fc_manual_check.evidence.llm_draft.jsonl",
        ],
        "outputs": [
            "results/paper_cose/cose_case_studies.json",
            "results/paper_cose/cose_case_studies.md",
            "paper/cose/tables/rq3_case_study_sketches.csv",
            "paper/cose/tables/rq3_case_study_sketches.md",
        ],
        "temp_args": lambda tmp: [
            "--output-dir",
            str(tmp / "paper_cose"),
            "--paper-table-dir",
            str(tmp / "paper_tables"),
        ],
        "temp_outputs": lambda tmp: [
            tmp / "paper_cose/cose_case_studies.json",
            tmp / "paper_cose/cose_case_studies.md",
            tmp / "paper_tables/rq3_case_study_sketches.csv",
            tmp / "paper_tables/rq3_case_study_sketches.md",
        ],
    },
    {
        "name": "cose_bibtex",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_cose_bibtex.py",
        ],
        "generator": "experiments/paper_artifacts/build_cose_bibtex.py",
        "inputs": ["paper/cose/references.md"],
        "outputs": ["paper/cose/references.bib"],
        "temp_args": lambda tmp: ["--output", str(tmp / "references.bib")],
        "temp_outputs": lambda tmp: [tmp / "references.bib"],
    },
    {
        "name": "cose_markdown",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_cose_manuscript.py",
        ],
        "generator": "experiments/paper_artifacts/build_cose_manuscript.py",
        "inputs": [
            "paper/cose/title_page.md",
            "paper/cose/highlights.md",
            "paper/cose/abstract.md",
            "paper/cose/sections/01_introduction.md",
            "paper/cose/sections/02_background_problem_definition.md",
            "paper/cose/sections/03_method.md",
            "paper/cose/sections/04_experimental_setup.md",
            "paper/cose/sections/05_results.md",
            "paper/cose/sections/06_discussion.md",
            "paper/cose/sections/07_threats_to_validity.md",
            "paper/cose/sections/08_related_work.md",
            "paper/cose/sections/09_conclusion.md",
            "paper/cose/references.md",
        ],
        "outputs": ["paper/cose/full_draft.md"],
        "temp_args": lambda tmp: ["--output", str(tmp / "full_draft.md")],
        "temp_outputs": lambda tmp: [tmp / "full_draft.md"],
    },
    {
        "name": "cose_latex",
        "command": [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_cose_latex.py",
        ],
        "generator": "experiments/paper_artifacts/build_cose_latex.py",
        "inputs": [
            "paper/cose/title_page.md",
            "paper/cose/abstract.md",
            "paper/cose/highlights.md",
            "paper/cose/declarations.md",
            "paper/cose/sections/01_introduction.md",
            "paper/cose/sections/02_background_problem_definition.md",
            "paper/cose/sections/03_method.md",
            "paper/cose/sections/04_experimental_setup.md",
            "paper/cose/sections/05_results.md",
            "paper/cose/sections/06_discussion.md",
            "paper/cose/sections/07_threats_to_validity.md",
            "paper/cose/sections/08_related_work.md",
            "paper/cose/sections/09_conclusion.md",
            "paper/cose/tables/rq1_discrepancy_distribution.csv",
            "paper/cose/tables/rq3_case_study_sketches.csv",
            "paper/cose/figures/rq1_discrepancy_heatmap.svg",
            "paper/cose/figures/method_framework.svg",
            "paper/cose/references.bib",
        ],
        "outputs": [
            "paper/cose/latex/main.tex",
            "paper/cose/latex/references.bib",
            "paper/cose/latex/sections/01_introduction.tex",
            "paper/cose/latex/sections/02_background_problem_definition.tex",
            "paper/cose/latex/sections/03_method.tex",
            "paper/cose/latex/sections/04_experimental_setup.tex",
            "paper/cose/latex/sections/05_results.tex",
            "paper/cose/latex/sections/06_discussion.tex",
            "paper/cose/latex/sections/07_threats_to_validity.tex",
            "paper/cose/latex/sections/08_related_work.tex",
            "paper/cose/latex/sections/09_conclusion.tex",
            "paper/cose/latex/sections/declarations.tex",
            "paper/cose/latex/tables/rq1_discrepancy_distribution.tex",
            "paper/cose/latex/tables/rq3_case_study_sketches.tex",
            "paper/cose/latex/figures/rq1_discrepancy_heatmap.png",
            "paper/cose/latex/figures/method_framework.png",
            "paper/cose/latex/README.md",
            "paper/cose/latex/Makefile",
        ],
        "temp_args": lambda tmp: ["--output-dir", str(tmp / "latex")],
        "temp_outputs": lambda tmp: [
            tmp / "latex/main.tex",
            tmp / "latex/references.bib",
            tmp / "latex/sections/01_introduction.tex",
            tmp / "latex/sections/02_background_problem_definition.tex",
            tmp / "latex/sections/03_method.tex",
            tmp / "latex/sections/04_experimental_setup.tex",
            tmp / "latex/sections/05_results.tex",
            tmp / "latex/sections/06_discussion.tex",
            tmp / "latex/sections/07_threats_to_validity.tex",
            tmp / "latex/sections/08_related_work.tex",
            tmp / "latex/sections/09_conclusion.tex",
            tmp / "latex/sections/declarations.tex",
            tmp / "latex/tables/rq1_discrepancy_distribution.tex",
            tmp / "latex/tables/rq3_case_study_sketches.tex",
            tmp / "latex/figures/rq1_discrepancy_heatmap.png",
            tmp / "latex/figures/method_framework.png",
            tmp / "latex/README.md",
            tmp / "latex/Makefile",
        ],
    },
]


class ValidationContext:
    def __init__(self) -> None:
        self.checks: list[dict] = []
        self.blockers: list[str] = []

    def check(self, name: str, ok: bool, details: str) -> None:
        self.checks.append({"name": name, "status": "pass" if ok else "fail", "details": details})

    def blocker(self, details: str) -> None:
        self.blockers.append(details)

    @property
    def failed(self) -> list[dict]:
        return [check for check in self.checks if check["status"] != "pass"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the COSE paper package.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--skip-latex-build",
        action="store_true",
        help="Do not run latexmk; validate generated source and existing log only.",
    )
    return parser.parse_args()


def resolve(path: str | Path) -> Path:
    path = Path(path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def rel(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path_value: str) -> dict:
    path = resolve(path_value)
    stat = path.stat()
    return {
        "path": rel(path),
        "sha256": sha256(path),
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def mtime_ns(path_value: str | Path) -> int:
    return resolve(path_value).stat().st_mtime_ns


def run_command(command: list[str], *, cwd: Path = PROJECT_ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def read_json(path_value: str | Path):
    return json.loads(resolve(path_value).read_text(encoding="utf-8"))


def iter_jsonl(path_value: str | Path):
    with resolve(path_value).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                yield line_number, json.loads(line)


def load_jsonl_by_sample_id(path_value: str | Path) -> dict[str, dict]:
    rows = {}
    for line_number, row in iter_jsonl(path_value):
        sample_id = row.get("sample_id")
        if not sample_id:
            raise ValueError(f"{path_value}:{line_number}: missing sample_id")
        if sample_id in rows:
            raise ValueError(f"{path_value}:{line_number}: duplicate sample_id {sample_id}")
        rows[sample_id] = row
    return rows


class IdCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)


def png_size(path: Path) -> tuple[int, int] | None:
    with path.open("rb") as handle:
        header = handle.read(24)
    if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")


def pdf_contact_sheet_consistency(
    metadata: dict,
    *,
    pdf_sha256: str,
    pdf_size_bytes: int,
    pdf_page_count: int | None,
    contact_sheet_sha256: str,
    contact_sheet_size_bytes: int,
    contact_sheet_dimensions: tuple[int, int] | None,
) -> dict[str, bool]:
    source_record = metadata.get("source_pdf", {})
    output_record = metadata.get("contact_sheet", {})
    rendered_pages = metadata.get("rendered_pages")
    expected_pages = (
        list(range(1, pdf_page_count + 1)) if pdf_page_count is not None else None
    )
    return {
        "source_identity": (
            pdf_page_count is not None
            and source_record.get("path") == "paper/cose/latex/main.pdf"
            and source_record.get("sha256") == pdf_sha256
            and source_record.get("size_bytes") == pdf_size_bytes
            and source_record.get("page_count") == pdf_page_count
        ),
        "complete_page_coverage": (
            expected_pages is not None
            and rendered_pages == expected_pages
            and metadata.get("rendered_page_count") == pdf_page_count
        ),
        "output_identity": (
            output_record.get("path") == PDF_CONTACT_SHEET_PATH
            and output_record.get("sha256") == contact_sheet_sha256
            and output_record.get("size_bytes") == contact_sheet_size_bytes
            and output_record.get("dimensions")
            == (list(contact_sheet_dimensions) if contact_sheet_dimensions else None)
        ),
    }


def sentence_windows(text: str) -> list[str]:
    sentences = re.split(r"(?<=[.!?])\s+", text)
    windows = []
    for index, sentence in enumerate(sentences):
        pieces = []
        if index > 0:
            pieces.append(sentences[index - 1])
        pieces.append(sentence)
        if index + 1 < len(sentences):
            pieces.append(sentences[index + 1])
        windows.append(" ".join(pieces))
    return windows


def markdown_citation_keys(text: str) -> set[str]:
    keys = set()
    for bracket in re.findall(r"\[([^\]]+)\]", text):
        parts = [part.strip() for part in bracket.split(",")]
        if parts and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9]+", part) for part in parts):
            keys.update(parts)
    return keys


def duplicate_values(values: list[str]) -> list[str]:
    counts = Counter(values)
    return sorted(value for value, count in counts.items() if count > 1)


def validate_rq1(ctx: ValidationContext) -> None:
    stats = read_json("data/processed/bootstrap/discrepancies/field_discrepancy_stats.json")
    ctx.check("rq1_processed_pairs", stats.get("processed_pairs") == 8066, str(stats.get("processed_pairs")))
    fields = set(stats.get("fields", {}))
    ctx.check("rq1_required_fields", RQ1_FIELDS <= fields, ", ".join(sorted(fields)))
    missing_types = []
    for field in RQ1_FIELDS:
        counts = stats["fields"].get(field, {})
        for dtype in DISCREPANCY_TYPES:
            if dtype not in counts:
                missing_types.append(f"{field}.{dtype}")
    ctx.check("rq1_discrepancy_type_keys", not missing_types, ", ".join(missing_types) or "all present")


def validate_rq2_blank_labels(ctx: ValidationContext) -> None:
    primary_rows = list(iter_jsonl("data/annotations/rq2/discrepancy_typing_seed.jsonl"))
    blank_primary = [
        row for _line, row in primary_rows if not row.get("annotation", {}).get("manual_status")
    ]
    ctx.check("rq2_primary_seed_rows", len(primary_rows) == 300, f"{len(primary_rows)} rows")
    ctx.check("rq2_primary_manual_status_blank", len(blank_primary) == 300, f"{len(blank_primary)}/300 blank")

    review_rows = list(
        iter_jsonl(
            "data/annotations/rq2/consistency_review/discrepancy_typing_consistency_review.jsonl"
        )
    )
    blank_review = [
        row
        for _line, row in review_rows
        if not row.get("review_annotation", {}).get("reviewer_status")
    ]
    ctx.check("rq2_consistency_rows", len(review_rows) == 60, f"{len(review_rows)} rows")
    ctx.check("rq2_reviewer_status_blank", len(blank_review) == 60, f"{len(blank_review)}/60 blank")

    forbidden_outputs = [
        "results/rq2_discrepancy_typing/rq2_manual_eval_metrics.json",
        "results/rq2_discrepancy_typing/rq2_manual_eval_metrics.md",
        "results/rq2_discrepancy_typing/rq2_annotation_consistency.json",
        "results/rq2_discrepancy_typing/rq2_annotation_consistency.md",
    ]
    present = [path for path in forbidden_outputs if resolve(path).exists()]
    ctx.check("rq2_no_blank_label_metrics", not present, ", ".join(present) or "no metric outputs")
    if blank_primary or blank_review:
        ctx.blocker("RQ2 primary/reviewer labels are blank; no RQ2 accuracy/agreement claim is submission-ready.")


def validate_rq2_full_impact_human_review(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    specs = {
        "references": {
            "path": "results/rq2_discrepancy_typing/reference_normalization_impact_human_review/reference_normalization_human_review_readiness.json",
            "artifact_type": "rq2_reference_normalization_human_review_readiness",
            "expected_rows": 56,
            "definition_sensitive_rows": 24,
        },
        "cwe_taxonomy": {
            "path": "results/rq2_discrepancy_typing/cwe_taxonomy/impact_human_review/cwe_taxonomy_human_review_readiness.json",
            "artifact_type": "rq2_cwe_taxonomy_human_review_readiness",
            "expected_rows": 17,
        },
    }
    summary = {}
    incomplete = []
    for name, spec in specs.items():
        path = spec["path"]
        if not resolve(path).exists():
            ctx.check(f"rq2_{name}_human_review_readiness_exists", False, f"{path} missing")
            incomplete.append(f"{name}: readiness artifact missing")
            continue
        artifact = read_json(path)
        expected_rows = spec["expected_rows"]
        rows = artifact.get("rows")
        signed = artifact.get("signed_final_rows")
        excluded = artifact.get("excluded_rows")
        pending = artifact.get("pending_rows")
        valid_shape = (
            artifact.get("artifact_type") == spec["artifact_type"]
            and artifact.get("packet_label_is_human") is False
            and rows == expected_rows
            and all(isinstance(value, int) for value in (signed, excluded, pending))
            and signed + excluded + pending == expected_rows
            and artifact.get("validation_error_count") == 0
        )
        if "definition_sensitive_rows" in spec:
            valid_shape = valid_shape and artifact.get(
                "definition_sensitive_rows"
            ) == spec["definition_sensitive_rows"]
        ctx.check(
            f"rq2_{name}_human_review_readiness_shape",
            valid_shape,
            (
                f"rows={rows}, signed={signed}, excluded={excluded}, "
                f"pending={pending}, errors={artifact.get('validation_error_count')}"
            ),
        )
        summary[name] = {
            "readiness": file_record(path),
            "rows": rows,
            "signed_final_rows": signed,
            "excluded_rows": excluded,
            "pending_rows": pending,
            "complete": artifact.get("complete"),
        }
        if artifact.get("complete") is not True:
            incomplete.append(f"{name}: {signed}/{expected_rows} signed")

    manifest["rq2_full_impact_human_review"] = summary
    if incomplete:
        ctx.blocker(
            "RQ2 full-impact real-human signoff is incomplete; non-human audits cannot substitute for human gold. "
            + "; ".join(incomplete)
        )


def validate_rq2_typing_human_review(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    summary = {}
    incomplete = []
    for name, spec in RQ2_TYPING_HUMAN_REVIEW_SPECS.items():
        path = spec["path"]
        if not resolve(path).exists():
            ctx.check(
                f"rq2_{name}_typing_human_review_readiness_exists",
                False,
                f"{path} missing",
            )
            incomplete.append(f"{name}: readiness artifact missing")
            continue
        artifact = read_json(path)
        expected_rows = spec["expected_rows"]
        rows = artifact.get("rows")
        signed = artifact.get("signed_final_rows")
        excluded = artifact.get("excluded_rows")
        pending = artifact.get("pending_rows")
        counts_are_valid = all(
            isinstance(value, int) for value in (signed, excluded, pending)
        ) and signed + excluded + pending == expected_rows
        valid_shape = (
            artifact.get("artifact_type") == spec["artifact_type"]
            and artifact.get("packet_label_is_human") is False
            and artifact.get("eligible_for_human_gold_claim") is False
            and artifact.get("external_identity_verification_required") is True
            and rows == expected_rows
            and counts_are_valid
            and artifact.get("validation_error_count") == 0
        )
        if name == "post_profile_snapshot_v1":
            valid_shape = valid_shape and (
                artifact.get("human_gold_promotion_performed") is False
                and artifact.get("validator_can_prove_real_person_identity") is False
            )
        ctx.check(
            f"rq2_{name}_typing_human_review_readiness_shape",
            valid_shape,
            (
                f"rows={rows}, signed={signed}, excluded={excluded}, "
                f"pending={pending}, errors={artifact.get('validation_error_count')}, "
                f"external_identity_required={artifact.get('external_identity_verification_required')}"
            ),
        )
        file_complete = (
            valid_shape
            and signed == expected_rows
            and excluded == 0
            and pending == 0
            and artifact.get(spec["workflow_complete_key"]) is True
        )
        summary[name] = {
            "readiness": file_record(path),
            "rows": rows,
            "signed_final_rows": signed,
            "excluded_rows": excluded,
            "pending_rows": pending,
            "file_workflow_complete": file_complete,
            "external_identity_verification_required": True,
            "validator_proves_real_person_identity": False,
        }
        if not file_complete:
            incomplete.append(f"{name}: {signed}/{expected_rows} signed")

    manifest["rq2_typing_human_review"] = summary
    if incomplete:
        ctx.blocker(
            "RQ2 full-cohort real-human signoff is incomplete; Codex decisions and blank packets cannot substitute for human gold. "
            + "; ".join(incomplete)
            + ". Real-person identity and reviewer independence still require external verification after file completion."
        )


def validate_rq2_post_profile_unresolved_evidence(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    path = resolve(RQ2_POST_PROFILE_UNRESOLVED_EVIDENCE_MANIFEST)
    if not path.is_file():
        ctx.check(
            "rq2_post_profile_unresolved_evidence_manifest_exists",
            False,
            f"{path} missing",
        )
        return
    result = read_json(path)
    records = {
        f"input.{name}": record for name, record in result.get("inputs", {}).items()
    }
    records.update(
        {
            f"output.{name}": record
            for name, record in result.get("outputs", {}).items()
        }
    )
    mismatches = []
    for name, record in records.items():
        record_path = resolve(record.get("path", ""))
        if not record_path.is_file() or sha256(record_path) != record.get("sha256"):
            mismatches.append(name)
    ctx.check(
        "rq2_post_profile_unresolved_evidence_hashes",
        not mismatches,
        f"mismatches={mismatches}",
    )
    summary_record = result.get("outputs", {}).get("summary", {})
    summary_path = resolve(summary_record.get("path", ""))
    summary = read_json(summary_path) if summary_path.is_file() else {}
    boundary_ok = (
        result.get("artifact_type")
        == "rq2_post_profile_unresolved_evidence_secondary_result_manifest_v1"
        and result.get("label_is_human") is False
        and result.get("eligible_for_human_gold_claim") is False
        and summary.get("label_is_human") is False
        and summary.get("selected_rows") == 16
        and summary.get("secondary_strict_rows") == 4
        and summary.get("combined_candidate_rows") == 238
        and summary.get("remaining_unresolved_rows") == 12
        and summary.get("advancement_gate", {}).get("status")
        == "no_go_post_selected_non_human_evidence_secondary"
        and summary.get("advancement_gate", {}).get("passed") is False
        and summary.get("boundary", {}).get("human_gold_claim_allowed") is False
        and summary.get("boundary", {}).get("confirmatory_claim_allowed") is False
        and summary.get("boundary", {}).get("production_switch_allowed") is False
    )
    ctx.check(
        "rq2_post_profile_unresolved_evidence_boundary",
        boundary_ok,
        (
            f"selected={summary.get('selected_rows')}, "
            f"strict={summary.get('secondary_strict_rows')}, "
            f"combined={summary.get('combined_candidate_rows')}, "
            f"gate={summary.get('advancement_gate', {}).get('status')}"
        ),
    )
    verifier = run_command(
        [
            PYTHON_EXECUTABLE,
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_unresolved_evidence_secondary.py",
        ]
    )
    ctx.check(
        "rq2_post_profile_unresolved_evidence_independent_verifier",
        verifier.returncode == 0,
        tail(verifier.stdout),
    )
    manifest["rq2_post_profile_unresolved_evidence_secondary"] = {
        "result_manifest": file_record(path),
        "selected_rows": summary.get("selected_rows"),
        "secondary_strict_rows": summary.get("secondary_strict_rows"),
        "combined_candidate_rows": summary.get("combined_candidate_rows"),
        "remaining_unresolved_rows": summary.get("remaining_unresolved_rows"),
        "gate": summary.get("advancement_gate", {}).get("status"),
        "label_is_human": False,
    }


def validate_rq2_post_profile_paired_test_identifiability(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    path = resolve(RQ2_POST_PROFILE_PAIRED_TEST_IDENTIFIABILITY_MANIFEST)
    if not path.is_file():
        ctx.check(
            "rq2_post_profile_paired_test_identifiability_manifest_exists",
            False,
            f"{path} missing",
        )
        return
    result = read_json(path)
    records = {
        f"input.{name}": record for name, record in result.get("inputs", {}).items()
    }
    records.update(
        {
            f"output.{name}": record
            for name, record in result.get("outputs", {}).items()
        }
    )
    mismatches = []
    for name, record in records.items():
        record_path = resolve(record.get("path", ""))
        if not record_path.is_file() or sha256(record_path) != record.get("sha256"):
            mismatches.append(name)
    ctx.check(
        "rq2_post_profile_paired_test_identifiability_hashes",
        not mismatches,
        f"mismatches={mismatches}",
    )
    analysis_record = result.get("outputs", {}).get("analysis", {})
    analysis_path = resolve(analysis_record.get("path", ""))
    analysis = read_json(analysis_path) if analysis_path.is_file() else {}
    exact_test = analysis.get("exact_test", {})
    representative = analysis.get("representative_assignment_enumeration", {})
    planning = analysis.get("planning_sensitivity", {})
    expected_classes = [
        [
            "current",
            "reference_resource_identity_original_v1",
            "reference_resource_identity_audited_v1",
        ],
        ["cwe_taxonomy_v1", "combined_original_v1", "combined_audited_v1"],
    ]
    boundary_ok = (
        result.get("artifact_type")
        == "rq2_post_profile_paired_test_identifiability_manifest_v1"
        and analysis.get("artifact_type")
        == "rq2_post_profile_paired_test_identifiability_v1"
        and analysis.get("label_is_human") is False
        and analysis.get("uses_any_labels") is False
        and analysis.get("eligible_for_human_gold_claim") is False
        and analysis.get("eligible_for_accuracy_claim") is False
        and analysis.get("eligible_for_confirmatory_gain_claim") is False
        and analysis.get("eligible_for_preregistered_power_claim") is False
        and analysis.get("candidate_promotion_allowed") is False
        and analysis.get("production_default_changed") is False
        and analysis.get("rows") == 250
        and analysis.get("profile_prediction_equivalence_classes")
        == expected_classes
        and exact_test.get("name") == "conditional_exact_two_sided_mcnemar"
        and exact_test.get("alpha") == 0.05
        and exact_test.get(
            "minimum_effective_correctness_discordant_rows_for_any_rejection"
        )
        == 6
        and exact_test.get("minimum_p_at_current_three_prediction_differences")
        == 0.25
        and exact_test.get(
            "any_current_profile_pair_can_reject_under_any_gold_assignment"
        )
        is False
        and representative.get("total_label_assignments") == 125
        and representative.get("rejecting_assignments_alpha_0_05") == 0
        and representative.get("minimum_attainable_two_sided_exact_p") == 0.25
        and planning.get("observed_prediction_difference_rate") == 3 / 250
        and planning.get("expected_rows_for_six_differences_at_observed_rate")
        == 500
        and planning.get("stationary_difference_rate_assumption") is True
        and planning.get("independent_random_sampling_assumption") is True
        and planning.get("power_is_conditional_on_correctness_discordance") is True
        and planning.get("planning_values_are_preregistered_sample_sizes") is False
    )
    ctx.check(
        "rq2_post_profile_paired_test_identifiability_boundary",
        boundary_ok,
        (
            f"classes={len(analysis.get('profile_prediction_equivalence_classes', []))}, "
            f"assignments={representative.get('total_label_assignments')}, "
            f"rejecting={representative.get('rejecting_assignments_alpha_0_05')}, "
            f"min_p={representative.get('minimum_attainable_two_sided_exact_p')}"
        ),
    )
    verifier = run_command(
        [
            PYTHON_EXECUTABLE,
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_paired_test_identifiability.py",
        ]
    )
    ctx.check(
        "rq2_post_profile_paired_test_identifiability_independent_verifier",
        verifier.returncode == 0,
        tail(verifier.stdout),
    )
    manifest["rq2_post_profile_paired_test_identifiability"] = {
        "result_manifest": file_record(path),
        "profile_equivalence_classes": analysis.get(
            "profile_prediction_equivalence_classes"
        ),
        "prediction_difference_rows": len(representative.get("difference_rows", [])),
        "minimum_attainable_two_sided_exact_p": representative.get(
            "minimum_attainable_two_sided_exact_p"
        ),
        "rejecting_assignments_alpha_0_05": representative.get(
            "rejecting_assignments_alpha_0_05"
        ),
        "minimum_effective_discordant_rows_for_any_rejection": exact_test.get(
            "minimum_effective_correctness_discordant_rows_for_any_rejection"
        ),
        "label_is_human": False,
    }


def validate_rq2_post_profile_eligible_universe_census(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    path = resolve(RQ2_POST_PROFILE_ELIGIBLE_UNIVERSE_CENSUS_MANIFEST)
    if not path.is_file():
        ctx.check(
            "rq2_post_profile_eligible_universe_census_manifest_exists",
            False,
            f"{path} missing",
        )
        return
    result = read_json(path)
    records = {
        f"input.{name}": record for name, record in result.get("inputs", {}).items()
    }
    records.update(
        {
            f"output.{name}": record
            for name, record in result.get("outputs", {}).items()
        }
    )
    mismatches = []
    for name, record in records.items():
        record_path = resolve(record.get("path", ""))
        if not record_path.is_file() or sha256(record_path) != record.get("sha256"):
            mismatches.append(name)
    ctx.check(
        "rq2_post_profile_eligible_universe_census_hashes",
        not mismatches,
        f"mismatches={mismatches}",
    )
    analysis_record = result.get("outputs", {}).get("analysis", {})
    analysis_path = resolve(analysis_record.get("path", ""))
    analysis = read_json(analysis_path) if analysis_path.is_file() else {}
    profile_counts = analysis.get("profile_difference_counts_vs_current", {})
    replay = analysis.get("sealed_sample_replay", {})
    expected_classes = [[profile] for profile in (
        "current",
        "reference_resource_identity_original_v1",
        "reference_resource_identity_audited_v1",
        "cwe_taxonomy_v1",
        "combined_original_v1",
        "combined_audited_v1",
    )]
    expected_profile_rows = {
        "reference_resource_identity_original_v1": 5,
        "reference_resource_identity_audited_v1": 3,
        "cwe_taxonomy_v1": 29,
        "combined_original_v1": 34,
        "combined_audited_v1": 32,
    }
    boundary_ok = (
        result.get("artifact_type")
        == "rq2_post_profile_eligible_universe_prediction_census_manifest_v1"
        and analysis.get("artifact_type")
        == "rq2_post_profile_eligible_universe_prediction_census_v1"
        and analysis.get("label_is_human") is False
        and analysis.get("uses_any_labels") is False
        and analysis.get("eligible_for_human_gold_claim") is False
        and analysis.get("eligible_for_accuracy_claim") is False
        and analysis.get("eligible_for_confirmatory_gain_claim") is False
        and analysis.get("eligible_for_temporal_generalization_claim") is False
        and analysis.get("eligible_for_preregistered_power_claim") is False
        and analysis.get("candidate_promotion_allowed") is False
        and analysis.get("production_default_changed") is False
        and analysis.get("same_snapshot_resampling_performed") is False
        and analysis.get("review_worklist_created") is False
        and analysis.get("eligible_tier") == "snapshot_external"
        and analysis.get("eligible_unique_cves") == 5_948
        and analysis.get("field_instances") == 29_740
        and analysis.get("union_prediction_difference_rows") == 34
        and analysis.get("union_prediction_difference_unique_cves") == 34
        and analysis.get("union_multi_field_difference_cves") == 0
        and analysis.get("profile_prediction_equivalence_classes")
        == expected_classes
        and {
            profile: values.get("rows")
            for profile, values in profile_counts.items()
        }
        == expected_profile_rows
        and replay.get("selected_rows") == 250
        and replay.get("prediction_replay_exact") is True
        and replay.get("sample_rates_are_population_estimates") is False
        and analysis.get("planning_boundary", {}).get(
            "prediction_difference_is_correctness_discordance"
        )
        is False
        and analysis.get("planning_boundary", {}).get(
            "future_strict_event_time_cohort_required"
        )
        is True
        and analysis.get("planning_boundary", {}).get(
            "current_snapshot_may_be_relabelled_as_confirmatory"
        )
        is False
    )
    ctx.check(
        "rq2_post_profile_eligible_universe_census_boundary",
        boundary_ok,
        (
            f"cves={analysis.get('eligible_unique_cves')}, "
            f"instances={analysis.get('field_instances')}, "
            f"difference_rows={analysis.get('union_prediction_difference_rows')}, "
            f"difference_cves={analysis.get('union_prediction_difference_unique_cves')}"
        ),
    )
    verifier = run_command(
        [
            PYTHON_EXECUTABLE,
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_eligible_universe_prediction_census.py",
        ]
    )
    ctx.check(
        "rq2_post_profile_eligible_universe_census_independent_verifier",
        verifier.returncode == 0,
        tail(verifier.stdout),
    )
    manifest["rq2_post_profile_eligible_universe_prediction_census"] = {
        "result_manifest": file_record(path),
        "eligible_unique_cves": analysis.get("eligible_unique_cves"),
        "field_instances": analysis.get("field_instances"),
        "union_prediction_difference_rows": analysis.get(
            "union_prediction_difference_rows"
        ),
        "union_prediction_difference_unique_cves": analysis.get(
            "union_prediction_difference_unique_cves"
        ),
        "profile_difference_rows_vs_current": expected_profile_rows,
        "sealed_sample_prediction_replay_exact": replay.get(
            "prediction_replay_exact"
        ),
        "label_is_human": False,
    }


def validate_rq2_post_profile_acquisition_delta(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    path = resolve(RQ2_POST_PROFILE_ACQUISITION_DELTA_MANIFEST)
    if not path.is_file():
        ctx.check(
            "rq2_post_profile_acquisition_delta_manifest_exists",
            False,
            f"{path} missing",
        )
        return
    result = read_json(path)
    records = {"builder": result.get("builder", {})}
    records.update(
        {f"input.{name}": record for name, record in result.get("inputs", {}).items()}
    )
    records.update(
        {
            f"output.{name}": record
            for name, record in result.get("outputs", {}).items()
        }
    )
    mismatches = []
    for name, record in records.items():
        record_path = resolve(record.get("path", ""))
        if not record_path.is_file() or sha256(record_path) != record.get("sha256"):
            mismatches.append(name)
    ctx.check(
        "rq2_post_profile_acquisition_delta_hashes",
        not mismatches,
        f"mismatches={mismatches}",
    )
    analysis_record = result.get("outputs", {}).get("analysis", {})
    analysis_path = resolve(analysis_record.get("path", ""))
    analysis = read_json(analysis_path) if analysis_path.is_file() else {}
    boundary = analysis.get("boundary", {})
    nvd = analysis.get("source_deltas", {}).get("nvd", {})
    ghsa = analysis.get("source_deltas", {}).get("ghsa", {})
    alignment = analysis.get("alignment_delta", {})
    readiness = analysis.get("strict_event_time_readiness", {})
    boundary_ok = (
        result.get("artifact_type")
        == "rq2_post_profile_acquisition_delta_manifest"
        and analysis.get("artifact_type")
        == "rq2_post_profile_acquisition_delta"
        and boundary == result.get("boundary")
        and boundary.get("contains_annotations") is False
        and boundary.get("selection_uses_labels") is False
        and boundary.get("label_is_human") is False
        and boundary.get("eligible_for_human_gold_claim") is False
        and boundary.get("production_switch_allowed") is False
        and nvd.get("previous_count") == 34056
        and nvd.get("current_count") == 34130
        and nvd.get("added_count") == 74
        and nvd.get("changed_count") == 26
        and nvd.get("published_after_profile_count") == 39
        and nvd.get("added_after_profile_count") == 39
        and ghsa.get("previous_count") == 33347
        and ghsa.get("current_count") == 33347
        and ghsa.get("added_count") == 0
        and ghsa.get("changed_count") == 0
        and ghsa.get("published_after_profile_count") == 0
        and alignment.get("previous_single_ghsa_count") == 5948
        and alignment.get("current_single_ghsa_count") == 5948
        and alignment.get("added_single_ghsa_count") == 0
        and alignment.get("removed_single_ghsa_count") == 0
        and alignment.get("changed_single_ghsa_count") == 0
        and alignment.get("field_views_byte_identical") is True
        and readiness.get("minimum_unique_cves") == 25
        and readiness.get("current_unique_cves") == 0
        and readiness.get("cohort_freeze_allowed") is False
        and readiness.get("decision") == "wait_for_bilateral_post_freeze_records"
        and readiness.get("bottleneck")
        == "no_ghsa_records_published_after_profile_freeze"
    )
    ctx.check(
        "rq2_post_profile_acquisition_delta_boundary",
        boundary_ok,
        (
            f"nvd_added={nvd.get('added_count')}, "
            f"nvd_post_freeze={nvd.get('published_after_profile_count')}, "
            f"ghsa_post_freeze={ghsa.get('published_after_profile_count')}, "
            f"strict={readiness.get('current_unique_cves')}, "
            f"decision={readiness.get('decision')}"
        ),
    )
    verifier = run_command(
        [
            PYTHON_EXECUTABLE,
            "experiments/rq2_discrepancy_typing/"
            "verify_rq2_post_profile_acquisition_delta.py",
        ]
    )
    ctx.check(
        "rq2_post_profile_acquisition_delta_independent_verifier",
        verifier.returncode == 0,
        tail(verifier.stdout),
    )
    manifest["rq2_post_profile_acquisition_delta"] = {
        "result_manifest": file_record(path),
        "nvd_added_records": nvd.get("added_count"),
        "nvd_records_published_after_profile": nvd.get(
            "published_after_profile_count"
        ),
        "ghsa_records_published_after_profile": ghsa.get(
            "published_after_profile_count"
        ),
        "strict_event_time_unique_cves": readiness.get("current_unique_cves"),
        "cohort_freeze_allowed": readiness.get("cohort_freeze_allowed"),
        "decision": readiness.get("decision"),
        "label_is_human": False,
    }


def validate_rq2_post_profile_complete_difference_reviews(
    ctx: ValidationContext,
    manifest: dict,
) -> None:
    cwe_merge_path = resolve(RQ2_POST_PROFILE_CWE_DIFFERENCE_MERGE_MANIFEST)
    if not cwe_merge_path.is_file():
        ctx.check(
            "rq2_post_profile_cwe_complete_difference_review_exists",
            False,
            f"{cwe_merge_path} missing",
        )
    else:
        cwe_merge = read_json(cwe_merge_path)
        cwe_summary_path = resolve(cwe_merge.get("outputs", {}).get("summary", {}).get("path", ""))
        cwe_summary = read_json(cwe_summary_path) if cwe_summary_path.is_file() else {}
        cwe_verifier = run_command(
            [
                PYTHON_EXECUTABLE,
                "experiments/rq2_discrepancy_typing/"
                "verify_rq2_post_profile_eligible_universe_cwe_difference_review.py",
            ]
        )
        cwe_ok = (
            cwe_verifier.returncode == 0
            and cwe_summary.get("artifact_type")
            == "rq2_post_profile_eligible_universe_cwe_difference_evidence_summary_v1"
            and cwe_summary.get("rows") == 29
            and cwe_summary.get("strict_rows") == 26
            and cwe_summary.get("candidate_direction_rows") == 25
            and cwe_summary.get("current_direction_rows") == 1
            and cwe_summary.get("neither_direction_rows") == 0
            and cwe_summary.get("unresolved_rows") == 3
            and cwe_summary.get("uses_human_labels") is False
            and cwe_summary.get("eligible_for_human_gold_claim") is False
            and cwe_summary.get("eligible_for_confirmatory_gain_claim") is False
            and cwe_summary.get("candidate_promotion_allowed") is False
            and cwe_summary.get("sealed_250_row_evaluation_changed") is False
            and cwe_summary.get("real_person_review_requirement_reduced") is False
        )
        ctx.check(
            "rq2_post_profile_cwe_complete_difference_review_verified",
            cwe_ok,
            (
                f"verifier={cwe_verifier.returncode}, rows={cwe_summary.get('rows')}, "
                f"strict={cwe_summary.get('strict_rows')}, "
                f"candidate/current/unresolved={cwe_summary.get('candidate_direction_rows')}/"
                f"{cwe_summary.get('current_direction_rows')}/{cwe_summary.get('unresolved_rows')}"
            ),
        )
        if cwe_ok:
            manifest["rq2_post_profile_complete_cwe_difference_review"] = {
                "merge_manifest": file_record(cwe_merge_path),
                "summary": file_record(cwe_summary_path),
                "rows": 29,
                "strict_rows": 26,
                "label_is_human": False,
            }

    reference_merge_path = resolve(
        RQ2_POST_PROFILE_REFERENCE_DIFFERENCE_MERGE_MANIFEST
    )
    if not reference_merge_path.is_file():
        ctx.check(
            "rq2_post_profile_reference_complete_difference_review_exists",
            False,
            f"{reference_merge_path} missing",
        )
    else:
        reference_merge = read_json(reference_merge_path)
        reference_summary_path = resolve(
            reference_merge.get("outputs", {}).get("summary", {}).get("path", "")
        )
        reference_summary = (
            read_json(reference_summary_path) if reference_summary_path.is_file() else {}
        )
        definitions = reference_summary.get("definitions", {})
        underlying = definitions.get("underlying_reference_resource_v1", {})
        frozen_http = definitions.get("frozen_http_resource_v1", {})
        current_original = frozen_http.get("profile_pairs", {}).get(
            "current_vs_original", {}
        )
        current_audited = frozen_http.get("profile_pairs", {}).get(
            "current_vs_audited", {}
        )
        reference_verifier = run_command(
            [
                PYTHON_EXECUTABLE,
                "experiments/rq2_discrepancy_typing/"
                "verify_rq2_post_profile_reference_difference_partition_review.py",
            ]
        )
        reference_ok = (
            reference_verifier.returncode == 0
            and reference_summary.get("artifact_type")
            == "rq2_post_profile_reference_difference_partition_summary_v2"
            and reference_summary.get("rows") == 5
            and underlying.get("strict_rows") == 1
            and underlying.get("unresolved_rows") == 4
            and frozen_http.get("strict_rows") == 3
            and frozen_http.get("unresolved_rows") == 2
            and current_original.get("prediction_difference_rows") == 5
            and current_original.get("right_direction_rows") == 3
            and current_original.get("conditional_exact_two_sided_mcnemar_p") == 0.25
            and current_audited.get("prediction_difference_rows") == 3
            and current_audited.get("right_direction_rows") == 3
            and current_audited.get("conditional_exact_two_sided_mcnemar_p") == 0.25
            and reference_summary.get("uses_human_labels") is False
            and reference_summary.get("eligible_for_human_gold_claim") is False
            and reference_summary.get("eligible_for_confirmatory_gain_claim") is False
            and reference_summary.get("candidate_promotion_allowed") is False
            and reference_summary.get("sealed_250_row_evaluation_changed") is False
            and reference_summary.get("real_person_review_requirement_reduced") is False
        )
        ctx.check(
            "rq2_post_profile_reference_complete_difference_review_verified",
            reference_ok,
            (
                f"verifier={reference_verifier.returncode}, rows={reference_summary.get('rows')}, "
                f"underlying={underlying.get('strict_rows')}/5, "
                f"frozen_http={frozen_http.get('strict_rows')}/5"
            ),
        )
        if reference_ok:
            manifest["rq2_post_profile_complete_reference_difference_review"] = {
                "merge_manifest": file_record(reference_merge_path),
                "summary": file_record(reference_summary_path),
                "rows": 5,
                "underlying_strict_rows": 1,
                "frozen_http_strict_rows": 3,
                "label_is_human": False,
            }


def validate_rq2_sample_coverage(ctx: ValidationContext) -> None:
    path = "results/rq2_discrepancy_typing/rq2_sample_coverage.json"
    if not resolve(path).exists():
        ctx.check("rq2_sample_coverage_artifact_exists", False, f"{path} missing")
        return

    artifact_tables_path = "results/paper_cose/cose_artifact_tables.json"
    if not resolve(artifact_tables_path).exists():
        ctx.check(
            "rq2_sample_coverage_wired_into_cose_tables",
            False,
            f"{artifact_tables_path} missing",
        )
        artifact_tables = {}
    else:
        artifact_tables = read_json(artifact_tables_path)

    artifact = read_json(path)
    primary = artifact.get("primary_seed", {})
    review = artifact.get("consistency_review", {})
    trigger = artifact.get("rule_trigger_coverage", {})
    checks = artifact.get("readiness_checks", {})
    wired = artifact_tables.get("rq2_sample_coverage", {})

    ctx.check(
        "rq2_sample_coverage_is_readiness_only",
        artifact.get("label_source") == "blank_annotation_templates"
        and artifact.get("gold_label_is_human") is False
        and artifact.get("metric_scope") == "readiness_diagnostic_only",
        (
            f"label_source={artifact.get('label_source')}, "
            f"gold_label_is_human={artifact.get('gold_label_is_human')}, "
            f"metric_scope={artifact.get('metric_scope')}"
        ),
    )
    ctx.check(
        "rq2_sample_coverage_primary_shape",
        primary.get("row_count") == 300
        and primary.get("blank_manual_status_rows") == 300
        and all(primary.get("field_counts", {}).get(field) == 60 for field in RQ1_FIELDS),
        (
            f"rows={primary.get('row_count')}, blank={primary.get('blank_manual_status_rows')}, "
            f"fields={primary.get('field_counts')}"
        ),
    )
    ctx.check(
        "rq2_sample_coverage_review_shape",
        review.get("row_count") == 60
        and review.get("blank_reviewer_status_rows") == 60
        and all(review.get("field_counts", {}).get(field) == 12 for field in RQ1_FIELDS),
        (
            f"rows={review.get('row_count')}, blank={review.get('blank_reviewer_status_rows')}, "
            f"fields={review.get('field_counts')}"
        ),
    )
    ctx.check(
        "rq2_sample_coverage_strata_and_top_triggers",
        primary.get("sampled_nonzero_candidate_strata") == primary.get(
            "nonzero_candidate_strata"
        )
        and trigger.get("covered_top_triggers") == trigger.get("top_trigger_count")
        and trigger.get("top_trigger_count") == 12,
        (
            f"strata={primary.get('sampled_nonzero_candidate_strata')}/"
            f"{primary.get('nonzero_candidate_strata')}, "
            f"top_triggers={trigger.get('covered_top_triggers')}/"
            f"{trigger.get('top_trigger_count')}"
        ),
    )
    ctx.check(
        "rq2_sample_coverage_readiness_checks_pass",
        bool(checks) and all(value is True for value in checks.values()),
        str(checks),
    )
    ctx.check(
        "rq2_sample_coverage_wired_into_cose_tables",
        wired.get("primary_seed", {}).get("row_count") == primary.get("row_count")
        and wired.get("rule_trigger_coverage", {}).get("covered_top_triggers")
        == trigger.get("covered_top_triggers"),
        (
            f"artifact_rows={wired.get('primary_seed', {}).get('row_count')}, "
            f"source_rows={primary.get('row_count')}"
        ),
    )


def validate_rq3_gold_audit_templates(ctx: ValidationContext, manifest: dict) -> None:
    paths = [RQ3_AUDIT_MANIFEST, RQ3_AUDIT_README]
    for spec in RQ3_AUDIT_DATASETS.values():
        paths.extend([spec["jsonl_path"], spec["csv_path"], spec["evidence_path"]])
    missing = [path for path in paths if not resolve(path).exists()]
    ctx.check("rq3_gold_audit_paths_exist", not missing, ", ".join(missing) or "all present")
    if missing:
        ctx.blocker(
            "RQ3 human audit outputs are absent or incomplete; RQ3 adjudication metrics remain silver/provisional and must not be reported as human-gold performance."
        )
        return

    audit_manifest = read_json(RQ3_AUDIT_MANIFEST)
    ctx.check(
        "rq3_gold_audit_schema_version",
        audit_manifest.get("schema_version") == RQ3_AUDIT_SCHEMA_VERSION,
        str(audit_manifest.get("schema_version")),
    )
    manifest_fields = {
        dataset.get("field"): dataset for dataset in audit_manifest.get("datasets", [])
    }
    ctx.check(
        "rq3_gold_audit_manifest_fields",
        set(manifest_fields) == set(RQ3_AUDIT_DATASETS),
        str(sorted(manifest_fields)),
    )

    audit_summary = {
        "manifest": file_record(RQ3_AUDIT_MANIFEST),
        "readme": file_record(RQ3_AUDIT_README),
        "datasets": {},
    }
    incomplete_fields = []
    metric_outputs_present_without_final_rows = []

    for field, spec in RQ3_AUDIT_DATASETS.items():
        audit_rows = load_jsonl_by_sample_id(spec["jsonl_path"])
        evidence_rows = load_jsonl_by_sample_id(spec["evidence_path"])
        expected_rows = spec["expected_rows"]
        csv_line_count = sum(1 for _line in resolve(spec["csv_path"]).open(encoding="utf-8"))
        manifest_item = manifest_fields.get(field, {})
        row_count_ok = len(audit_rows) == expected_rows
        csv_count_ok = csv_line_count == expected_rows + 1
        manifest_count_ok = manifest_item.get("row_count") == expected_rows
        ctx.check(
            f"rq3_{field}_gold_audit_row_counts",
            row_count_ok and csv_count_ok and manifest_count_ok,
            (
                f"jsonl={len(audit_rows)}, csv_lines={csv_line_count}, "
                f"manifest={manifest_item.get('row_count')}, expected={expected_rows}"
            ),
        )

        sample_ids_match = set(audit_rows) == set(evidence_rows)
        ctx.check(
            f"rq3_{field}_gold_audit_sample_ids_match_source",
            sample_ids_match,
            f"audit={len(audit_rows)}, evidence={len(evidence_rows)}",
        )

        schema_mismatches = []
        id_mismatches = []
        status_counts = Counter()
        blank_human_rows = 0
        final_rows = 0
        llm_authoritative_rows = 0
        for sample_id, audit_row in audit_rows.items():
            if audit_row.get("schema_version") != RQ3_AUDIT_SCHEMA_VERSION:
                schema_mismatches.append(sample_id)
            evidence_row = evidence_rows.get(sample_id, {})
            for key in ("cve_id", "field", "nvd_source_id", "ghsa_source_id"):
                if audit_row.get(key) != evidence_row.get(key):
                    id_mismatches.append(f"{sample_id}.{key}")
            human = audit_row.get("human_audit") or {}
            status = str(human.get("audit_status") or "").strip().lower()
            status_counts[status or "<blank>"] += 1
            if status == "final":
                final_rows += 1
            if (
                status == "draft"
                and not human.get("human_label")
                and not human.get("is_baseline_false_positive")
                and not human.get("adjudicated_source")
                and not human.get("adjudicated_value")
                and not human.get("evidence_urls")
            ):
                blank_human_rows += 1
            if "llm_annotation" in audit_row:
                llm_authoritative_rows += 1

        if final_rows < expected_rows:
            incomplete_fields.append(f"{field}: {final_rows}/{expected_rows} final")
        ctx.check(
            f"rq3_{field}_gold_audit_schema_on_rows",
            not schema_mismatches,
            ", ".join(schema_mismatches[:10]) or "all rows",
        )
        ctx.check(
            f"rq3_{field}_gold_audit_identifiers_preserved",
            not id_mismatches,
            ", ".join(id_mismatches[:10]) or "all identifiers preserved",
        )
        ctx.check(
            f"rq3_{field}_gold_audit_blank_template_status",
            blank_human_rows + final_rows == expected_rows and status_counts.get("draft", 0) == blank_human_rows,
            f"statuses={dict(sorted(status_counts.items()))}, blank_draft={blank_human_rows}, final={final_rows}",
        )
        ctx.check(
            f"rq3_{field}_gold_audit_no_llm_authoritative_label",
            llm_authoritative_rows == 0,
            f"{llm_authoritative_rows} rows contain top-level llm_annotation",
        )

        present_metrics = [path for path in spec["metrics_paths"] if resolve(path).exists()]
        if final_rows == 0 and present_metrics:
            metric_outputs_present_without_final_rows.extend(present_metrics)
        for metrics_path in present_metrics:
            if not metrics_path.endswith(".json"):
                continue
            metrics = read_json(metrics_path)
            gold_guard_ok = (
                metrics.get("gold_label_is_human") is True
                and metrics.get("label_source") == "human_audit_final_rows"
                and metrics.get("final_row_count", 0) > 0
            )
            ctx.check(
                f"rq3_{field}_gold_audit_metrics_source_guard",
                gold_guard_ok,
                f"{metrics_path}: label_source={metrics.get('label_source')}, final_rows={metrics.get('final_row_count')}",
            )

        audit_summary["datasets"][field] = {
            "jsonl": file_record(spec["jsonl_path"]),
            "csv": file_record(spec["csv_path"]),
            "source_evidence": file_record(spec["evidence_path"]),
            "expected_rows": expected_rows,
            "audit_rows": len(audit_rows),
            "status_counts": dict(sorted(status_counts.items())),
            "blank_draft_rows": blank_human_rows,
            "final_rows": final_rows,
            "gold_metric_outputs_present": present_metrics,
        }

    ctx.check(
        "rq3_no_gold_audit_metrics_without_final_rows",
        not metric_outputs_present_without_final_rows,
        ", ".join(metric_outputs_present_without_final_rows) or "no premature gold-audit metric outputs",
    )
    manifest["rq3_human_audit"] = audit_summary

    if incomplete_fields:
        ctx.blocker(
            "RQ3 human audit outputs are absent or incomplete; RQ3 adjudication metrics remain silver/provisional and must not be reported as human-gold performance. "
            + "; ".join(incomplete_fields)
        )


def validate_citations(ctx: ValidationContext, manifest: dict) -> None:
    section_paths = list(resolve("paper/cose/sections").glob("[0-9][0-9]_*.md")) + [
        resolve("paper/cose/abstract.md")
    ]
    text = "\n".join(path.read_text(encoding="utf-8") for path in section_paths)
    used = markdown_citation_keys(text)
    bib_key_list = re.findall(
        r"@\w+\{([^,]+),", resolve("paper/cose/references.bib").read_text(encoding="utf-8")
    )
    md_key_list = re.findall(
        r"^- \[([^\]]+)\]", resolve("paper/cose/references.md").read_text(encoding="utf-8"), re.M
    )
    bib_keys = set(bib_key_list)
    md_keys = set(md_key_list)
    ctx.check("citation_keys_present_in_bib", not (used - bib_keys), str(sorted(used - bib_keys)))
    ctx.check("citation_keys_present_in_references_md", not (used - md_keys), str(sorted(used - md_keys)))
    ctx.check("bib_has_no_unused_keys", not (bib_keys - used), str(sorted(bib_keys - used)))
    ctx.check("references_md_has_no_unused_keys", not (md_keys - used), str(sorted(md_keys - used)))
    ctx.check(
        "bib_has_no_duplicate_keys",
        not duplicate_values(bib_key_list),
        str(duplicate_values(bib_key_list)),
    )
    ctx.check(
        "references_md_has_no_duplicate_keys",
        not duplicate_values(md_key_list),
        str(duplicate_values(md_key_list)),
    )
    ctx.check(
        "references_md_and_bib_key_sets_match",
        md_keys == bib_keys,
        f"md_only={sorted(md_keys - bib_keys)}, bib_only={sorted(bib_keys - md_keys)}",
    )
    manifest["citation_integrity"] = {
        "used_keys": sorted(used),
        "references_md_keys": sorted(md_keys),
        "bib_keys": sorted(bib_keys),
        "used_key_count": len(used),
        "references_md_key_count": len(md_key_list),
        "bib_key_count": len(bib_key_list),
    }


def validate_submission_limits(ctx: ValidationContext) -> None:
    highlights = [
        line.strip()[2:]
        for line in resolve("paper/cose/highlights.md").read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- ")
    ]
    too_long = [f"{index}:{len(value)}" for index, value in enumerate(highlights, 1) if len(value) > 85]
    ctx.check("highlights_count", 3 <= len(highlights) <= 5, f"{len(highlights)} highlights")
    ctx.check("highlights_85_char_limit", not too_long, ", ".join(too_long) or "all <=85")
    abstract_lines = []
    for line in resolve("paper/cose/abstract.md").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("Keywords:"):
            abstract_lines.append(stripped)
    word_count = len(" ".join(abstract_lines).split())
    ctx.check("abstract_250_word_limit", word_count <= 250, f"{word_count} words")


def validate_claim_boundaries(ctx: ValidationContext) -> None:
    paths = [
        *resolve("paper/cose/sections").glob("[0-9][0-9]_*.md"),
        resolve("paper/cose/abstract.md"),
        resolve("paper/cose/manuscript.md"),
        resolve("paper/cose/latex/main.tex"),
    ]
    risky = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for window in sentence_windows(text):
            if CLAIM_PATTERNS.search(window) and not any(guard in window.lower() for guard in CLAIM_GUARDS):
                risky.append(f"{rel(path)}: {window[:160]}")
    ctx.check("silver_claim_boundary_lint", not risky, "\n".join(risky[:10]) or "guarded")

    affected_risky = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for window in sentence_windows(text):
            lower = window.lower()
            if (
                "affected_versions" in lower
                and AFFECTED_RISKY_PATTERNS.search(window)
                and not any(guard in lower for guard in AFFECTED_GUARDS)
            ):
                affected_risky.append(f"{rel(path)}: {window[:180]}")
    ctx.check(
        "affected_versions_claim_boundary_lint",
        not affected_risky,
        "\n".join(affected_risky[:10]) or "guarded",
    )


def validate_generated_outputs(ctx: ValidationContext, manifest: dict) -> None:
    for spec in GENERATOR_SPECS:
        missing = [path for path in spec["inputs"] + spec["outputs"] if not resolve(path).exists()]
        ctx.check(f"{spec['name']}_paths_exist", not missing, ", ".join(missing) or "all present")
        manifest["generators"].append(
            {
                "name": spec["name"],
                "command": " ".join(spec["command"]),
                "generator": file_record(spec["generator"]),
                "inputs": [file_record(path) for path in spec["inputs"] if resolve(path).exists()],
                "outputs": [file_record(path) for path in spec["outputs"] if resolve(path).exists()],
            }
        )


def validate_submission_planning_boundaries(ctx: ValidationContext) -> None:
    missing_internal = [path for path in INTERNAL_PLANNING_FILES if not resolve(path).exists()]
    ctx.check(
        "internal_planning_files_exist",
        not missing_internal,
        ", ".join(missing_internal) or "all present",
    )

    unmarked = []
    for path in INTERNAL_PLANNING_FILES:
        resolved = resolve(path)
        if resolved.exists() and INTERNAL_ONLY_BANNER not in resolved.read_text(encoding="utf-8"):
            unmarked.append(path)
    ctx.check(
        "internal_planning_files_marked_internal_only",
        not unmarked,
        ", ".join(unmarked) or "all internal-only banners present",
    )

    generator_inputs = {
        spec["name"]: set(spec["inputs"])
        for spec in GENERATOR_SPECS
        if spec["name"] in {"cose_markdown", "cose_latex"}
    }
    leaked_inputs = []
    for generator_name, inputs in generator_inputs.items():
        for path in INTERNAL_PLANNING_FILES:
            if path in inputs:
                leaked_inputs.append(f"{generator_name}:{path}")
    ctx.check(
        "submission_facing_generators_exclude_internal_planning",
        not leaked_inputs,
        ", ".join(leaked_inputs) or "internal planning files excluded",
    )

    leaks = []
    for path in SUBMISSION_OUTPUT_FILES:
        resolved = resolve(path)
        if not resolved.exists():
            continue
        text = resolved.read_text(encoding="utf-8")
        for pattern in INTERNAL_LEAK_PATTERNS:
            if pattern in text:
                leaks.append(f"{path}:{pattern}")
    ctx.check(
        "submission_facing_outputs_exclude_internal_planning",
        not leaks,
        ", ".join(leaks) or "no internal planning markers in submission outputs",
    )


def validate_method_visual_artifacts(ctx: ValidationContext, manifest: dict) -> None:
    paths = [
        METHOD_FRAMEWORK_SVG_PATH,
        METHOD_FRAMEWORK_PNG_PATH,
        METHOD_FRAMEWORK_LATEX_PNG_PATH,
        METHOD_EXPLAINER_PATH,
        PDF_CONTACT_SHEET_PATH,
        PDF_CONTACT_SHEET_MANIFEST_PATH,
        *(path for path, _size in VISUAL_CHECK_SCREENSHOTS.values()),
    ]
    missing = [path for path in paths if not resolve(path).exists()]
    ctx.check("method_visual_artifact_paths_exist", not missing, ", ".join(missing) or "all present")
    if missing:
        return

    svg_path = resolve(METHOD_FRAMEWORK_SVG_PATH)
    try:
        root = ET.parse(svg_path).getroot()
        svg_ok = root.tag.endswith("svg")
    except ET.ParseError as error:
        root = None
        svg_ok = False
        svg_error = str(error)
    else:
        svg_error = "xml ok"
    ctx.check("method_framework_svg_xml_valid", svg_ok, svg_error)

    svg_text = svg_path.read_text(encoding="utf-8")
    missing_terms = [term for term in METHOD_FRAMEWORK_REQUIRED_TEXT if term not in svg_text]
    viewbox_ok = 'viewBox="0 0 1180 900"' in svg_text
    ctx.check(
        "method_framework_routing_contract_present",
        not missing_terms and viewbox_ok,
        (
            f"missing={missing_terms or []}, "
            f"viewBox_1180x900={viewbox_ok}"
        ),
    )

    png_checks = []
    for path_value in (METHOD_FRAMEWORK_PNG_PATH, METHOD_FRAMEWORK_LATEX_PNG_PATH):
        size = png_size(resolve(path_value))
        png_checks.append((path_value, size))
    ctx.check(
        "method_framework_png_dimensions",
        all(size == (1180, 900) for _path, size in png_checks),
        ", ".join(f"{path}={size}" for path, size in png_checks),
    )

    html_path = resolve(METHOD_EXPLAINER_PATH)
    html_text = html_path.read_text(encoding="utf-8")
    parser = IdCollector()
    try:
        parser.feed(html_text)
        html_parse_ok = True
        html_error = "html parse ok"
    except Exception as error:  # HTMLParser can raise on malformed entity callbacks.
        html_parse_ok = False
        html_error = str(error)
    ctx.check("method_explainer_html_parse", html_parse_ok, html_error)

    missing_ids = [id_value for id_value in METHOD_EXPLAINER_REQUIRED_IDS if id_value not in parser.ids]
    missing_text = [term for term in METHOD_EXPLAINER_REQUIRED_TEXT if term not in html_text]
    ctx.check(
        "method_explainer_sections_present",
        not missing_ids and not missing_text,
        f"missing_ids={missing_ids or []}, missing_text={missing_text or []}",
    )
    ctx.check(
        "method_explainer_links_method_artifacts",
        "figures/method_framework.svg" in html_text and "sections/03_method.md" in html_text,
        "links to method SVG and method section",
    )

    manifest["method_visual_artifacts"] = {
        "framework_svg": file_record(METHOD_FRAMEWORK_SVG_PATH),
        "framework_png": file_record(METHOD_FRAMEWORK_PNG_PATH),
        "framework_latex_png": file_record(METHOD_FRAMEWORK_LATEX_PNG_PATH),
        "explainer_html": file_record(METHOD_EXPLAINER_PATH),
        "required_svg_terms": list(METHOD_FRAMEWORK_REQUIRED_TEXT),
        "required_html_ids": list(METHOD_EXPLAINER_REQUIRED_IDS),
    }

    screenshot_checks = []
    freshness_checks = []
    screenshot_records = {}
    for name, (path_value, expected_size) in VISUAL_CHECK_SCREENSHOTS.items():
        size = png_size(resolve(path_value))
        source_path = METHOD_FRAMEWORK_SVG_PATH if name == "method_framework_svg" else METHOD_EXPLAINER_PATH
        is_fresh = mtime_ns(path_value) >= mtime_ns(source_path)
        screenshot_checks.append((name, size, expected_size))
        freshness_checks.append((name, is_fresh, path_value, source_path))
        screenshot_records[name] = {
            "file": file_record(path_value),
            "expected_size": list(expected_size),
            "observed_size": list(size) if size else None,
            "source_path": source_path,
            "fresh_against_source": is_fresh,
        }
    ctx.check(
        "method_visual_screenshot_dimensions",
        all(size == expected for _name, size, expected in screenshot_checks),
        ", ".join(f"{name}={size} expected={expected}" for name, size, expected in screenshot_checks),
    )
    stale_screenshots = [
        f"{name}:{path_value} older than {source_path}"
        for name, is_fresh, path_value, source_path in freshness_checks
        if not is_fresh
    ]
    ctx.check(
        "method_visual_screenshots_fresh",
        not stale_screenshots,
        "; ".join(stale_screenshots) or "screenshots are newer than source HTML/SVG",
    )
    pdf_path = resolve("paper/cose/latex/main.pdf")
    contact_sheet_path = resolve(PDF_CONTACT_SHEET_PATH)
    contact_sheet_manifest = read_json(PDF_CONTACT_SHEET_MANIFEST_PATH)
    pdfinfo_result = run_command(["pdfinfo", str(pdf_path)])
    page_match = re.search(r"^Pages:\s+(\d+)\s*$", pdfinfo_result.stdout, flags=re.MULTILINE)
    observed_page_count = int(page_match.group(1)) if page_match else None
    source_record = contact_sheet_manifest.get("source_pdf", {})
    output_record = contact_sheet_manifest.get("contact_sheet", {})
    rendered_pages = contact_sheet_manifest.get("rendered_pages")
    expected_pages = (
        list(range(1, observed_page_count + 1)) if observed_page_count is not None else None
    )
    observed_dimensions = png_size(contact_sheet_path)
    consistency = pdf_contact_sheet_consistency(
        contact_sheet_manifest,
        pdf_sha256=sha256(pdf_path),
        pdf_size_bytes=pdf_path.stat().st_size,
        pdf_page_count=observed_page_count,
        contact_sheet_sha256=sha256(contact_sheet_path),
        contact_sheet_size_bytes=contact_sheet_path.stat().st_size,
        contact_sheet_dimensions=observed_dimensions,
    )
    contact_sheet_fresh = mtime_ns(PDF_CONTACT_SHEET_PATH) >= mtime_ns(pdf_path)
    ctx.check(
        "pdf_contact_sheet_fresh",
        contact_sheet_fresh,
        f"{PDF_CONTACT_SHEET_PATH} mtime >= paper/cose/latex/main.pdf mtime",
    )
    ctx.check(
        "pdf_contact_sheet_source_identity",
        pdfinfo_result.returncode == 0 and consistency["source_identity"],
        (
            f"pdfinfo_pages={observed_page_count}, "
            f"manifest_pages={source_record.get('page_count')}, "
            f"sha_matches={source_record.get('sha256') == sha256(pdf_path)}"
        ),
    )
    ctx.check(
        "pdf_contact_sheet_complete_page_coverage",
        consistency["complete_page_coverage"],
        (
            f"pdf_pages={observed_page_count}, "
            f"rendered_page_count={contact_sheet_manifest.get('rendered_page_count')}, "
            f"sequence_exact={rendered_pages == expected_pages}"
        ),
    )
    ctx.check(
        "pdf_contact_sheet_output_identity",
        consistency["output_identity"],
        (
            f"dimensions={observed_dimensions}, "
            f"manifest_dimensions={output_record.get('dimensions')}, "
            f"sha_matches={output_record.get('sha256') == sha256(contact_sheet_path)}"
        ),
    )
    manifest["method_visual_artifacts"]["visual_check_screenshots"] = screenshot_records
    manifest["method_visual_artifacts"]["pdf_contact_sheet"] = {
        "file": file_record(PDF_CONTACT_SHEET_PATH),
        "manifest": file_record(PDF_CONTACT_SHEET_MANIFEST_PATH),
        "source_pdf_sha256": source_record.get("sha256"),
        "page_count": source_record.get("page_count"),
        "rendered_page_count": contact_sheet_manifest.get("rendered_page_count"),
    }


def build_pdf_contact_sheet(ctx: ValidationContext) -> None:
    pdf_path = resolve("paper/cose/latex/main.pdf")
    if not pdf_path.exists():
        ctx.check("pdf_contact_sheet_build", False, f"missing source PDF: {pdf_path}")
        return
    result = run_command(
        [
            PYTHON_EXECUTABLE,
            "experiments/paper_artifacts/build_pdf_contact_sheet.py",
        ]
    )
    ctx.check("pdf_contact_sheet_build", result.returncode == 0, tail(result.stdout))


def validate_rerender_byte_identical(ctx: ValidationContext) -> None:
    with tempfile.TemporaryDirectory(prefix="cose-package-") as tmp_raw:
        tmp = Path(tmp_raw)
        for spec in GENERATOR_SPECS:
            temp_args = spec.get("temp_args")
            temp_outputs = spec.get("temp_outputs")
            if not temp_args or not temp_outputs:
                continue
            result = run_command([*spec["command"], *temp_args(tmp)])
            if result.returncode != 0:
                ctx.check(f"{spec['name']}_rerender_command", False, tail(result.stdout))
                continue
            generated = temp_outputs(tmp)
            missing = [str(path) for path in generated if not path.exists()]
            if missing:
                ctx.check(f"{spec['name']}_rerender_outputs_exist", False, ", ".join(missing))
                continue
            mismatches = []
            for actual_path, temp_path in zip(spec["outputs"], generated):
                actual = resolve(actual_path)
                if actual.suffix.lower() == ".png":
                    continue
                if sha256(actual) != sha256(temp_path):
                    mismatches.append(f"{actual_path} != {temp_path}")
            ctx.check(
                f"{spec['name']}_rerender_byte_identical",
                not mismatches,
                "; ".join(mismatches) or "byte-identical",
            )


def validate_latex(ctx: ValidationContext, *, skip_build: bool) -> None:
    main_tex = resolve("paper/cose/latex/main.tex")
    text = main_tex.read_text(encoding="utf-8")
    inputs = re.findall(r"\\input\{([^}]+)\}", text)
    graphics = re.findall(r"\\includegraphics(?:\[[^\]]+\])?\{([^}]+)\}", text)
    missing_inputs = [path for path in inputs if not (main_tex.parent / path).exists()]
    missing_graphics = [path for path in graphics if not (main_tex.parent / path).exists()]
    ctx.check("latex_input_files_exist", not missing_inputs, ", ".join(missing_inputs) or "all present")
    ctx.check("latex_graphics_exist", not missing_graphics, ", ".join(missing_graphics) or "all present")
    same_bib = sha256(resolve("paper/cose/references.bib")) == sha256(resolve("paper/cose/latex/references.bib"))
    ctx.check("latex_bib_matches_root_bib", same_bib, "root references.bib vs latex/references.bib")

    if not skip_build:
        result = run_command(
            ["latexmk", "-pdf", "-interaction=nonstopmode", "-halt-on-error", "main.tex"],
            cwd=main_tex.parent,
        )
        ctx.check("latexmk_pdf_build", result.returncode == 0, tail(result.stdout))
    log = resolve("paper/cose/latex/main.log")
    if log.exists():
        log_text = log.read_text(encoding="utf-8", errors="replace")
        bad_patterns = [
            "undefined citations",
            "multiply defined",
            "Empty `thebibliography'",
            "LaTeX Warning: Citation",
            "Package natbib Warning: Citation",
            "Fatal error",
            "Emergency stop",
        ]
        hits = {pattern: log_text.count(pattern) for pattern in bad_patterns}
        ctx.check("latex_log_no_citation_or_fatal_errors", not any(hits.values()), json.dumps(hits))
    ctx.check("latex_pdf_exists", resolve("paper/cose/latex/main.pdf").exists(), "paper/cose/latex/main.pdf")


def validate_error_accounting(ctx: ValidationContext) -> None:
    predictions = [row for _line, row in iter_jsonl("results/rq3_adjudication/severity_silver_v2_predictions.jsonl")]
    evidence_rows = [row for row in predictions if row.get("method") == "evidence_score_baseline"]
    expected_errors = sum(1 for row in evidence_rows if not row.get("is_correct"))
    artifact = read_json("results/paper_cose/cose_artifact_tables.json")
    observed_errors = artifact.get("rq3_prediction_summary", {}).get("evidence_score_baseline", {}).get("error_count")
    ctx.check(
        "rq3_error_count_matches_predictions",
        observed_errors == expected_errors,
        f"observed={observed_errors}, expected={expected_errors}",
    )
    md = resolve("results/paper_cose/cose_artifact_tables.md").read_text(encoding="utf-8")
    if "Confusion pairs are" in md:
        has_correct_pairs = any(f"{label}->{label}" in md for label in ("both", "nvd", "ghsa", "abstain", "neither"))
        heading_ok = "Confusion pairs are" in md and "Error count" in md
        ctx.check(
            "rq3_confusion_heading_not_error_only",
            heading_ok or not has_correct_pairs,
            "confusion table includes all prediction pairs and is labeled as confusion pairs",
        )

    error_modes = read_json("results/rq3_adjudication/rq3_silver_error_modes.json")
    artifact_error_modes = artifact.get("rq3_silver_error_modes", {})
    severity_error_modes = error_modes.get("fields", {}).get("severity", {})
    artifact_severity_error_modes = artifact_error_modes.get("fields", {}).get("severity", {})
    ctx.check(
        "rq3_error_mode_artifact_is_silver_only",
        error_modes.get("silver_label_is_gold") is False,
        f"silver_label_is_gold={error_modes.get('silver_label_is_gold')}",
    )
    ctx.check(
        "rq3_error_mode_severity_count_matches_predictions",
        severity_error_modes.get("error_count") == expected_errors,
        f"observed={severity_error_modes.get('error_count')}, expected={expected_errors}",
    )
    ctx.check(
        "rq3_error_mode_wired_into_cose_tables",
        artifact_severity_error_modes.get("error_count") == severity_error_modes.get("error_count"),
        (
            f"artifact={artifact_severity_error_modes.get('error_count')}, "
            f"source={severity_error_modes.get('error_count')}"
        ),
    )

    affected_metrics = read_json("results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json")
    metric_notes = " ".join(affected_metrics.get("notes", [])).lower()
    methods = set(affected_metrics.get("methods", {}))
    ctx.check(
        "affected_versions_metrics_are_silver_only",
        affected_metrics.get("silver_label_is_gold") is False and affected_metrics.get("sample_count") == 100,
        (
            f"silver_label_is_gold={affected_metrics.get('silver_label_is_gold')}, "
            f"sample_count={affected_metrics.get('sample_count')}"
        ),
    )
    ctx.check(
        "affected_versions_metrics_guard_semantics",
        "not human gold" in metric_notes and "not a semantic version-range adjudicator" in metric_notes,
        metric_notes[:240],
    )
    ctx.check(
        "affected_versions_token_support_method_present",
        "version_token_support_baseline" in methods,
        ", ".join(sorted(methods)),
    )

    affected_error_modes = error_modes.get("fields", {}).get("affected_versions", {})
    ctx.check(
        "rq3_error_mode_affected_versions_profiles_present",
        bool(affected_error_modes.get("package_overlap_error_counts"))
        and bool(affected_error_modes.get("version_shape_error_counts")),
        "package/version profile counts present",
    )

    affected_alignment = read_json(
        "results/rq3_adjudication/affected_versions_alignment_diagnostics.json"
    )
    artifact_alignment = artifact.get("affected_versions_alignment_diagnostic", {})
    combined_counts = affected_alignment.get("diagnostic_counts", {}).get(
        "combined_category", {}
    )
    artifact_combined_counts = artifact_alignment.get("diagnostic_counts", {}).get(
        "combined_category", {}
    )
    ctx.check(
        "affected_versions_alignment_is_diagnostic_only",
        affected_alignment.get("silver_label_is_gold") is False
        and affected_alignment.get("sample_count") == 100
        and any(
            "not a semantic version-range adjudicator" in note
            for note in affected_alignment.get("cautions", [])
        ),
        (
            f"silver_label_is_gold={affected_alignment.get('silver_label_is_gold')}, "
            f"sample_count={affected_alignment.get('sample_count')}"
        ),
    )
    ctx.check(
        "affected_versions_alignment_wired_into_cose_tables",
        artifact_combined_counts == combined_counts and bool(combined_counts),
        f"artifact={artifact_combined_counts}, source={combined_counts}",
    )

    sensitivity = read_json(
        "results/rq3_adjudication/rq3_silver_baseline_sensitivity.json"
    )
    artifact_sensitivity = artifact.get("rq3_silver_baseline_sensitivity", {})
    sensitivity_fields = sensitivity.get("fields", {})
    artifact_sensitivity_fields = artifact_sensitivity.get("fields", {})
    ctx.check(
        "rq3_sensitivity_is_silver_only",
        sensitivity.get("silver_label_is_gold") is False
        and sensitivity.get("metric_scope")
        == "silver_label_threshold_diagnostic_only"
        and set(sensitivity_fields) == {"severity", "affected_versions"},
        (
            f"silver_label_is_gold={sensitivity.get('silver_label_is_gold')}, "
            f"metric_scope={sensitivity.get('metric_scope')}, "
            f"fields={sorted(sensitivity_fields)}"
        ),
    )
    ctx.check(
        "rq3_sensitivity_expected_thresholds",
        sensitivity_fields.get("severity", {}).get("baseline_threshold") == 3
        and sensitivity_fields.get("affected_versions", {}).get("baseline_threshold")
        == 1
        and len(
            sensitivity_fields.get("severity", {}).get("metrics_by_threshold", {})
        )
        == 6
        and len(
            sensitivity_fields.get("affected_versions", {}).get(
                "metrics_by_threshold", {}
            )
        )
        == 3,
        (
            f"severity={sensitivity_fields.get('severity', {}).get('metrics_by_threshold', {}).keys()}, "
            f"affected={sensitivity_fields.get('affected_versions', {}).get('metrics_by_threshold', {}).keys()}"
        ),
    )
    ctx.check(
        "rq3_sensitivity_wired_into_cose_tables",
        artifact_sensitivity_fields.get("severity", {}).get("baseline_threshold")
        == sensitivity_fields.get("severity", {}).get("baseline_threshold")
        and artifact_sensitivity_fields.get("affected_versions", {}).get(
            "baseline_threshold"
        )
        == sensitivity_fields.get("affected_versions", {}).get(
            "baseline_threshold"
        ),
        (
            f"artifact_fields={sorted(artifact_sensitivity_fields)}, "
            f"source_fields={sorted(sensitivity_fields)}"
        ),
    )

    reliability = read_json(
        "results/rq3_adjudication/evidence_source_reliability.json"
    )
    artifact_reliability = artifact.get("evidence_source_reliability", {})
    reliability_fields = reliability.get("fields", {})
    artifact_reliability_fields = artifact_reliability.get("fields", {})
    severity_reliability = reliability_fields.get("severity", {})
    affected_reliability = reliability_fields.get("affected_versions", {})
    ctx.check(
        "evidence_reliability_is_diagnostic_only",
        reliability.get("silver_label_is_gold") is False
        and reliability.get("metric_scope")
        == "evidence_availability_and_provenance_diagnostic_only"
        and set(reliability_fields) == {"severity", "affected_versions"},
        (
            f"silver_label_is_gold={reliability.get('silver_label_is_gold')}, "
            f"metric_scope={reliability.get('metric_scope')}, "
            f"fields={sorted(reliability_fields)}"
        ),
    )
    ctx.check(
        "evidence_reliability_sample_and_record_counts",
        severity_reliability.get("sample_count") == 80
        and affected_reliability.get("sample_count") == 100
        and severity_reliability.get("record_summary", {}).get("record_count")
        == 470
        and affected_reliability.get("record_summary", {}).get("record_count")
        == 585,
        (
            f"severity={severity_reliability.get('sample_count')}/"
            f"{severity_reliability.get('record_summary', {}).get('record_count')}, "
            f"affected={affected_reliability.get('sample_count')}/"
            f"{affected_reliability.get('record_summary', {}).get('record_count')}"
        ),
    )
    ctx.check(
        "evidence_reliability_source_classes_present",
        bool(
            severity_reliability.get("record_summary", {})
            .get("by_source_class", {})
            .get("nvd", {})
            .get("records")
        )
        and bool(
            affected_reliability.get("record_summary", {})
            .get("by_source_class", {})
            .get("github_commit_or_repo", {})
            .get("records")
        ),
        "nvd and github source-class counts present",
    )
    ctx.check(
        "evidence_reliability_wired_into_cose_tables",
        artifact_reliability_fields.get("severity", {}).get("record_summary", {}).get(
            "ok_text_records"
        )
        == severity_reliability.get("record_summary", {}).get("ok_text_records")
        and artifact_reliability_fields.get("affected_versions", {})
        .get("record_summary", {})
        .get("ok_text_records")
        == affected_reliability.get("record_summary", {}).get("ok_text_records"),
        (
            f"artifact_fields={sorted(artifact_reliability_fields)}, "
            f"source_fields={sorted(reliability_fields)}"
        ),
    )


def validate_rq3_human_audit_readiness(ctx: ValidationContext) -> None:
    readiness_path = "results/rq3_adjudication/rq3_human_audit_readiness.json"
    artifact_path = "results/paper_cose/cose_artifact_tables.json"
    readiness = read_json(readiness_path)
    artifact = read_json(artifact_path)
    artifact_readiness = artifact.get("rq3_human_audit_readiness", {})
    fields = readiness.get("fields", {})
    severity = fields.get("severity", {})
    affected = fields.get("affected_versions", {})

    ctx.check(
        "rq3_human_audit_readiness_is_readiness_only",
        readiness.get("gold_label_evaluation") is False
        and readiness.get("metric_scope") == "human_audit_template_readiness_only"
        and readiness.get("ready_for_gold_evaluation") is False,
        (
            f"gold_label_evaluation={readiness.get('gold_label_evaluation')}, "
            f"metric_scope={readiness.get('metric_scope')}, "
            f"ready={readiness.get('ready_for_gold_evaluation')}"
        ),
    )
    ctx.check(
        "rq3_human_audit_readiness_shape",
        severity.get("audit_row_count") == 80
        and affected.get("audit_row_count") == 100
        and severity.get("final_row_count") == 0
        and affected.get("final_row_count") == 0
        and severity.get("draft_row_count") == 80
        and affected.get("draft_row_count") == 100,
        (
            f"severity={severity.get('audit_row_count')}/"
            f"{severity.get('final_row_count')}/"
            f"{severity.get('draft_row_count')}, "
            f"affected={affected.get('audit_row_count')}/"
            f"{affected.get('final_row_count')}/"
            f"{affected.get('draft_row_count')}"
        ),
    )
    ctx.check(
        "rq3_human_audit_readiness_evidence_and_worklist",
        severity.get("samples_with_ok_evidence") == 80
        and affected.get("samples_with_ok_evidence") == 100
        and severity.get("priority_reason_counts", {}).get("human_label_blank") == 80
        and affected.get("priority_reason_counts", {}).get("human_label_blank") == 100
        and bool(severity.get("priority_worklist_top"))
        and bool(affected.get("priority_worklist_top")),
        "evidence/worklist counts present",
    )
    artifact_fields = artifact_readiness.get("fields", {})
    ctx.check(
        "rq3_human_audit_readiness_wired_into_cose_tables",
        artifact_readiness.get("metric_scope")
        == readiness.get("metric_scope")
        and artifact_fields.get("severity", {}).get("audit_row_count")
        == severity.get("audit_row_count")
        and artifact_fields.get("affected_versions", {}).get("audit_row_count")
        == affected.get("audit_row_count"),
        (
            f"artifact_fields={sorted(artifact_fields)}, "
            f"source_fields={sorted(fields)}"
        ),
    )


def validate_blocking_placeholders(ctx: ValidationContext) -> None:
    paths = [
        "paper/cose/title_page.md",
        "paper/cose/declarations.md",
        "paper/cose/latex/sections/declarations.tex",
        "paper/cose/latex/main.tex",
    ]
    pattern = re.compile(r"\bTODO\b|placeholder|Final submission should include|Authors:", re.IGNORECASE)
    hits = []
    for path in paths:
        for line_number, line in enumerate(resolve(path).read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                hits.append(f"{path}:{line_number}")
    if hits:
        ctx.blocker("Submission metadata/declaration placeholders remain: " + ", ".join(hits[:12]))


def validate_latex_build_artifacts(ctx: ValidationContext) -> None:
    disposable = [
        "paper/cose/latex/main.aux",
        "paper/cose/latex/main.bbl",
        "paper/cose/latex/main.blg",
        "paper/cose/latex/main.fdb_latexmk",
        "paper/cose/latex/main.fls",
        "paper/cose/latex/main.log",
        "paper/cose/latex/main.spl",
    ]
    existing = [path for path in disposable if resolve(path).exists()]
    ctx.check(
        "latex_disposable_build_outputs_present_but_ignored",
        True,
        f"{len(existing)} disposable build outputs present; .gitignore excludes them",
    )


def tail(text: str, lines: int = 30) -> str:
    return "\n".join(text.splitlines()[-lines:])


def main() -> int:
    args = parse_args()
    ctx = ValidationContext()
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_root": str(PROJECT_ROOT),
        "status": "unknown",
        "generators": [],
        "checks": ctx.checks,
        "submission_blockers": ctx.blockers,
    }

    validate_rq1(ctx)
    validate_rq2_blank_labels(ctx)
    validate_rq2_sample_coverage(ctx)
    validate_rq2_full_impact_human_review(ctx, manifest)
    validate_rq2_typing_human_review(ctx, manifest)
    validate_rq2_post_profile_unresolved_evidence(ctx, manifest)
    validate_rq2_post_profile_paired_test_identifiability(ctx, manifest)
    validate_rq2_post_profile_eligible_universe_census(ctx, manifest)
    validate_rq2_post_profile_acquisition_delta(ctx, manifest)
    validate_rq2_post_profile_complete_difference_reviews(ctx, manifest)
    validate_rq3_gold_audit_templates(ctx, manifest)
    validate_citations(ctx, manifest)
    validate_submission_limits(ctx)
    validate_claim_boundaries(ctx)
    validate_generated_outputs(ctx, manifest)
    validate_submission_planning_boundaries(ctx)
    validate_rerender_byte_identical(ctx)
    validate_latex(ctx, skip_build=args.skip_latex_build)
    build_pdf_contact_sheet(ctx)
    validate_method_visual_artifacts(ctx, manifest)
    validate_error_accounting(ctx)
    validate_rq3_human_audit_readiness(ctx)
    validate_blocking_placeholders(ctx)
    validate_latex_build_artifacts(ctx)

    manifest["checks"] = ctx.checks
    manifest["submission_blockers"] = ctx.blockers
    manifest["status"] = "pass" if not ctx.failed else "fail"
    manifest["submission_ready"] = manifest["status"] == "pass" and not ctx.blockers

    output_path = resolve(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    print(f"status={manifest['status']} submission_ready={manifest['submission_ready']}")
    if ctx.failed:
        print("Failed checks:")
        for check in ctx.failed:
            print(f"- {check['name']}: {check['details']}")
        return 1
    if ctx.blockers:
        print("Submission blockers:")
        for blocker in ctx.blockers:
            print(f"- {blocker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
