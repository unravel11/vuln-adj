#!/usr/bin/env python3
"""Fail-closed validator for the no-human JSS zero-draft package."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import tempfile
from pathlib import Path


EXPECTED_ANALYSIS_SHA256 = "47428580744f0d83331c15b82a623a771f40a40d1ddcf59731fd83787553f7a8"
FORBIDDEN_MANIFEST_PARTS = (
    "t1_human_validation",
    "reviewer_",
    "calibration",
    "formal",
    "reason_return",
    "action_return",
    "private",
)
TABLE_FILES = (
    "rq1_status_counts.csv",
    "rq2_strategy_actions.csv",
    "rq2_pairwise_disagreements.csv",
    "table_rq1_status_counts.tex",
    "table_rq2_strategy_actions.tex",
    "table_rq2_pairwise_disagreements.tex",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_builder(repo_root: Path):
    path = repo_root / "experiments/paper_artifacts/build_jss_deterministic_tables.py"
    spec = importlib.util.spec_from_file_location("build_jss_deterministic_tables", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def validate(repo_root: Path) -> list[str]:
    checks: list[str] = []
    analysis_path = repo_root / "results/jss/t1_routing_precheck_v1/analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    if sha256(analysis_path) != EXPECTED_ANALYSIS_SHA256:
        raise ValueError("deterministic analysis hash changed")
    safe_flags = {
        "uses_any_labels": False,
        "label_is_human": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_submission_readiness_claim": False,
        "eligible_for_workload_reduction_claim": False,
    }
    for key, expected in safe_flags.items():
        if analysis.get(key) is not expected:
            raise ValueError(f"unsafe analysis flag {key}={analysis.get(key)!r}")
    checks.append("deterministic analysis is hash-bound and label-free")

    state = json.loads((repo_root / "paper/jss/paper_state.json").read_text(encoding="utf-8"))
    if state.get("stage") != "S2_ARGUMENT_LOCKED":
        raise ValueError("paper stage advanced without human evidence")
    for gate in ("draft_present", "artifact_verified", "submission_blockers_resolved"):
        if state["gates"].get(gate) is not False:
            raise ValueError(f"paper gate {gate} must remain false")
    checks.append("paper remains at S2 and submission gates remain closed")

    main_tex = (repo_root / "paper/jss/latex/main.tex").read_text(encoding="utf-8")
    required_spans = (
        "[Result-neutral placeholder.]",
        "[REAL-HUMAN RESULTS PLACEHOLDER.]",
        "[CONCLUSION PLACEHOLDER.]",
        "[AUTHOR TO COMPLETE.]",
        r"\input{table_rq1_status_counts.tex}",
        r"\input{table_rq2_strategy_actions.tex}",
        r"\input{table_rq2_pairwise_disagreements.tex}",
    )
    for span in required_spans:
        if span not in main_tex:
            raise ValueError(f"missing required source span: {span}")
    if re.search(r"RQ3.{0,80}(outperform|superior|improv)", main_tex, re.IGNORECASE | re.DOTALL):
        raise ValueError("RQ3 placeholder contains a prewritten positive claim")
    checks.append("abstract, RQ3, conclusion, and declarations retain explicit placeholders")

    bib_text = (repo_root / "paper/jss/latex/references.bib").read_text(encoding="utf-8")
    bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib_text))
    cited: set[str] = set()
    for group in re.findall(r"\\cite[tp]?\{([^}]+)\}", main_tex):
        cited.update(key.strip() for key in group.split(","))
    missing = sorted(cited - bib_keys)
    unused = sorted(bib_keys - cited)
    if missing:
        raise ValueError(f"citation keys missing from BibTeX: {missing}")
    if unused:
        raise ValueError(f"uncited BibTeX entries: {unused}")
    checks.append(f"citation/BibTeX closure holds for {len(cited)} keys")

    builder = _load_builder(repo_root)
    with tempfile.TemporaryDirectory(prefix="jss-table-validate-") as tmp:
        tmp_path = Path(tmp)
        builder.build(analysis_path, tmp_path)
        for name in TABLE_FILES:
            committed = repo_root / "paper/jss/latex" / name
            regenerated = tmp_path / name
            if committed.read_bytes() != regenerated.read_bytes():
                raise ValueError(f"generated table drift: {name}")
    checks.append("six CSV/LaTeX table artifacts reproduce byte-for-byte")

    manifest_path = repo_root / "paper/jss/ARTIFACT_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    boundary = manifest["claim_boundary"]
    expected_boundary = {
        "contains_human_results": False,
        "human_labels": 0,
        "uses_ai_as_human_gold": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_workload_reduction_claim": False,
        "submission_ready": False,
    }
    if boundary != expected_boundary:
        raise ValueError(f"unexpected artifact claim boundary: {boundary}")
    seen: set[str] = set()
    for entry in manifest["files"]:
        relative = entry["path"]
        lower = relative.lower()
        if any(part in lower for part in FORBIDDEN_MANIFEST_PARTS):
            raise ValueError(f"human/private path present in manifest: {relative}")
        if relative in seen:
            raise ValueError(f"duplicate manifest path: {relative}")
        seen.add(relative)
        path = repo_root / relative
        if path.stat().st_size != entry["bytes"] or sha256(path) != entry["sha256"]:
            raise ValueError(f"manifest mismatch: {relative}")
    checks.append(f"artifact manifest binds {len(seen)} allowlisted files and excludes human/private paths")

    latex_dir = repo_root / "paper/jss/latex"
    committed_build_products = [p.name for p in latex_dir.iterdir() if p.suffix in {".pdf", ".aux", ".bbl", ".blg", ".log", ".fdb_latexmk", ".fls"}]
    if committed_build_products:
        raise ValueError(f"build products must remain uncommitted: {committed_build_products}")
    checks.append("no generated PDF or TeX build products are committed")

    return checks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    checks = validate(args.repo_root.resolve())
    print(f"PASS: {len(checks)} no-human package checks")
    for check in checks:
        print(f"- {check}")


if __name__ == "__main__":
    main()
