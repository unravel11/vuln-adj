#!/usr/bin/env python3
"""Run the label-free V3.1 safety-identifiability audit.

This script never reads reviewer returns.  It characterizes only the frozen
sample, policy actions, and the event counts needed to interpret a future
manual-route safety analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from analyze_t1_routing_precheck import (
    FIELDS,
    MAIN_FIRST,
    MAIN_SECOND,
    MANUAL_REVIEW_ACTIONS,
    policy_actions,
)
from build_t1_human_validation_packet_v3 import evaluation_cell


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIELD_VIEW = (
    "data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl"
)
DEFAULT_SAMPLING_FRAME = (
    "data/annotations/rq2/t1_human_validation_v3/internal/"
    "frozen_sampling_frame.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/jss/t1_v31_safety_identifiability"
EXPECTED_FIELD_VIEW_SHA256 = (
    "c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2"
)
EFFICACY_FIELDS = ("severity", "affected_versions")
ALPHA = 0.05
CANDIDATE_MARGINS = (0.05, 0.10, 0.15)
SELECTED_MARGIN = 0.10
REPORTING_FLOOR = 25
POSITIVE_FRAMING_FLOOR = 29


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--field-view", default=DEFAULT_FIELD_VIEW)
    parser.add_argument("--sampling-frame", default=DEFAULT_SAMPLING_FRAME)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_values(values: Iterable[str]) -> str:
    payload = "\n".join(sorted(values)) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc
    return rows


def binomial_cdf(x: int, n: int, p: float) -> float:
    return sum(
        math.comb(n, k) * (p**k) * ((1.0 - p) ** (n - k))
        for k in range(x + 1)
    )


def one_sided_cp_upper(events: int, total: int, alpha: float = ALPHA) -> float:
    """One-sided Clopper-Pearson upper bound for a binomial event rate."""
    if total <= 0 or not 0 <= events <= total:
        raise ValueError("events and total must satisfy 0 <= events <= total")
    if events == total:
        return 1.0
    low = events / total
    high = 1.0
    for _ in range(100):
        midpoint = (low + high) / 2.0
        if binomial_cdf(events, total, midpoint) > alpha:
            low = midpoint
        else:
            high = midpoint
    return high


def minimum_zero_event_n(margin: float, alpha: float = ALPHA) -> int:
    for total in range(1, 10000):
        if one_sided_cp_upper(0, total, alpha) < margin:
            return total
    raise RuntimeError("minimum n search exceeded bound")


def kish_effective_sample_size(weights: list[float]) -> float:
    if not weights:
        return 0.0
    return sum(weights) ** 2 / sum(weight * weight for weight in weights)


def git_value(*args: str) -> str | None:
    try:
        return subprocess.check_output(
            ("git", *args),
            cwd=PROJECT_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def project_population_cells(
    source_rows: list[dict[str, Any]],
) -> dict[str, Counter[str]]:
    cells: dict[str, Counter[str]] = defaultdict(Counter)
    for source_row in source_rows:
        unified = source_row.get("unified_view") or {}
        discrepancies = source_row.get("field_discrepancies") or {}
        policy_view = dict(unified)
        policy_view["field_discrepancies"] = discrepancies
        for field in EFFICACY_FIELDS:
            discrepancy = discrepancies[field]
            actions = policy_actions(policy_view, field)
            if (
                actions[MAIN_FIRST] not in MANUAL_REVIEW_ACTIONS
                and actions[MAIN_SECOND] not in MANUAL_REVIEW_ACTIONS
            ):
                pair = f"{actions[MAIN_FIRST]}->{actions[MAIN_SECOND]}"
                cell = evaluation_cell(field, discrepancy["status"], pair)
                cells[field][cell] += 1
    return cells


def analyze(field_view_path: Path, sampling_frame_path: Path) -> dict[str, Any]:
    if sha256_file(field_view_path) != EXPECTED_FIELD_VIEW_SHA256:
        raise ValueError("frozen field-view hash mismatch")
    source_rows = load_jsonl(field_view_path)
    frame_rows = load_jsonl(sampling_frame_path)
    evaluation = [row for row in frame_rows if row.get("phase") == "evaluation"]
    if len(evaluation) != 120:
        raise ValueError(f"expected 120 formal rows, observed {len(evaluation)}")
    if len({row["cve_id"] for row in evaluation}) != len(evaluation):
        raise ValueError("formal rows are not CVE-unique")

    audit_rows = [
        row
        for row in evaluation
        if row["field"] in EFFICACY_FIELDS
        and row["policy_actions"][MAIN_FIRST] not in MANUAL_REVIEW_ACTIONS
        and row["policy_actions"][MAIN_SECOND] not in MANUAL_REVIEW_ACTIONS
    ]
    by_field: dict[str, list[dict[str, Any]]] = {
        field: [row for row in audit_rows if row["field"] == field]
        for field in EFFICACY_FIELDS
    }
    if {field: len(rows) for field, rows in by_field.items()} != {
        "severity": 15,
        "affected_versions": 19,
    }:
        raise ValueError("frozen shared-no-manual audit count drift")

    population_cells = project_population_cells(source_rows)
    selected_cells: dict[str, Counter[str]] = defaultdict(Counter)
    for row in audit_rows:
        selected_cells[row["field"]][row["selection_cell"]] += 1
    for field in EFFICACY_FIELDS:
        if set(selected_cells[field]) != set(population_cells[field]):
            raise ValueError(f"{field}: shared-no-manual population cells not covered")

    field_details: dict[str, Any] = {}
    for field, rows in by_field.items():
        weights = [float(row["evaluation_weight"]) for row in rows]
        field_details[field] = {
            "selected_cases": len(rows),
            "source_sample_id_set_sha256": sha256_values(
                row["sample_id"] for row in rows
            ),
            "selected_cell_counts": dict(sorted(selected_cells[field].items())),
            "population_cell_counts": dict(sorted(population_cells[field].items())),
            "kish_effective_sample_size": kish_effective_sample_size(weights),
            "zero_event_one_sided_95pct_sample_conditional_upper": (
                one_sided_cp_upper(0, len(rows))
            ),
        }

    feasibility = []
    for margin in CANDIDATE_MARGINS:
        minimum = minimum_zero_event_n(margin)
        feasibility.append(
            {
                "candidate_margin": margin,
                "minimum_human_conflicts_if_zero_simple_only_losses": minimum,
                "reporting_floor_25_can_certify_zero_loss": REPORTING_FLOOR >= minimum,
                "positive_floor_29_can_certify_zero_loss": (
                    POSITIVE_FRAMING_FLOOR >= minimum
                ),
            }
        )

    checkpoints = {
        str(total): one_sided_cp_upper(0, total)
        for total in (25, 29, 30, 34, 50, 59)
    }
    return {
        "schema_version": "t1_v31_safety_identifiability_v1",
        "analysis_type": "label_free_design_audit",
        "uses_any_human_labels": False,
        "human_labels": 0,
        "decision": "GO_FREEZE_V3_1_WITH_DELTA_0_10_AND_N29",
        "inputs": {
            relative(field_view_path): sha256_file(field_view_path),
            relative(sampling_frame_path): sha256_file(sampling_frame_path),
        },
        "repository": {
            "branch": git_value("branch", "--show-current"),
            "head": git_value("rev-parse", "HEAD"),
        },
        "safety_gate": {
            "selected_margin": SELECTED_MARGIN,
            "margin_selected_substantively_not_from_labels": True,
            "minimum_conflict_actions_per_reviewer_for_reporting": REPORTING_FLOOR,
            "minimum_conflict_actions_per_reviewer_for_positive_framing": (
                POSITIVE_FRAMING_FLOOR
            ),
            "confidence_level_one_sided": 0.95,
            "event": (
                "human conflict_escalation where field-aware-simple is manual "
                "and type-first-abstention is no-manual"
            ),
            "candidate_margin_feasibility": feasibility,
            "zero_event_upper_bound_checkpoints": checkpoints,
        },
        "shared_no_manual_route_audit": {
            "definition": (
                "both field_aware_simple_v1 and type_first_abstention_v1 choose "
                "an action outside {conflict_escalation, abstain}"
            ),
            "selected_cases": len(audit_rows),
            "source_sample_id_set_sha256": sha256_values(
                row["sample_id"] for row in audit_rows
            ),
            "fields": field_details,
            "zero_event_one_sided_95pct_sample_conditional_upper": (
                one_sided_cp_upper(0, len(audit_rows))
            ),
            "population_rate_identified": False,
            "purpose": "falsification opportunity and boundary evidence",
        },
        "claim_ceiling": {
            "human_reliability_established": False,
            "policy_superiority_established": False,
            "safety_noninferiority_established": False,
            "population_miss_rate_established": False,
            "packet_distribution_authorized": False,
        },
    }


def report_text(result: dict[str, Any]) -> str:
    audit = result["shared_no_manual_route_audit"]
    gate = result["safety_gate"]
    lines = [
        "# V3.1 Label-Free Safety Identifiability Audit",
        "",
        f"Decision: `{result['decision']}`",
        "",
        "This audit uses no human labels. It freezes what the planned sample can",
        "and cannot identify before reviewer exposure.",
        "",
        "## Frozen observations",
        "",
        f"- Shared no-manual-route audit: {audit['selected_cases']} formal cases.",
        "- Severity: 15 cases; affected versions: 19 cases.",
        (
            "- If all 34 have zero human-confirmed shared misses, the one-sided "
            f"95% sample-conditional upper bound is "
            f"{audit['zero_event_one_sided_95pct_sample_conditional_upper']:.3f}."
        ),
        "- That bound is not a population miss-rate bound; weights have small",
        "  effective sample sizes and the sample is deliberately cell-stratified.",
        "",
        "## Pre-registered positive-framing safety gate",
        "",
        f"- Simple-only manual-route loss margin: {gate['selected_margin']:.2f}.",
        "- The margin was selected substantively, not by inspecting labels.",
        (
            "- At least 29 human conflict-escalation actions are required for "
            "each reviewer; 25 remains only the reporting floor."
        ),
        "- Both reviewers must independently clear the gate.",
        "",
        "## Margin feasibility with zero observed losses",
        "",
        "| Margin | Minimum conflict actions | n=25 sufficient | n=29 sufficient |",
        "|---:|---:|:---:|:---:|",
    ]
    for row in gate["candidate_margin_feasibility"]:
        lines.append(
            f"| {row['candidate_margin']:.2f} | "
            f"{row['minimum_human_conflicts_if_zero_simple_only_losses']} | "
            f"{'yes' if row['reporting_floor_25_can_certify_zero_loss'] else 'no'} | "
            f"{'yes' if row['positive_floor_29_can_certify_zero_loss'] else 'no'} |"
        )
    lines.extend(
        [
            "",
            "No correctness, superiority, safety, or distribution claim follows",
            "from this label-free audit.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    field_view_path = resolve(args.field_view)
    sampling_frame_path = resolve(args.sampling_frame)
    output_dir = resolve(args.output_dir)
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output_dir}")
    result = analyze(field_view_path, sampling_frame_path)
    output_dir.mkdir(parents=True)
    (output_dir / "analysis.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "report.md").write_text(report_text(result), encoding="utf-8")
    print(
        "PASS: label-free V3.1 safety audit; "
        f"shared_no_manual={result['shared_no_manual_route_audit']['selected_cases']} "
        "delta_manual=0.10 positive_floor=29 human_labels=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
