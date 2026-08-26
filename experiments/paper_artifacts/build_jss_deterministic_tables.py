#!/usr/bin/env python3
"""Build the editable, label-free RQ1/RQ2 tables for the JSS zero draft.

The script reads only the frozen deterministic routing census. It refuses
inputs that contain labels or advertise human/correctness evidence. CSV and
LaTeX are written from the same checked rows so lookup tables and the
manuscript cannot silently diverge.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


FIELD_ORDER = ("severity", "affected_versions", "published", "references")
FIELD_LABELS = {
    "severity": "Severity",
    "affected_versions": "Affected versions",
    "published": "Publication date",
    "references": "References",
}
STATUS_ORDER = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
STATUS_LABELS = {
    "equivalent": "EQ",
    "representation_discrepancy": "RD",
    "incomplete": "INC",
    "temporal_discrepancy": "TD",
    "factual_conflict": "FC",
}
STRATEGY_ORDER = (
    "field_aware_simple_v1",
    "type_first_current_v1",
    "type_first_abstention_v1",
)
STRATEGY_LABELS = {
    "field_aware_simple_v1": "Field-aware simple",
    "type_first_current_v1": "Type-first current",
    "type_first_abstention_v1": "Type-first abstention-aware",
}
STRATEGY_TEX_LABELS = {
    "Field-aware simple": "Field-aware",
    "Type-first current": "Type-first current",
    "Type-first abstention-aware": "Type-first abstention",
}
ACTION_ORDER = (
    "no_action",
    "enrich_record",
    "wait_for_sync",
    "conflict_escalation",
    "abstain",
)
ACTION_LABELS = {
    "no_action": "No action",
    "enrich_record": "Enrich",
    "wait_for_sync": "Wait",
    "conflict_escalation": "Conflict",
    "abstain": "Abstain",
}
PAIR_ORDER = (
    ("field_aware_simple_v1", "type_first_current_v1"),
    ("field_aware_simple_v1", "type_first_abstention_v1"),
    ("type_first_current_v1", "type_first_abstention_v1"),
)
PAIR_LABELS = {
    PAIR_ORDER[0]: "Simple vs current",
    PAIR_ORDER[1]: "Simple vs abstention-aware",
    PAIR_ORDER[2]: "Current vs abstention-aware",
}
PAIR_TEX_LABELS = {
    "Simple vs current": "Simple/current",
    "Simple vs abstention-aware": "Simple/abstention",
    "Current vs abstention-aware": "Current/abstention",
}


def _require_label_free(analysis: dict) -> None:
    checks = {
        "uses_any_labels": False,
        "label_is_human": False,
        "eligible_for_accuracy_claim": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_policy_superiority_claim": False,
        "eligible_for_submission_readiness_claim": False,
        "eligible_for_workload_reduction_claim": False,
    }
    for key, expected in checks.items():
        actual = analysis.get(key)
        if actual is not expected:
            raise ValueError(f"unsafe analysis flag {key}={actual!r}; expected {expected!r}")
    if analysis.get("label_source") != "none_label_free_policy_census":
        raise ValueError("analysis label_source is not the frozen label-free census")


def build_rows(analysis: dict) -> tuple[list[list[object]], list[list[object]], list[list[object]]]:
    _require_label_free(analysis)
    rows = int(analysis["rows"])
    field_instances = int(analysis["field_instances"])
    if rows != 8066 or field_instances != rows * len(FIELD_ORDER):
        raise ValueError(f"unexpected corpus dimensions: rows={rows}, field_instances={field_instances}")

    rq1_rows: list[list[object]] = []
    for field in FIELD_ORDER:
        counts = analysis["deterministic_status_counts"][field]
        values = [int(counts.get(status, 0)) for status in STATUS_ORDER]
        if sum(values) != rows:
            raise ValueError(f"RQ1 row for {field} sums to {sum(values)}, expected {rows}")
        rq1_rows.append([FIELD_LABELS[field], *values, sum(values)])

    rq2_rows: list[list[object]] = []
    for strategy in STRATEGY_ORDER:
        by_field = analysis["policy_action_counts"][strategy]
        totals = {action: 0 for action in ACTION_ORDER}
        for field in FIELD_ORDER:
            field_total = 0
            for action in ACTION_ORDER:
                value = int(by_field[field].get(action, 0))
                totals[action] += value
                field_total += value
            if field_total != rows:
                raise ValueError(
                    f"action row for {strategy}/{field} sums to {field_total}, expected {rows}"
                )
        all_actions = sum(totals.values())
        if all_actions != field_instances:
            raise ValueError(f"strategy {strategy} sums to {all_actions}, expected {field_instances}")
        manual_total = totals["conflict_escalation"] + totals["abstain"]
        rq2_rows.append(
            [
                STRATEGY_LABELS[strategy],
                *(totals[action] for action in ACTION_ORDER),
                manual_total,
                all_actions,
            ]
        )

    disagreement_rows: list[list[object]] = []
    disagreements = analysis["pairwise_action_disagreement_counts"]
    for first, second in PAIR_ORDER:
        key = f"{first}__vs__{second}"
        if key not in disagreements:
            key = f"{second}__vs__{first}"
        counts = disagreements[key]
        values = [int(counts.get(field, 0)) for field in FIELD_ORDER]
        disagreement_rows.append([PAIR_LABELS[(first, second)], *values, sum(values)])

    return rq1_rows, rq2_rows, disagreement_rows


def _write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _latex_escape(value: object) -> str:
    return str(value).replace("&", r"\&").replace("%", r"\%").replace("_", r"\_")


def _write_tex(
    path: Path,
    caption: str,
    label: str,
    header: list[str],
    rows: list[list[object]],
    column_spec: str,
    note: str,
) -> None:
    lines = [
        "% Generated by experiments/paper_artifacts/build_jss_deterministic_tables.py",
        "% Source: results/jss/t1_routing_precheck_v1/analysis.json",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{" + caption + "}",
        r"\label{" + label + "}",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{3pt}",
        r"\begin{tabular}{" + column_spec + "}",
        r"\toprule",
        " & ".join(_latex_escape(cell) for cell in header) + r" \\",
        r"\midrule",
    ]
    lines.extend(" & ".join(_latex_escape(cell) for cell in row) + r" \\" for row in rows)
    lines.extend(
        [
            r"\bottomrule",
            r"\end{tabular}",
            r"\begin{minipage}{0.98\linewidth}",
            r"\footnotesize\textit{Note:} " + note,
            r"\end{minipage}",
            r"\end{table}",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def build(analysis_path: Path, output_dir: Path) -> None:
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    rq1_rows, rq2_rows, disagreement_rows = build_rows(analysis)
    output_dir.mkdir(parents=True, exist_ok=True)

    rq1_header = ["Field", *(STATUS_LABELS[s] for s in STATUS_ORDER), "Total"]
    rq2_header = [
        "Strategy",
        *(ACTION_LABELS[a] for a in ACTION_ORDER),
        "Manual total",
        "All",
    ]
    disagreement_header = ["Pair", *(FIELD_LABELS[f] for f in FIELD_ORDER), "Total"]
    rq2_tex_header = [
        "Strategy",
        "No act.",
        "Enrich",
        "Wait",
        "Conflict",
        "Abstain",
        "Manual",
        "Total",
    ]
    disagreement_tex_header = ["Pair", "Sev.", "Affected", "Date", "Refs", "Total"]
    rq2_tex_rows = [
        [STRATEGY_TEX_LABELS[str(row[0])], *row[1:]]
        for row in rq2_rows
    ]
    disagreement_tex_rows = [
        [PAIR_TEX_LABELS[str(row[0])], *row[1:]]
        for row in disagreement_rows
    ]

    _write_csv(output_dir / "rq1_status_counts.csv", rq1_header, rq1_rows)
    _write_csv(output_dir / "rq2_strategy_actions.csv", rq2_header, rq2_rows)
    _write_csv(
        output_dir / "rq2_pairwise_disagreements.csv", disagreement_header, disagreement_rows
    )

    _write_tex(
        output_dir / "table_rq1_status_counts.tex",
        "Deterministic discrepancy-status counts by field.",
        "tab:rq1-status",
        rq1_header,
        rq1_rows,
        "lrrrrrr",
        "EQ = equivalent; RD = representation discrepancy; INC = incomplete; "
        "TD = temporal discrepancy; FC = factual conflict. Counts are deterministic "
        "rule outputs, not human-verified factual labels.",
    )
    _write_tex(
        output_dir / "table_rq2_strategy_actions.tex",
        "Deterministic routing allocations by strategy.",
        "tab:rq2-actions",
        rq2_tex_header,
        rq2_tex_rows,
        "lrrrrrrr",
        "Manual total is Conflict + Abstain. Counts describe strategy outputs on "
        "32,264 field instances; they do not measure labor, correctness, safety, or utility.",
    )
    _write_tex(
        output_dir / "table_rq2_pairwise_disagreements.tex",
        "Pairwise action disagreements across routing strategies.",
        "tab:rq2-disagreements",
        disagreement_tex_header,
        disagreement_tex_rows,
        "lrrrrr",
        "Each cell counts field instances on which the two named frozen strategies "
        "emit different actions. Zero is an observed census count, not missing data.",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--analysis",
        type=Path,
        default=Path("results/jss/t1_routing_precheck_v1/analysis.json"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("paper/jss/latex"))
    args = parser.parse_args()
    build(args.analysis, args.output_dir)


if __name__ == "__main__":
    main()
