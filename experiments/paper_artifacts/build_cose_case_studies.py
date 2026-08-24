#!/usr/bin/env python3
"""Build small COSE case-study sketches from existing RQ3 artifacts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEVERITY_EVIDENCE = (
    "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl"
)
DEFAULT_SEVERITY_SILVER = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "severity_fc_adjudication_seed.evidence.llm_draft.jsonl"
)
DEFAULT_SEVERITY_PREDICTIONS = (
    "results/rq3_adjudication/severity_silver_v2_predictions.jsonl"
)
DEFAULT_AFFECTED_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_AFFECTED_SILVER = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/paper_cose"
DEFAULT_PAPER_TABLE_DIR = "paper/cose/tables"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build reproducible COSE case-study sketches."
    )
    parser.add_argument("--severity-evidence", default=DEFAULT_SEVERITY_EVIDENCE)
    parser.add_argument("--severity-silver", default=DEFAULT_SEVERITY_SILVER)
    parser.add_argument("--severity-predictions", default=DEFAULT_SEVERITY_PREDICTIONS)
    parser.add_argument("--affected-evidence", default=DEFAULT_AFFECTED_EVIDENCE)
    parser.add_argument("--affected-silver", default=DEFAULT_AFFECTED_SILVER)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--paper-table-dir", default=DEFAULT_PAPER_TABLE_DIR)
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


def load_by_sample_id(path: Path) -> dict[str, dict]:
    rows = {}
    for row in iter_jsonl(path):
        sample_id = row["sample_id"]
        if sample_id in rows:
            raise ValueError(f"Duplicate sample_id in {path}: {sample_id}")
        rows[sample_id] = row
    return rows


def load_predictions(path: Path) -> dict[str, dict[str, dict]]:
    predictions = defaultdict(dict)
    for row in iter_jsonl(path):
        predictions[row["sample_id"]][row["method"]] = row
    return dict(predictions)


def evidence_status_summary(row: dict) -> dict:
    statuses = Counter()
    ok_hosts = Counter()
    for record in row.get("evidence_context", {}).get("records", []):
        status = record.get("fetch_status") or "missing"
        statuses[status] += 1
        if status == "ok":
            ok_hosts[record.get("host") or ""] += 1
    return {
        "candidate_url_count": row.get("evidence_context", {}).get(
            "candidate_url_count", 0
        ),
        "fetch_status_counts": dict(sorted(statuses.items())),
        "ok_hosts": [host for host, _ in ok_hosts.most_common(5)],
    }


def summarize_version_span(span: dict) -> str:
    if span.get("version"):
        return str(span["version"])
    parts = []
    if span.get("introduced"):
        parts.append(f"introduced {span['introduced']}")
    if span.get("version_start_including"):
        parts.append(f">={span['version_start_including']}")
    if span.get("version_start_excluding"):
        parts.append(f">{span['version_start_excluding']}")
    if span.get("version_end_including"):
        parts.append(f"<={span['version_end_including']}")
    if span.get("version_end_excluding"):
        parts.append(f"<{span['version_end_excluding']}")
    if span.get("fixed"):
        parts.append(f"fixed {span['fixed']}")
    return ", ".join(parts) if parts else "unspecified"


def summarize_value(value) -> str:
    if isinstance(value, list):
        spans = [summarize_version_span(item) for item in value[:3]]
        suffix = "" if len(value) <= 3 else f"; +{len(value) - 3} more"
        return f"{len(value)} span(s): " + "; ".join(spans) + suffix
    return str(value)


def support_scores(prediction: dict) -> dict:
    detail = prediction.get("prediction_detail") or {}
    support = detail.get("support") or {}
    return {
        source: {
            "score": values.get("score", 0),
            "matched_terms": values.get("matched_terms", []),
            "matched_url_count": len(values.get("matched_urls", [])),
        }
        for source, values in sorted(support.items())
    }


def compact_text(value: str, limit: int = 88) -> str:
    value = " ".join(str(value).split())
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def severity_case(kind: str, evidence: dict, silver: dict, prediction: dict) -> dict:
    annotation = silver["llm_annotation"]
    return {
        "kind": kind,
        "sample_id": evidence["sample_id"],
        "cve_id": evidence["cve_id"],
        "field": "severity",
        "nvd_value": summarize_value(evidence.get("nvd_value")),
        "ghsa_value": summarize_value(evidence.get("ghsa_value")),
        "silver_label": annotation["llm_label"],
        "silver_source": annotation["adjudicated_source"],
        "predicted_source": prediction["predicted_source"],
        "silver_match": prediction["is_correct"],
        "confidence": annotation["confidence"],
        "support": support_scores(prediction),
        "evidence": evidence_status_summary(evidence),
    }


def affected_case(kind: str, evidence: dict, silver: dict) -> dict:
    annotation = silver["llm_annotation"]
    return {
        "kind": kind,
        "sample_id": evidence["sample_id"],
        "cve_id": evidence["cve_id"],
        "field": "affected_versions",
        "nvd_value": summarize_value(evidence.get("nvd_value")),
        "ghsa_value": summarize_value(evidence.get("ghsa_value")),
        "silver_label": annotation["llm_label"],
        "is_baseline_false_positive": annotation["is_baseline_false_positive"],
        "adjudicated_source": annotation["adjudicated_source"],
        "confidence": annotation["confidence"],
        "evidence": evidence_status_summary(evidence),
    }


def select_severity_cases(
    evidence_rows: dict[str, dict],
    silver_rows: dict[str, dict],
    predictions: dict[str, dict[str, dict]],
) -> list[dict]:
    selected = []
    criteria = [
        (
            "severity_both_sources_supported",
            lambda row: row["is_correct"]
            and row["silver_source"] == "both"
            and row["predicted_source"] == "both",
        ),
        (
            "severity_single_source_supported",
            lambda row: row["is_correct"]
            and row["silver_source"] == "nvd"
            and row["predicted_source"] == "nvd",
        ),
        (
            "severity_silver_label_mismatch_both_vs_nvd",
            lambda row: (not row["is_correct"])
            and row["silver_source"] == "both"
            and row["predicted_source"] == "nvd",
        ),
        (
            "severity_manual_review_abstain",
            lambda row: row["silver_source"] == "abstain",
        ),
    ]
    for kind, predicate in criteria:
        for sample_id in sorted(predictions):
            prediction = predictions[sample_id].get("evidence_score_baseline")
            if not prediction or not predicate(prediction):
                continue
            selected.append(
                severity_case(
                    kind,
                    evidence_rows[sample_id],
                    silver_rows[sample_id],
                    prediction,
                )
            )
            break
    return selected


def select_affected_cases(
    evidence_rows: dict[str, dict],
    silver_rows: dict[str, dict],
) -> list[dict]:
    selected = []
    criteria = [
        (
            "affected_versions_baseline_false_positive",
            lambda ann: ann["is_baseline_false_positive"] == "yes"
            and ann["llm_label"] in {"incomplete", "representation_discrepancy"},
        ),
        (
            "affected_versions_residual_factual_conflict",
            lambda ann: ann["is_baseline_false_positive"] == "no"
            and ann["llm_label"] == "factual_conflict",
        ),
    ]
    for kind, predicate in criteria:
        for sample_id in sorted(silver_rows):
            annotation = silver_rows[sample_id]["llm_annotation"]
            if not predicate(annotation):
                continue
            selected.append(
                affected_case(kind, evidence_rows[sample_id], silver_rows[sample_id])
            )
            break
    return selected


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def case_pattern(case: dict) -> str:
    patterns = {
        "severity_both_sources_supported": "Severity evidence supports both sources",
        "severity_single_source_supported": "Severity evidence supports one source",
        "severity_silver_label_mismatch_both_vs_nvd": "Severity silver-label mismatch",
        "severity_manual_review_abstain": "Severity abstention/manual review",
        "affected_versions_baseline_false_positive": "Affected_versions baseline false positive",
        "affected_versions_residual_factual_conflict": "Affected_versions residual conflict",
    }
    return patterns.get(case["kind"], case["kind"])


def case_silver_reading(case: dict) -> str:
    if case["field"] == "severity":
        return (
            f"silver source={case['silver_source']}; "
            f"baseline={case['predicted_source']}; "
            f"matches_silver={case['silver_match']}"
        )
    return (
        f"silver label={case['silver_label']}; "
        f"baseline false positive={case['is_baseline_false_positive']}; "
        f"source={case['adjudicated_source']}"
    )


def case_evidence_note(case: dict) -> str:
    status_text = ", ".join(
        f"{status}={count}"
        for status, count in case["evidence"]["fetch_status_counts"].items()
    )
    hosts = ", ".join(case["evidence"]["ok_hosts"]) or "none"
    return f"{status_text}; ok hosts: {hosts}"


def paper_case_rows(cases: list[dict]) -> list[dict[str, str]]:
    rows = []
    for case in cases:
        rows.append(
            {
                "pattern": case_pattern(case),
                "cve": case["cve_id"],
                "field": case["field"],
                "nvd_value": compact_text(case["nvd_value"]),
                "ghsa_value": compact_text(case["ghsa_value"]),
                "silver_reading": case_silver_reading(case),
                "evidence_note": compact_text(case_evidence_note(case), limit=110),
            }
        )
    return rows


def render_paper_case_table(cases: list[dict]) -> str:
    rows = paper_case_rows(cases)
    return "\n".join(
        [
            "# RQ3 Case-Study Sketch Table",
            "",
            "Generated from existing RQ3 silver-label artifacts. These examples are interpretive sketches, not new human gold labels.",
            "",
            table(
                [
                    "Pattern",
                    "CVE",
                    "Field",
                    "NVD value",
                    "GHSA value",
                    "Silver reading",
                    "Evidence note",
                ],
                [
                    [
                        row["pattern"],
                        row["cve"],
                        row["field"],
                        row["nvd_value"],
                        row["ghsa_value"],
                        row["silver_reading"],
                        row["evidence_note"],
                    ]
                    for row in rows
                ],
            ),
            "",
        ]
    )


def write_paper_case_csv(path: Path, cases: list[dict]) -> None:
    rows = paper_case_rows(cases)
    fieldnames = [
        "pattern",
        "cve",
        "field",
        "nvd_value",
        "ghsa_value",
        "silver_reading",
        "evidence_note",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def render_case_md(cases: list[dict]) -> str:
    lines = [
        "# COSE Case Study Sketches",
        "",
        "These cases are selected deterministically from existing RQ3 artifacts. They are paper-facing examples, not new gold labels.",
        "",
        table(
            ["Kind", "CVE", "Field", "NVD value", "GHSA value", "Silver outcome"],
            [
                [
                    case["kind"],
                    case["cve_id"],
                    case["field"],
                    case["nvd_value"],
                    case["ghsa_value"],
                    case.get("silver_source")
                    or case.get("adjudicated_source")
                    or case["silver_label"],
                ]
                for case in cases
            ],
        ),
        "",
    ]

    for case in cases:
        status_text = ", ".join(
            f"{status}={count}"
            for status, count in case["evidence"]["fetch_status_counts"].items()
        )
        lines.extend(
            [
                f"## {case['kind']}",
                "",
                f"- Sample: `{case['sample_id']}` / `{case['cve_id']}`",
                f"- Field: `{case['field']}`",
                f"- NVD value: {case['nvd_value']}",
                f"- GHSA value: {case['ghsa_value']}",
                f"- Evidence fetch status: {status_text}",
                f"- OK evidence hosts: {', '.join(case['evidence']['ok_hosts'])}",
            ]
        )
        if case["field"] == "severity":
            support_parts = []
            for source, values in case["support"].items():
                terms = ",".join(values["matched_terms"]) or "none"
                support_parts.append(
                    f"{source}: score={values['score']}, urls={values['matched_url_count']}, terms={terms}"
                )
            lines.extend(
                [
                    f"- Silver source: `{case['silver_source']}`; prediction: `{case['predicted_source']}`; matches silver: `{case['silver_match']}`",
                    f"- Support sketch: {'; '.join(support_parts)}",
                ]
            )
        else:
            lines.extend(
                [
                    f"- Silver label: `{case['silver_label']}`; baseline false positive: `{case['is_baseline_false_positive']}`",
                    f"- Adjudicated source: `{case['adjudicated_source']}`; confidence: `{case['confidence']}`",
                ]
            )
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    paper_table_dir = resolve_path(args.paper_table_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    paper_table_dir.mkdir(parents=True, exist_ok=True)

    severity_evidence = load_by_sample_id(resolve_path(args.severity_evidence))
    severity_silver = load_by_sample_id(resolve_path(args.severity_silver))
    severity_predictions = load_predictions(resolve_path(args.severity_predictions))
    affected_evidence = load_by_sample_id(resolve_path(args.affected_evidence))
    affected_silver = load_by_sample_id(resolve_path(args.affected_silver))

    cases = []
    cases.extend(
        select_severity_cases(severity_evidence, severity_silver, severity_predictions)
    )
    cases.extend(select_affected_cases(affected_evidence, affected_silver))

    artifact = {
        "source_paths": {
            "severity_evidence": str(resolve_path(args.severity_evidence)),
            "severity_silver": str(resolve_path(args.severity_silver)),
            "severity_predictions": str(resolve_path(args.severity_predictions)),
            "affected_versions_evidence": str(resolve_path(args.affected_evidence)),
            "affected_versions_silver": str(resolve_path(args.affected_silver)),
        },
        "cautions": [
            "Cases are selected from silver-label artifacts, not human gold labels.",
            "Affected_versions cases are not performance metrics.",
            "Abstention/manual-review cases are illustrative sketches, not new labels.",
        ],
        "cases": cases,
    }

    json_path = output_dir / "cose_case_studies.json"
    md_path = output_dir / "cose_case_studies.md"
    paper_md_path = paper_table_dir / "rq3_case_study_sketches.md"
    paper_csv_path = paper_table_dir / "rq3_case_study_sketches.csv"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
    md_path.write_text(render_case_md(cases), encoding="utf-8")
    paper_md_path.write_text(render_paper_case_table(cases), encoding="utf-8")
    write_paper_case_csv(paper_csv_path, cases)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Wrote {paper_md_path}")
    print(f"Wrote {paper_csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
