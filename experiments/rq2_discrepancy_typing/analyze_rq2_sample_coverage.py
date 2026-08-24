#!/usr/bin/env python3
"""Build non-gold RQ2 annotation sample readiness diagnostics.

This script audits the prepared RQ2 annotation templates. It reports sampling
coverage, schema readiness, and blank-label status only; it does not evaluate
typing correctness, accuracy, agreement, or any gold-label metric.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIMARY = "data/annotations/rq2/discrepancy_typing_seed.jsonl"
DEFAULT_PRIMARY_MANIFEST = "data/annotations/rq2/sample_manifest.json"
DEFAULT_REVIEW = (
    "data/annotations/rq2/consistency_review/"
    "discrepancy_typing_consistency_review.jsonl"
)
DEFAULT_REVIEW_MANIFEST = (
    "data/annotations/rq2/consistency_review/sample_manifest.json"
)
DEFAULT_RQ2_DIAGNOSTICS = (
    "results/rq2_discrepancy_typing/rq2_typing_diagnostics.json"
)
DEFAULT_OUTPUT_DIR = "results/rq2_discrepancy_typing"

FIELDS = ("severity", "published", "references", "affected_versions", "cwe_ids")
STATUSES = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
)
PRIMARY_ANNOTATION_FIELDS = (
    "manual_status",
    "manual_rationale",
    "is_baseline_correct",
    "needs_adjudication",
    "evidence_urls",
    "annotator_notes",
)
REVIEW_ANNOTATION_FIELDS = (
    "reviewer_status",
    "reviewer_rationale",
    "reviewer_notes",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build non-gold RQ2 annotation sample readiness diagnostics."
    )
    parser.add_argument("--primary-path", default=DEFAULT_PRIMARY)
    parser.add_argument("--primary-manifest", default=DEFAULT_PRIMARY_MANIFEST)
    parser.add_argument("--review-path", default=DEFAULT_REVIEW)
    parser.add_argument("--review-manifest", default=DEFAULT_REVIEW_MANIFEST)
    parser.add_argument("--rq2-diagnostics", default=DEFAULT_RQ2_DIAGNOSTICS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (PROJECT_ROOT / path).resolve()


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                row = json.loads(line)
                row["_line_number"] = line_number
                yield row


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(count: int, total: int, digits: int = 1) -> str:
    if not total:
        return f"{0:.{digits}f}%"
    return f"{count / total * 100:.{digits}f}%"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] + ["---:" for _ in headers[1:]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def counter_dict(counter: Counter) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def tuple_counter_rows(counter: Counter) -> list[dict]:
    return [
        {
            "field": field,
            "baseline_status": status,
            "baseline_note": note,
            "count": count,
        }
        for (field, status, note), count in sorted(
            counter.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])
        )
    ]


def annotation_missing(row: dict, key: str, required_fields: tuple[str, ...]) -> list[str]:
    annotation = row.get(key)
    if not isinstance(annotation, dict):
        return [key]
    return [field for field in required_fields if field not in annotation]


def blank_primary_count(rows: list[dict]) -> int:
    return sum(
        1
        for row in rows
        if not str(row.get("annotation", {}).get("manual_status", "")).strip()
    )


def blank_review_count(rows: list[dict]) -> int:
    return sum(
        1
        for row in rows
        if not str(row.get("review_annotation", {}).get("reviewer_status", "")).strip()
    )


def build_primary_summary(rows: list[dict], manifest: dict, path: Path) -> dict:
    field_counts = Counter(row["field"] for row in rows)
    status_counts = Counter(row["baseline_status"] for row in rows)
    field_status_counts = Counter(
        (row["field"], row["baseline_status"]) for row in rows
    )
    rule_triggers = Counter(
        (row["field"], row["baseline_status"], row.get("baseline_note") or "")
        for row in rows
    )
    missing_schema = []
    duplicate_ids = [
        sample_id
        for sample_id, count in Counter(row.get("sample_id") for row in rows).items()
        if count > 1
    ]
    for row in rows:
        missing = annotation_missing(row, "annotation", PRIMARY_ANNOTATION_FIELDS)
        if missing:
            missing_schema.append(
                {
                    "sample_id": row.get("sample_id"),
                    "missing_fields": missing,
                }
            )

    manifest_strata = manifest.get("strata", [])
    nonzero_candidate_strata = [
        item
        for item in manifest_strata
        if item.get("candidate_count", 0) > 0
    ]
    sampled_nonzero_candidate_strata = [
        item
        for item in nonzero_candidate_strata
        if item.get("sampled_count", 0) > 0
    ]
    zero_candidate_strata = [
        item
        for item in manifest_strata
        if item.get("candidate_count", 0) == 0
    ]
    under_target_strata = [
        item
        for item in manifest_strata
        if item.get("candidate_count", 0) > 0
        and item.get("sampled_count", 0) < max(1, min(item.get("candidate_count", 0), 15))
    ]

    return {
        "path": str(path),
        "row_count": len(rows),
        "unique_sample_ids": len({row.get("sample_id") for row in rows}),
        "duplicate_sample_ids": duplicate_ids,
        "blank_manual_status_rows": blank_primary_count(rows),
        "annotation_schema_missing_rows": missing_schema,
        "field_counts": counter_dict(field_counts),
        "status_counts": counter_dict(status_counts),
        "field_status_counts": [
            {"field": field, "baseline_status": status, "count": count}
            for (field, status), count in sorted(field_status_counts.items())
        ],
        "distinct_sampled_rule_triggers": len(rule_triggers),
        "sampled_rule_triggers": tuple_counter_rows(rule_triggers),
        "manifest_seed": manifest.get("seed"),
        "target_per_field": manifest.get("target_per_field"),
        "manifest_sampled_count": manifest.get("sampled_count"),
        "manifest_field_count": len(manifest.get("fields", [])),
        "manifest_status_count": len(manifest.get("statuses", [])),
        "manifest_strata_count": len(manifest_strata),
        "nonzero_candidate_strata": len(nonzero_candidate_strata),
        "sampled_nonzero_candidate_strata": len(sampled_nonzero_candidate_strata),
        "zero_candidate_strata": [
            {
                "field": item.get("field"),
                "baseline_status": item.get("baseline_status"),
            }
            for item in zero_candidate_strata
        ],
        "under_target_nonzero_candidate_strata": under_target_strata,
    }


def build_review_summary(
    review_rows: list[dict],
    primary_rows: list[dict],
    manifest: dict,
    path: Path,
) -> dict:
    primary_by_id = {row["sample_id"]: row for row in primary_rows}
    missing_originals = []
    field_mismatches = []
    duplicate_ids = [
        sample_id
        for sample_id, count in Counter(
            row.get("review_sample_id") for row in review_rows
        ).items()
        if count > 1
    ]
    missing_schema = []
    field_counts = Counter()
    status_counts = Counter()
    field_status_counts = Counter()
    rule_triggers = Counter()

    for row in review_rows:
        original_id = row.get("original_sample_id")
        primary = primary_by_id.get(original_id)
        if not primary:
            missing_originals.append(original_id)
        elif primary.get("field") != row.get("field"):
            field_mismatches.append(row.get("review_sample_id"))

        field_counts[row["field"]] += 1
        status_counts[row["baseline_status"]] += 1
        field_status_counts[(row["field"], row["baseline_status"])] += 1
        rule_triggers[
            (row["field"], row["baseline_status"], row.get("baseline_note") or "")
        ] += 1
        missing = annotation_missing(
            row, "review_annotation", REVIEW_ANNOTATION_FIELDS
        )
        if missing:
            missing_schema.append(
                {
                    "review_sample_id": row.get("review_sample_id"),
                    "missing_fields": missing,
                }
            )

    return {
        "path": str(path),
        "row_count": len(review_rows),
        "unique_review_sample_ids": len(
            {row.get("review_sample_id") for row in review_rows}
        ),
        "duplicate_review_sample_ids": duplicate_ids,
        "blank_reviewer_status_rows": blank_review_count(review_rows),
        "review_schema_missing_rows": missing_schema,
        "missing_original_sample_ids": missing_originals,
        "field_mismatches_with_primary": field_mismatches,
        "field_counts": counter_dict(field_counts),
        "status_counts": counter_dict(status_counts),
        "field_status_counts": [
            {"field": field, "baseline_status": status, "count": count}
            for (field, status), count in sorted(field_status_counts.items())
        ],
        "distinct_sampled_rule_triggers": len(rule_triggers),
        "sampled_rule_triggers": tuple_counter_rows(rule_triggers),
        "manifest_seed": manifest.get("seed"),
        "manifest_fraction": manifest.get("fraction"),
        "manifest_candidate_count": manifest.get("candidate_count"),
        "manifest_sampled_count": manifest.get("sampled_count"),
        "manifest_strata": manifest.get("strata", []),
    }


def build_rule_trigger_coverage(primary_rows: list[dict], diagnostics: dict | None) -> dict:
    if not diagnostics:
        return {
            "diagnostics_path_present": False,
            "top_trigger_count": 0,
            "covered_top_triggers": 0,
            "covered_top_trigger_rate": 0.0,
            "top_triggers": [],
        }

    sampled_triggers = {
        (row["field"], row["baseline_status"], row.get("baseline_note") or "")
        for row in primary_rows
    }
    top_triggers = []
    covered = 0
    for item in diagnostics.get("rule_triggers", [])[:12]:
        trigger_key = (
            item.get("field"),
            item.get("status"),
            item.get("note") or "",
        )
        is_covered = trigger_key in sampled_triggers
        covered += int(is_covered)
        top_triggers.append(
            {
                "field": trigger_key[0],
                "baseline_status": trigger_key[1],
                "baseline_note": trigger_key[2],
                "full_corpus_count": item.get("count", 0),
                "covered_by_primary_seed": is_covered,
            }
        )
    return {
        "diagnostics_path_present": True,
        "top_trigger_count": len(top_triggers),
        "covered_top_triggers": covered,
        "covered_top_trigger_rate": covered / len(top_triggers)
        if top_triggers
        else 0.0,
        "top_triggers": top_triggers,
    }


def build_readiness(
    primary_path: Path,
    primary_manifest_path: Path,
    review_path: Path,
    review_manifest_path: Path,
    diagnostics_path: Path,
) -> dict:
    primary_rows = list(iter_jsonl(primary_path))
    review_rows = list(iter_jsonl(review_path))
    primary_manifest = read_json(primary_manifest_path)
    review_manifest = read_json(review_manifest_path)
    diagnostics = read_json(diagnostics_path) if diagnostics_path.exists() else None

    primary = build_primary_summary(primary_rows, primary_manifest, primary_path)
    review = build_review_summary(
        review_rows, primary_rows, review_manifest, review_path
    )
    trigger_coverage = build_rule_trigger_coverage(primary_rows, diagnostics)

    primary_fields_ok = all(primary["field_counts"].get(field) == 60 for field in FIELDS)
    review_fields_ok = all(review["field_counts"].get(field) == 12 for field in FIELDS)
    primary_blank = primary["blank_manual_status_rows"] == primary["row_count"]
    review_blank = review["blank_reviewer_status_rows"] == review["row_count"]

    return {
        "artifact": "rq2_sample_coverage_readiness",
        "label_source": "blank_annotation_templates",
        "gold_label_is_human": False,
        "metric_scope": "readiness_diagnostic_only",
        "source_paths": {
            "primary": str(primary_path),
            "primary_manifest": str(primary_manifest_path),
            "review": str(review_path),
            "review_manifest": str(review_manifest_path),
            "rq2_typing_diagnostics": str(diagnostics_path),
        },
        "cautions": [
            "This is a blank annotation-template readiness diagnostic, not a gold-label evaluation.",
            "It reports sample coverage, schema readiness, and blank-label guards only.",
            "Do not report RQ2 accuracy, macro-F1, precision, recall, agreement, or Cohen's kappa from this artifact.",
        ],
        "primary_seed": primary,
        "consistency_review": review,
        "rule_trigger_coverage": trigger_coverage,
        "readiness_checks": {
            "primary_row_count_is_300": primary["row_count"] == 300,
            "primary_field_counts_are_60_each": primary_fields_ok,
            "primary_all_nonzero_candidate_strata_sampled": (
                primary["sampled_nonzero_candidate_strata"]
                == primary["nonzero_candidate_strata"]
            ),
            "primary_manual_status_all_blank": primary_blank,
            "primary_annotation_schema_complete": not primary[
                "annotation_schema_missing_rows"
            ],
            "review_row_count_is_60": review["row_count"] == 60,
            "review_field_counts_are_12_each": review_fields_ok,
            "review_original_ids_match_primary": not review[
                "missing_original_sample_ids"
            ],
            "reviewer_status_all_blank": review_blank,
            "review_annotation_schema_complete": not review[
                "review_schema_missing_rows"
            ],
            "no_completed_rq2_labels": primary_blank and review_blank,
        },
    }


def render_markdown(readiness: dict) -> str:
    primary = readiness["primary_seed"]
    review = readiness["consistency_review"]
    trigger = readiness["rule_trigger_coverage"]

    lines = [
        "# RQ2 Sample Coverage Readiness",
        "",
        "This artifact summarizes prepared RQ2 annotation templates. It is a readiness diagnostic, not a gold-label evaluation.",
        "",
        f"- Primary seed rows: {primary['row_count']}",
        f"- Primary blank `manual_status` rows: {primary['blank_manual_status_rows']}/{primary['row_count']}",
        f"- Consistency review rows: {review['row_count']}",
        f"- Blank `reviewer_status` rows: {review['blank_reviewer_status_rows']}/{review['row_count']}",
        f"- Nonzero `(field, baseline_status)` candidate strata sampled: {primary['sampled_nonzero_candidate_strata']}/{primary['nonzero_candidate_strata']}",
        f"- Distinct primary sampled rule triggers: {primary['distinct_sampled_rule_triggers']}",
        f"- Covered top full-corpus rule triggers: {trigger['covered_top_triggers']}/{trigger['top_trigger_count']}",
        "",
        "## Primary Seed Field Coverage",
        "",
        table(
            ["Field", "Rows"],
            [[field, str(primary["field_counts"].get(field, 0))] for field in FIELDS],
        ),
        "",
        "## Primary Seed Status Coverage",
        "",
        table(
            ["Status", "Rows"],
            [
                [status, str(primary["status_counts"].get(status, 0))]
                for status in STATUSES
            ],
        ),
        "",
        "## Field/Status Sample Coverage",
        "",
        table(
            ["Field", "Status", "Rows"],
            [
                [item["field"], item["baseline_status"], str(item["count"])]
                for item in primary["field_status_counts"]
            ],
        ),
        "",
        "## Consistency Review Field Coverage",
        "",
        table(
            ["Field", "Rows"],
            [[field, str(review["field_counts"].get(field, 0))] for field in FIELDS],
        ),
        "",
        "## Top Rule-Trigger Coverage",
        "",
        table(
            ["Field", "Status", "Full corpus count", "Covered"],
            [
                [
                    item["field"],
                    item["baseline_status"],
                    str(item["full_corpus_count"]),
                    "yes" if item["covered_by_primary_seed"] else "no",
                ]
                for item in trigger["top_triggers"]
            ],
        ),
        "",
        "## Readiness Checks",
        "",
        table(
            ["Check", "Status"],
            [
                [name, "pass" if ok else "fail"]
                for name, ok in readiness["readiness_checks"].items()
            ],
        ),
        "",
        "Caution: these templates remain blank and must not be used to report RQ2 accuracy, macro-F1, precision, recall, agreement, or Cohen's kappa.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    readiness = build_readiness(
        resolve_path(args.primary_path),
        resolve_path(args.primary_manifest),
        resolve_path(args.review_path),
        resolve_path(args.review_manifest),
        resolve_path(args.rq2_diagnostics),
    )
    json_path = output_dir / "rq2_sample_coverage.json"
    md_path = output_dir / "rq2_sample_coverage.md"
    json_path.write_text(
        json.dumps(readiness, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(readiness), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
