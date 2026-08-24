#!/usr/bin/env python3
"""Characterize affected_versions package and version-system alignment.

This is a deterministic diagnostic over the 100-sample affected_versions
silver-v2 set. It describes package-name, version-shape, and token-overlap
properties; it does not adjudicate semantic version ranges or create gold
labels.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from evaluate_affected_versions_silver_v2 import extract_version_tokens


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_SILVER = (
    "data/annotations/rq3/silver_v2/llm_silver_v2/"
    "affected_versions_fc_manual_check.evidence.llm_draft.jsonl"
)
DEFAULT_OUTPUT_JSON = (
    "results/rq3_adjudication/affected_versions_alignment_diagnostics.json"
)
DEFAULT_OUTPUT_MD = "results/rq3_adjudication/affected_versions_alignment_diagnostics.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze affected_versions package/version-system alignment."
    )
    parser.add_argument("--evidence-input", default=DEFAULT_EVIDENCE)
    parser.add_argument("--silver-input", default=DEFAULT_SILVER)
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    return parser.parse_args()


def resolve_path(value: str | Path) -> Path:
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


def normalize_name(value: str) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"^pkg:[^/]+/", "", value)
    value = value.replace("_", "-")
    return value


def leaf_name(value: str) -> str:
    value = normalize_name(value)
    for separator in ("/", ":", "\\"):
        if separator in value:
            value = value.split(separator)[-1]
    return value


def package_profile(row: dict) -> dict:
    nvd_names = {normalize_name(value) for value in row.get("nvd_context", {}).get("package_names", [])}
    ghsa_names = {normalize_name(value) for value in row.get("ghsa_context", {}).get("package_names", [])}
    nvd_leaf = {leaf_name(value) for value in nvd_names}
    ghsa_leaf = {leaf_name(value) for value in ghsa_names}
    exact_overlap = sorted(nvd_names & ghsa_names)
    leaf_overlap = sorted(nvd_leaf & ghsa_leaf)
    if exact_overlap:
        category = "exact_package_overlap"
    elif leaf_overlap:
        category = "leaf_package_overlap_only"
    elif nvd_names and ghsa_names:
        category = "no_package_name_overlap"
    else:
        category = "missing_package_name"
    return {
        "category": category,
        "nvd_package_names": sorted(nvd_names),
        "ghsa_package_names": sorted(ghsa_names),
        "exact_overlap": exact_overlap,
        "leaf_overlap": leaf_overlap,
        "nvd_package_count": len(nvd_names),
        "ghsa_package_count": len(ghsa_names),
    }


def span_shape(span: dict) -> str:
    has_point = bool(span.get("version"))
    has_start = bool(span.get("version_start_including") or span.get("version_start_excluding") or span.get("introduced"))
    has_end = bool(span.get("version_end_including") or span.get("version_end_excluding") or span.get("fixed"))
    if has_point and (has_start or has_end):
        return "mixed_point_and_range"
    if has_point:
        return "point_version"
    if has_start and has_end:
        return "bounded_range"
    if has_start:
        return "lower_bounded_range"
    if has_end:
        return "upper_bounded_range"
    return "empty_span"


def version_profile(row: dict) -> dict:
    nvd_shapes = Counter(span_shape(span) for span in row.get("nvd_value") or [])
    ghsa_shapes = Counter(span_shape(span) for span in row.get("ghsa_value") or [])
    nvd_tokens = extract_version_tokens(row.get("nvd_value") or [])
    ghsa_tokens = extract_version_tokens(row.get("ghsa_value") or [])
    shared_tokens = sorted(nvd_tokens & ghsa_tokens)
    suffix_tokens = [
        token
        for token in sorted(nvd_tokens | ghsa_tokens)
        if re.search(r"(?:-|\\+|rc|alpha|beta|p\\d|lts|ext)", token, re.I)
    ]
    if nvd_shapes == ghsa_shapes:
        shape_category = "same_shape_counts"
    elif nvd_shapes.get("point_version") and (
        ghsa_shapes.get("bounded_range")
        or ghsa_shapes.get("upper_bounded_range")
        or ghsa_shapes.get("lower_bounded_range")
    ):
        shape_category = "nvd_points_vs_ghsa_ranges"
    elif ghsa_shapes.get("point_version") and (
        nvd_shapes.get("bounded_range")
        or nvd_shapes.get("upper_bounded_range")
        or nvd_shapes.get("lower_bounded_range")
    ):
        shape_category = "ghsa_points_vs_nvd_ranges"
    elif len(row.get("nvd_value") or []) != len(row.get("ghsa_value") or []):
        shape_category = "span_count_mismatch"
    else:
        shape_category = "other_shape_mismatch"
    return {
        "shape_category": shape_category,
        "nvd_shape_counts": dict(sorted(nvd_shapes.items())),
        "ghsa_shape_counts": dict(sorted(ghsa_shapes.items())),
        "nvd_span_count": sum(nvd_shapes.values()),
        "ghsa_span_count": sum(ghsa_shapes.values()),
        "nvd_token_count": len(nvd_tokens),
        "ghsa_token_count": len(ghsa_tokens),
        "shared_token_count": len(shared_tokens),
        "shared_tokens": shared_tokens[:20],
        "suffix_token_count": len(suffix_tokens),
        "suffix_tokens": suffix_tokens[:20],
    }


def evidence_profile(row: dict) -> dict:
    status_counts = Counter()
    ok_hosts = Counter()
    ok_records = 0
    for record in row.get("evidence_context", {}).get("records", []):
        status = record.get("fetch_status") or "missing"
        status_counts[status] += 1
        if status == "ok":
            ok_records += 1
            ok_hosts[record.get("host") or ""] += 1
    return {
        "candidate_url_count": row.get("evidence_context", {}).get("candidate_url_count", 0),
        "ok_record_count": ok_records,
        "ok_host_count": len(ok_hosts),
        "fetch_status_counts": dict(sorted(status_counts.items())),
        "ok_hosts": dict(sorted(ok_hosts.items())),
    }


def combined_category(package_category: str, shape_category: str) -> str:
    if package_category == "no_package_name_overlap":
        return "package_mismatch"
    if shape_category in {
        "nvd_points_vs_ghsa_ranges",
        "ghsa_points_vs_nvd_ranges",
        "span_count_mismatch",
    }:
        return "version_shape_mismatch"
    return "aligned_or_minor_shape_difference"


def analyze(evidence_rows: dict[str, dict], silver_rows: dict[str, dict]) -> dict:
    if set(evidence_rows) != set(silver_rows):
        raise ValueError("Evidence and silver sample_id sets differ")

    counters = {
        "package_category": Counter(),
        "version_shape_category": Counter(),
        "combined_category": Counter(),
        "silver_label_by_combined_category": Counter(),
        "false_positive_by_combined_category": Counter(),
        "adjudicated_source_by_combined_category": Counter(),
        "token_overlap": Counter(),
        "suffix_tokens": Counter(),
        "evidence_ok_records": Counter(),
    }
    samples = []
    for sample_id in sorted(evidence_rows):
        row = evidence_rows[sample_id]
        silver = silver_rows[sample_id]["llm_annotation"]
        packages = package_profile(row)
        versions = version_profile(row)
        evidence = evidence_profile(row)
        combined = combined_category(packages["category"], versions["shape_category"])
        token_overlap_key = token_overlap_category(versions["shared_token_count"])
        suffix_key = "has_suffix_or_prerelease_tokens" if versions["suffix_token_count"] else "no_suffix_tokens"
        evidence_key = evidence_record_bin(evidence["ok_record_count"])

        counters["package_category"][packages["category"]] += 1
        counters["version_shape_category"][versions["shape_category"]] += 1
        counters["combined_category"][combined] += 1
        counters["silver_label_by_combined_category"][f"{combined}:{silver['llm_label']}"] += 1
        counters["false_positive_by_combined_category"][
            f"{combined}:{silver['is_baseline_false_positive']}"
        ] += 1
        counters["adjudicated_source_by_combined_category"][
            f"{combined}:{silver['adjudicated_source']}"
        ] += 1
        counters["token_overlap"][token_overlap_key] += 1
        counters["suffix_tokens"][suffix_key] += 1
        counters["evidence_ok_records"][evidence_key] += 1

        samples.append(
            {
                "sample_id": sample_id,
                "cve_id": row["cve_id"],
                "baseline_status": row.get("baseline_status"),
                "silver_label": silver["llm_label"],
                "silver_is_baseline_false_positive": silver["is_baseline_false_positive"],
                "silver_adjudicated_source": silver["adjudicated_source"],
                "silver_confidence": silver["confidence"],
                "package_profile": packages,
                "version_profile": versions,
                "evidence_profile": evidence,
                "combined_category": combined,
            }
        )

    return {
        "schema_version": 1,
        "task": "affected_versions_package_version_alignment_diagnostic",
        "silver_label_is_gold": False,
        "sample_count": len(samples),
        "cautions": [
            "This artifact characterizes package-name and version-shape alignment only.",
            "It is not a semantic version-range adjudicator and does not produce gold labels.",
            "Silver-label cross-tabs are diagnostic and must not be reported as human-gold accuracy.",
        ],
        "diagnostic_counts": {
            name: dict(sorted(counter.items())) for name, counter in counters.items()
        },
        "samples": samples,
    }


def token_overlap_category(count: int) -> str:
    if count == 0:
        return "no_shared_version_tokens"
    if count == 1:
        return "one_shared_version_token"
    return "multiple_shared_version_tokens"


def evidence_record_bin(count: int) -> str:
    if count == 0:
        return "0"
    if count <= 2:
        return "1-2"
    if count <= 5:
        return "3-5"
    return "6+"


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---", *["---:" for _ in headers[1:]]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def counter_rows(values: dict[str, int]) -> list[list[str]]:
    return [[key, str(value)] for key, value in values.items()]


def render_markdown(artifact: dict) -> str:
    counts = artifact["diagnostic_counts"]
    lines = [
        "# Affected Versions Alignment Diagnostic",
        "",
        "This artifact characterizes the 100 affected_versions silver-v2 samples. It is diagnostic only: no human-gold labels or semantic version-range adjudication are produced.",
        "",
        f"- Samples: `{artifact['sample_count']}`",
        f"- Silver labels are gold: `{artifact['silver_label_is_gold']}`",
        "",
        "## Package-name profile",
        "",
        table(["Profile", "Samples"], counter_rows(counts["package_category"])),
        "",
        "## Version-shape profile",
        "",
        table(["Profile", "Samples"], counter_rows(counts["version_shape_category"])),
        "",
        "## Combined diagnostic category",
        "",
        table(["Category", "Samples"], counter_rows(counts["combined_category"])),
        "",
        "## Token and evidence profile",
        "",
        table(["Version-token overlap", "Samples"], counter_rows(counts["token_overlap"])),
        "",
        table(["Suffix/prerelease tokens", "Samples"], counter_rows(counts["suffix_tokens"])),
        "",
        table(["OK evidence records", "Samples"], counter_rows(counts["evidence_ok_records"])),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    evidence_path = resolve_path(args.evidence_input)
    silver_path = resolve_path(args.silver_input)
    artifact = analyze(load_by_sample_id(evidence_path), load_by_sample_id(silver_path))
    artifact["source_paths"] = {
        "evidence_input": str(evidence_path),
        "silver_input": str(silver_path),
    }

    output_json = resolve_path(args.output_json)
    output_md = resolve_path(args.output_md)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output_md.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {output_json}")
    print(f"Wrote {output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
