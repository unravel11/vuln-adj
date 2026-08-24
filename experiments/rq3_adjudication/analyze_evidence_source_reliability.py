#!/usr/bin/env python3
"""Analyze RQ3 evidence-source availability and provenance.

This diagnostic characterizes fetched evidence by source class and whether a
URL came from NVD references, GHSA references, or both. It cross-tabs these
availability features with the existing silver-only baseline predictions, but
does not treat silver labels or source classes as human-gold truth.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEVERITY_EVIDENCE = (
    "data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl"
)
DEFAULT_AFFECTED_EVIDENCE = (
    "data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_SEVERITY_PREDICTIONS = (
    "results/rq3_adjudication/severity_silver_v2_predictions.jsonl"
)
DEFAULT_AFFECTED_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/rq3_adjudication"

BASELINE_METHODS = {
    "severity": "evidence_score_baseline",
    "affected_versions": "version_token_support_baseline",
}
SOURCE_CLASSES = (
    "nvd",
    "github_advisory",
    "github_commit_or_repo",
    "vendor_advisory",
    "package_registry",
    "mailing_list_issue_tracker",
    "other",
)
PROVENANCE_CLASSES = ("nvd_only", "ghsa_only", "shared", "unknown")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build RQ3 evidence source reliability diagnostics."
    )
    parser.add_argument("--severity-evidence", default=DEFAULT_SEVERITY_EVIDENCE)
    parser.add_argument("--affected-evidence", default=DEFAULT_AFFECTED_EVIDENCE)
    parser.add_argument("--severity-predictions", default=DEFAULT_SEVERITY_PREDICTIONS)
    parser.add_argument("--affected-predictions", default=DEFAULT_AFFECTED_PREDICTIONS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
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


def normalize_url(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip()
    parsed = urlparse(text)
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = re.sub(r"/+$", "", parsed.path)
    query = f"?{parsed.query}" if parsed.query else ""
    if scheme and host:
        return f"{scheme}://{host}{path}{query}"
    return text.rstrip("/")


def host_from_url(url: str) -> str:
    return urlparse(url).netloc.lower()


def source_class(url: str, host: str | None = None) -> str:
    host = (host or host_from_url(url)).lower()
    path = urlparse(url).path.lower()
    if host == "nvd.nist.gov":
        return "nvd"
    if host == "github.com":
        if "/security/advisories/" in path:
            return "github_advisory"
        return "github_commit_or_repo"
    if host in {
        "pypi.org",
        "npmjs.com",
        "www.npmjs.com",
        "rubygems.org",
        "packagist.org",
        "crates.io",
        "pkg.go.dev",
        "repo.maven.apache.org",
        "central.sonatype.com",
    }:
        return "package_registry"
    if any(
        marker in host
        for marker in (
            "bugzilla",
            "issues.",
            "jira",
            "lists.",
            "mail.",
            "openwall.com",
            "groups.google.com",
        )
    ):
        return "mailing_list_issue_tracker"
    if any(
        marker in path
        for marker in (
            "advisory",
            "advisories",
            "security",
            "vulnerability",
            "cve-",
            "apsb",
            "release",
        )
    ):
        return "vendor_advisory"
    return "other"


def provenance(url: str, nvd_refs: set[str], ghsa_refs: set[str]) -> str:
    normalized = normalize_url(url)
    in_nvd = normalized in nvd_refs
    in_ghsa = normalized in ghsa_refs
    if in_nvd and in_ghsa:
        return "shared"
    if in_nvd:
        return "nvd_only"
    if in_ghsa:
        return "ghsa_only"
    return "unknown"


def ok_record(record: dict) -> bool:
    return record.get("fetch_status") == "ok" and bool(record.get("text_snippet"))


def counter_to_dict(counter: Counter) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def rate(count: int, total: int) -> float:
    if not total:
        return 0.0
    return count / total


def classify_records(row: dict) -> list[dict]:
    nvd_refs = {
        normalize_url(url)
        for url in row.get("nvd_context", {}).get("references", [])
        if normalize_url(url)
    }
    ghsa_refs = {
        normalize_url(url)
        for url in row.get("ghsa_context", {}).get("references", [])
        if normalize_url(url)
    }
    records = []
    for record in row.get("evidence_context", {}).get("records", []):
        url = record.get("url") or ""
        host = record.get("host") or host_from_url(url)
        records.append(
            {
                "url": url,
                "host": host,
                "source_class": source_class(url, host),
                "provenance": provenance(url, nvd_refs, ghsa_refs),
                "fetch_status": record.get("fetch_status") or "missing",
                "has_text": bool(record.get("text_snippet")),
                "is_ok_text": ok_record(record),
            }
        )
    return records


def load_baseline_predictions(path: Path, method: str) -> dict[str, dict]:
    predictions = {}
    for row in iter_jsonl(path):
        if row.get("method") != method:
            continue
        sample_id = row["sample_id"]
        if sample_id in predictions:
            raise ValueError(f"Duplicate prediction for {method}: {sample_id}")
        predictions[sample_id] = row
    return predictions


def summarize_records(records: list[dict]) -> dict:
    total = len(records)
    ok = sum(1 for record in records if record["is_ok_text"])
    statuses = Counter(record["fetch_status"] for record in records)
    by_class: dict[str, Counter] = defaultdict(Counter)
    by_provenance: dict[str, Counter] = defaultdict(Counter)
    by_class_provenance: dict[tuple[str, str], Counter] = defaultdict(Counter)
    hosts = Counter()
    ok_hosts = Counter()

    for record in records:
        cls = record["source_class"]
        prov = record["provenance"]
        status = record["fetch_status"]
        by_class[cls]["records"] += 1
        by_class[cls][f"status:{status}"] += 1
        by_class[cls]["ok_text"] += int(record["is_ok_text"])
        by_provenance[prov]["records"] += 1
        by_provenance[prov][f"status:{status}"] += 1
        by_provenance[prov]["ok_text"] += int(record["is_ok_text"])
        by_class_provenance[(cls, prov)]["records"] += 1
        by_class_provenance[(cls, prov)]["ok_text"] += int(record["is_ok_text"])
        if record["host"]:
            hosts[record["host"]] += 1
            if record["is_ok_text"]:
                ok_hosts[record["host"]] += 1

    return {
        "record_count": total,
        "ok_text_records": ok,
        "ok_text_rate": rate(ok, total),
        "fetch_status_counts": counter_to_dict(statuses),
        "by_source_class": summarize_nested(by_class, SOURCE_CLASSES),
        "by_provenance": summarize_nested(by_provenance, PROVENANCE_CLASSES),
        "by_source_class_and_provenance": [
            {
                "source_class": cls,
                "provenance": prov,
                "records": values["records"],
                "ok_text_records": values["ok_text"],
                "ok_text_rate": rate(values["ok_text"], values["records"]),
            }
            for (cls, prov), values in sorted(by_class_provenance.items())
        ],
        "top_hosts": hosts.most_common(10),
        "top_ok_hosts": ok_hosts.most_common(10),
    }


def summarize_nested(
    by_group: dict[str, Counter], ordered_keys: tuple[str, ...]
) -> dict[str, dict]:
    output = {}
    for key in ordered_keys:
        values = by_group.get(key, Counter())
        records = values["records"]
        output[key] = {
            "records": records,
            "ok_text_records": values["ok_text"],
            "ok_text_rate": rate(values["ok_text"], records),
            "fetch_status_counts": {
                status_key.removeprefix("status:"): count
                for status_key, count in sorted(values.items())
                if status_key.startswith("status:")
            },
        }
    return output


def sample_feature_summary(records: list[dict]) -> dict:
    ok_classes = {
        record["source_class"] for record in records if record["is_ok_text"]
    }
    ok_provenance = {
        record["provenance"] for record in records if record["is_ok_text"]
    }
    candidate_classes = {record["source_class"] for record in records}
    return {
        "candidate_record_count": len(records),
        "ok_text_record_count": sum(1 for record in records if record["is_ok_text"]),
        "ok_source_classes": sorted(ok_classes),
        "ok_provenance": sorted(ok_provenance),
        "has_vendor_or_github_ok_text": bool(
            ok_classes
            & {"github_advisory", "github_commit_or_repo", "vendor_advisory"}
        ),
        "has_nvd_ok_text": "nvd" in ok_classes,
        "has_shared_ok_text": "shared" in ok_provenance,
        "candidate_source_classes": sorted(candidate_classes),
    }


def cross_tab_predictions(sample_features: dict[str, dict], predictions: dict[str, dict]) -> dict:
    bins = {
        "has_vendor_or_github_ok_text": Counter(),
        "has_nvd_ok_text": Counter(),
        "has_shared_ok_text": Counter(),
        "ok_text_record_count_bin": Counter(),
        "candidate_record_count_bin": Counter(),
    }
    by_predicted_source = Counter()
    error_by_predicted_source = Counter()
    missing_predictions = []
    for sample_id, features in sample_features.items():
        pred = predictions.get(sample_id)
        if not pred:
            missing_predictions.append(sample_id)
            continue
        is_error = not pred.get("is_correct")
        predicted_source = pred.get("predicted_source") or "missing"
        by_predicted_source[predicted_source] += 1
        error_by_predicted_source[predicted_source] += int(is_error)
        for feature in (
            "has_vendor_or_github_ok_text",
            "has_nvd_ok_text",
            "has_shared_ok_text",
        ):
            label = "yes" if features[feature] else "no"
            bins[feature][f"{label}:samples"] += 1
            bins[feature][f"{label}:errors"] += int(is_error)
        ok_bin = count_bin(features["ok_text_record_count"])
        candidate_bin = count_bin(features["candidate_record_count"])
        bins["ok_text_record_count_bin"][f"{ok_bin}:samples"] += 1
        bins["ok_text_record_count_bin"][f"{ok_bin}:errors"] += int(is_error)
        bins["candidate_record_count_bin"][f"{candidate_bin}:samples"] += 1
        bins["candidate_record_count_bin"][f"{candidate_bin}:errors"] += int(is_error)

    return {
        "prediction_count": len(predictions),
        "missing_prediction_sample_ids": missing_predictions[:10],
        "predicted_source_counts": counter_to_dict(by_predicted_source),
        "error_counts_by_predicted_source": counter_to_dict(error_by_predicted_source),
        "feature_bins": {
            feature: render_error_bins(counter)
            for feature, counter in bins.items()
        },
    }


def count_bin(count: int) -> str:
    if count == 0:
        return "0"
    if count == 1:
        return "1"
    if count <= 3:
        return "2-3"
    return "4+"


def render_error_bins(counter: Counter) -> list[dict]:
    labels = sorted({key.split(":", 1)[0] for key in counter})
    return [
        {
            "bin": label,
            "samples": counter[f"{label}:samples"],
            "silver_mismatches": counter[f"{label}:errors"],
            "silver_mismatch_rate": rate(
                counter[f"{label}:errors"], counter[f"{label}:samples"]
            ),
        }
        for label in labels
    ]


def analyze_field(
    field: str,
    evidence_path: Path,
    predictions_path: Path,
) -> dict:
    rows = list(iter_jsonl(evidence_path))
    predictions = load_baseline_predictions(predictions_path, BASELINE_METHODS[field])
    all_records = []
    sample_features = {}
    samples_without_ok_text = []
    ok_class_sets = Counter()
    ok_provenance_sets = Counter()

    for row in rows:
        records = classify_records(row)
        all_records.extend(records)
        features = sample_feature_summary(records)
        sample_features[row["sample_id"]] = features
        if not features["ok_text_record_count"]:
            samples_without_ok_text.append(row["sample_id"])
        ok_class_sets[",".join(features["ok_source_classes"]) or "none"] += 1
        ok_provenance_sets[",".join(features["ok_provenance"]) or "none"] += 1

    records_summary = summarize_records(all_records)
    samples_with_ok_text = sum(
        1 for features in sample_features.values() if features["ok_text_record_count"]
    )
    return {
        "field": field,
        "method_cross_tabbed": BASELINE_METHODS[field],
        "evidence_path": str(evidence_path),
        "predictions_path": str(predictions_path),
        "sample_count": len(rows),
        "silver_label_is_gold": False,
        "record_summary": records_summary,
        "sample_summary": {
            "samples_with_ok_text": samples_with_ok_text,
            "samples_with_ok_text_rate": rate(samples_with_ok_text, len(rows)),
            "samples_without_ok_text": samples_without_ok_text[:10],
            "ok_source_class_set_counts": counter_to_dict(ok_class_sets),
            "ok_provenance_set_counts": counter_to_dict(ok_provenance_sets),
        },
        "prediction_cross_tabs": cross_tab_predictions(sample_features, predictions),
    }


def render_markdown(summary: dict) -> str:
    lines = [
        "# RQ3 Evidence Source Reliability Diagnostic",
        "",
        "This artifact characterizes evidence URL provenance, fetch availability, and source classes. Cross-tabs use silver-only baseline predictions and are not human-gold correctness claims.",
        "",
    ]
    for field, field_summary in summary["fields"].items():
        record_summary = field_summary["record_summary"]
        sample_summary = field_summary["sample_summary"]
        lines.extend(
            [
                f"## {field}",
                "",
                f"- Samples: {field_summary['sample_count']}",
                f"- Evidence records: {record_summary['record_count']}",
                f"- OK text records: {record_summary['ok_text_records']}/{record_summary['record_count']} ({record_summary['ok_text_rate']:.1%})",
                f"- Samples with at least one OK text record: {sample_summary['samples_with_ok_text']}/{field_summary['sample_count']} ({sample_summary['samples_with_ok_text_rate']:.1%})",
                "",
                "Source classes:",
                "",
                table(
                    ["Class", "Records", "OK text", "OK rate"],
                    [
                        [
                            cls,
                            str(values["records"]),
                            str(values["ok_text_records"]),
                            f"{values['ok_text_rate']:.1%}",
                        ]
                        for cls, values in record_summary["by_source_class"].items()
                        if values["records"]
                    ],
                ),
                "",
                "Reference provenance:",
                "",
                table(
                    ["Provenance", "Records", "OK text", "OK rate"],
                    [
                        [
                            prov,
                            str(values["records"]),
                            str(values["ok_text_records"]),
                            f"{values['ok_text_rate']:.1%}",
                        ]
                        for prov, values in record_summary["by_provenance"].items()
                        if values["records"]
                    ],
                ),
                "",
                "Silver-only prediction cross-tab:",
                "",
                table(
                    ["Feature", "Bin", "Samples", "Silver mismatches", "Rate"],
                    [
                        [
                            feature,
                            item["bin"],
                            str(item["samples"]),
                            str(item["silver_mismatches"]),
                            f"{item['silver_mismatch_rate']:.1%}",
                        ]
                        for feature, bins in field_summary[
                            "prediction_cross_tabs"
                        ]["feature_bins"].items()
                        for item in bins
                    ],
                ),
                "",
            ]
        )
    lines.extend(
        [
            "Caution: source classes and silver-label cross-tabs characterize evidence availability and audit risk only. They do not establish source truth or adjudication correctness.",
            "",
        ]
    )
    return "\n".join(lines)


def table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] + ["---:" for _ in headers[1:]]) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    output_dir = resolve_path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "artifact": "rq3_evidence_source_reliability",
        "metric_scope": "evidence_availability_and_provenance_diagnostic_only",
        "silver_label_is_gold": False,
        "cautions": [
            "This diagnostic characterizes fetched evidence sources and provenance; it does not decide which source is correct.",
            "Prediction cross-tabs use evidence-aware LLM silver labels and are not human-gold error analysis.",
            "Source classes are heuristic host/path categories for audit planning.",
        ],
        "fields": {
            "severity": analyze_field(
                "severity",
                resolve_path(args.severity_evidence),
                resolve_path(args.severity_predictions),
            ),
            "affected_versions": analyze_field(
                "affected_versions",
                resolve_path(args.affected_evidence),
                resolve_path(args.affected_predictions),
            ),
        },
    }

    json_path = output_dir / "evidence_source_reliability.json"
    md_path = output_dir / "evidence_source_reliability.md"
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
