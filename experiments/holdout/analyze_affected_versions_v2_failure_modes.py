#!/usr/bin/env python3
"""Analyze v2 type abstention and source-evidence dependence after unsealing."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
BASE = "data/annotations/holdout/affected_versions_v2"
DEFAULT_CONSENSUS = (
    "results/holdout/affected_versions_v2/affected_versions_holdout_v2_consensus.jsonl"
)
DEFAULT_TYPE_PREDICTIONS = (
    "results/holdout/affected_versions_v2/sealed_predictions/"
    "affected_versions_holdout_v2_type_predictions.jsonl"
)
DEFAULT_SOURCE_PREDICTIONS = (
    "results/holdout/affected_versions_v2/sealed_predictions/"
    "affected_versions_holdout_v2_source_predictions.jsonl"
)
DEFAULT_AGENT_A = f"{BASE}/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = f"{BASE}/agent_b_decisions.jsonl"
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v2/posthoc_failure_analysis"
TYPE_PRIMARY = "task_separated_type_v1"
SOURCE_PRIMARY = "branch_release_graph"
PRIMARY_OR_ECOSYSTEM_CLASSES = {
    "upstream_github_advisory",
    "ecosystem_advisory_database",
    "mailing_list_disclosure",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consensus", default=DEFAULT_CONSENSUS)
    parser.add_argument("--type-predictions", default=DEFAULT_TYPE_PREDICTIONS)
    parser.add_argument("--source-predictions", default=DEFAULT_SOURCE_PREDICTIONS)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def index_unique(rows: list[dict], key: str) -> dict[str, dict]:
    indexed = {}
    for row in rows:
        value = row.get(key)
        if not value or value in indexed:
            raise ValueError(f"missing or duplicate {key}: {value}")
        indexed[value] = row
    return indexed


def prediction_matrix(rows: list[dict]) -> dict[str, dict[str, dict]]:
    matrix: dict[str, dict[str, dict]] = {}
    for row in rows:
        sample_id = row.get("sample_id")
        method = row.get("method")
        if not sample_id or not method or method in matrix.setdefault(sample_id, {}):
            raise ValueError("invalid or duplicate prediction identity")
        matrix[sample_id][method] = row
    return matrix


def classify_evidence_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(":", 1)[0]
    path = parsed.path.lower()
    if host == "nvd.nist.gov":
        return "nvd_record"
    if host == "github.com" and "/security/advisories/" in path:
        return "upstream_github_advisory"
    if host == "github.com" and "/pypa/advisory-database/" in path:
        return "ecosystem_advisory_database"
    if host in {"openwall.com", "www.openwall.com"}:
        return "mailing_list_disclosure"
    if host == "devhub.checkmarx.com":
        return "secondary_aggregator"
    if host == "github.com":
        return "github_code_or_poc"
    return "other_web_evidence"


def cited_source_urls(decision: dict) -> set[str]:
    return {
        url
        for field in ("positive_support", "contradiction_or_scope_exclusion")
        for urls in decision[field].values()
        for url in urls
    }


def evidence_profile(left: dict, right: dict) -> dict:
    left_urls = cited_source_urls(left)
    right_urls = cited_source_urls(right)
    left_classes = {classify_evidence_url(url) for url in left_urls}
    right_classes = {classify_evidence_url(url) for url in right_urls}
    union_classes = left_classes | right_classes
    return {
        "agent_a_urls": sorted(left_urls),
        "agent_b_urls": sorted(right_urls),
        "agent_a_classes": sorted(left_classes),
        "agent_b_classes": sorted(right_classes),
        "same_exact_url_set": left_urls == right_urls,
        "same_single_url": left_urls == right_urls and len(left_urls) == 1,
        "only_nvd_record_collectively": union_classes == {"nvd_record"},
        "at_least_one_reviewer_has_primary_or_ecosystem_evidence": bool(
            union_classes & PRIMARY_OR_ECOSYSTEM_CLASSES
        ),
        "both_reviewers_have_primary_or_ecosystem_evidence": bool(
            left_classes & PRIMARY_OR_ECOSYSTEM_CLASSES
        )
        and bool(right_classes & PRIMARY_OR_ECOSYSTEM_CLASSES),
    }


def cross_tab(rows: list[dict], feature: str) -> dict[str, dict[str, int]]:
    values: dict[str, Counter] = {}
    for row in rows:
        values.setdefault(str(row[feature]), Counter()).update([row["gold_label"]])
    return {
        value: dict(sorted(counts.items()))
        for value, counts in sorted(values.items())
    }


def render_markdown(artifact: dict) -> str:
    type_summary = artifact["type_failure_analysis"]
    source_summary = artifact["source_evidence_analysis"]
    lines = [
        "# Affected-Versions V2 Post-hoc Failure Analysis",
        "",
        "This analysis was created after v2 unsealing. It uses non-human consensus labels and is not confirmatory or human-gold evidence.",
        "",
        "## Type endpoint",
        "",
        f"Strict type rows: {type_summary['strict_rows']}; primary determinate: {type_summary['primary_determinate']}; primary correct: {type_summary['primary_correct']}.",
        "",
        "Primary false abstentions by strict consensus label:",
        "",
        "| Label | Rows |",
        "|---|---:|",
    ]
    for label, count in type_summary["false_abstain_gold_counts"].items():
        lines.append(f"| {label} | {count} |")
    lines.extend(
        [
            "",
            "## Strict FC-source evidence dependence",
            "",
            f"Strict source rows: {source_summary['strict_source_rows']}.",
            f"Same single cited URL for both reviewers: {source_summary['same_single_url_rows']}.",
            f"Only NVD record evidence collectively: {source_summary['only_nvd_record_collectively_rows']}.",
            f"At least one reviewer cites primary/ecosystem evidence: {source_summary['at_least_one_primary_or_ecosystem_rows']}.",
            f"Both reviewers cite primary/ecosystem evidence: {source_summary['both_primary_or_ecosystem_rows']}.",
            "",
            "| Sample | Gold | Branch | Prefer NVD | Same single URL | Only NVD page | Any primary/ecosystem | Both primary/ecosystem |",
            "|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in source_summary["rows"]:
        lines.append(
            "| {sample_id} | {gold_source} | {branch_prediction} | {prefer_nvd_prediction} | "
            "{same_single_url} | {only_nvd} | {any_primary} | {both_primary} |".format(
                sample_id=row["sample_id"],
                gold_source=row["gold_source"],
                branch_prediction=row["branch_prediction"],
                prefer_nvd_prediction=row["prefer_nvd_prediction"],
                same_single_url=str(row["evidence_profile"]["same_single_url"]).lower(),
                only_nvd=str(
                    row["evidence_profile"]["only_nvd_record_collectively"]
                ).lower(),
                any_primary=str(
                    row["evidence_profile"][
                        "at_least_one_reviewer_has_primary_or_ecosystem_evidence"
                    ]
                ).lower(),
                both_primary=str(
                    row["evidence_profile"][
                        "both_reviewers_have_primary_or_ecosystem_evidence"
                    ]
                ).lower(),
            )
        )
    lines.extend(
        [
            "",
            "Reviewer independence does not imply evidence independence. A future source-label contract should distinguish source-owned database pages, upstream maintainer advisories, ecosystem databases, disclosures, and secondary aggregators before accepting a strict source label.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    consensus_path = resolve(args.consensus)
    type_path = resolve(args.type_predictions)
    source_path = resolve(args.source_predictions)
    agent_a_path = resolve(args.agent_a)
    agent_b_path = resolve(args.agent_b)
    output_dir = resolve(args.output_dir)

    consensus = load_jsonl(consensus_path)
    type_matrix = prediction_matrix(load_jsonl(type_path))
    source_matrix = prediction_matrix(load_jsonl(source_path))
    agent_a = index_unique(load_jsonl(agent_a_path), "sample_id")
    agent_b = index_unique(load_jsonl(agent_b_path), "sample_id")
    expected_ids = {row["sample_id"] for row in consensus}
    if not (
        set(type_matrix)
        == set(source_matrix)
        == set(agent_a)
        == set(agent_b)
        == expected_ids
    ):
        raise ValueError("input sample identities differ")

    strict_type_features = []
    for gold in consensus:
        if gold["type_consensus_status"] != "strict_determinate":
            continue
        prediction = type_matrix[gold["sample_id"]][TYPE_PRIMARY]
        detail = prediction["prediction_detail"]
        strict_type_features.append(
            {
                "sample_id": gold["sample_id"],
                "gold_label": gold["discrepancy_label"],
                "predicted_label": prediction["predicted_discrepancy_label"],
                "prediction_status": prediction["prediction_status"],
                "package_comparable": detail["package_profile"]["comparable"],
                "package_reason": detail["package_profile"].get("reason"),
                "legacy_relation": detail["legacy_range_profile"]["relation"],
                "structured_relation": detail["structured_range_profile"]["relation"],
                "has_boundary_contradiction": detail["boundary_contradiction_count"] > 0,
            }
        )
    false_abstains = [
        row for row in strict_type_features if row["prediction_status"] == "abstain"
    ]
    determinate = [
        row for row in strict_type_features if row["prediction_status"] == "determinate"
    ]
    type_analysis = {
        "strict_rows": len(strict_type_features),
        "primary_determinate": len(determinate),
        "primary_correct": sum(
            row["gold_label"] == row["predicted_label"] for row in determinate
        ),
        "false_abstain_rows": len(false_abstains),
        "false_abstain_gold_counts": dict(
            sorted(Counter(row["gold_label"] for row in false_abstains).items())
        ),
        "gold_by_package_comparable": cross_tab(
            strict_type_features, "package_comparable"
        ),
        "gold_by_legacy_relation": cross_tab(strict_type_features, "legacy_relation"),
        "gold_by_structured_relation": cross_tab(
            strict_type_features, "structured_relation"
        ),
        "gold_by_boundary_contradiction": cross_tab(
            strict_type_features, "has_boundary_contradiction"
        ),
        "rows": strict_type_features,
    }

    source_rows = []
    for gold in consensus:
        if gold["source_consensus_status"] != "strict_determinate":
            continue
        sample_id = gold["sample_id"]
        profile = evidence_profile(agent_a[sample_id], agent_b[sample_id])
        source_rows.append(
            {
                "sample_id": sample_id,
                "cve_id": gold["cve_id"],
                "gold_source": gold["adjudicated_source"],
                "branch_prediction": source_matrix[sample_id][SOURCE_PRIMARY][
                    "predicted_source"
                ],
                "prefer_nvd_prediction": source_matrix[sample_id]["prefer_nvd"][
                    "predicted_source"
                ],
                "evidence_profile": profile,
            }
        )
    source_analysis = {
        "strict_source_rows": len(source_rows),
        "same_exact_url_set_rows": sum(
            row["evidence_profile"]["same_exact_url_set"] for row in source_rows
        ),
        "same_single_url_rows": sum(
            row["evidence_profile"]["same_single_url"] for row in source_rows
        ),
        "only_nvd_record_collectively_rows": sum(
            row["evidence_profile"]["only_nvd_record_collectively"]
            for row in source_rows
        ),
        "at_least_one_primary_or_ecosystem_rows": sum(
            row["evidence_profile"][
                "at_least_one_reviewer_has_primary_or_ecosystem_evidence"
            ]
            for row in source_rows
        ),
        "both_primary_or_ecosystem_rows": sum(
            row["evidence_profile"][
                "both_reviewers_have_primary_or_ecosystem_evidence"
            ]
            for row in source_rows
        ),
        "branch_correct": sum(
            row["branch_prediction"] == row["gold_source"] for row in source_rows
        ),
        "prefer_nvd_correct": sum(
            row["prefer_nvd_prediction"] == row["gold_source"] for row in source_rows
        ),
        "rows": source_rows,
    }

    artifact = {
        "artifact_type": "affected_versions_v2_posthoc_failure_analysis",
        "analysis_is_posthoc": True,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "type_failure_analysis": type_analysis,
        "source_evidence_analysis": source_analysis,
        "inputs": {
            "consensus": {"path": str(consensus_path), "sha256": sha256(consensus_path)},
            "type_predictions": {"path": str(type_path), "sha256": sha256(type_path)},
            "source_predictions": {"path": str(source_path), "sha256": sha256(source_path)},
            "agent_a": {"path": str(agent_a_path), "sha256": sha256(agent_a_path)},
            "agent_b": {"path": str(agent_b_path), "sha256": sha256(agent_b_path)},
        },
        "cautions": [
            "The analysis was designed after v2 labels were unsealed.",
            "All target labels are strict dual-Codex candidates, not human gold.",
            "URL classes are deterministic provenance categories, not truth or authority scores.",
            "Any method designed from these rows requires a new disjoint cohort.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "affected_versions_v2_failure_analysis.json"
    md_path = output_dir / "affected_versions_v2_failure_analysis.md"
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
