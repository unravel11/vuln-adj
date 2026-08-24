#!/usr/bin/env python3
"""Verify merged and evaluated snapshot-external dual-Codex results."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from evaluate_rq2_post_profile_snapshot import (  # noqa: E402
    METHODS,
    build_records,
    cluster_bootstrap,
    method_metrics,
    paired_profile_comparison,
    reviewer_agreement,
    safe_divide,
)
from merge_rq2_post_profile_reviews import (  # noqa: E402
    audit_request_log,
    cohen_kappa,
    load_unique,
    sha256,
)
from verify_rq2_post_profile_cohort import validate as verify_cohort  # noqa: E402


DEFAULT_BASE = "data/annotations/holdout/rq2_post_profile_snapshot_v1"
DEFAULT_REVIEW = "results/holdout/rq2_post_profile_snapshot_v1/review"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-dir", default=DEFAULT_BASE)
    parser.add_argument("--review-dir", default=DEFAULT_REVIEW)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def checked(record: dict, name: str) -> Path:
    path = resolve(record["path"])
    if not path.is_file() or sha256(path) != record.get("sha256"):
        raise ValueError(f"missing or hash-mismatched {name}: {path}")
    return path


def forbidden_gold_keys(value: object, prefix: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            lowered = str(key).lower()
            if lowered == "gold" or lowered.startswith("gold_") or lowered.endswith("_gold"):
                found.append(path)
            found.extend(forbidden_gold_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(forbidden_gold_keys(child, f"{prefix}[{index}]"))
    return found


def verify_merge(
    sealed: dict,
    sealed_path: Path,
    merge_manifest: dict,
    summary: dict,
    consensus_path: Path,
) -> None:
    if summary.get("artifact_type") != "rq2_post_profile_snapshot_dual_codex_review":
        raise ValueError("unexpected dual-review summary artifact")
    if summary.get("label_is_human") is not False:
        raise ValueError("dual-review summary must remain non-human")
    if summary.get("snapshot_external_is_time_confirmatory") is not False:
        raise ValueError("snapshot-external review cannot be time-confirmatory")
    consensus = list(load_unique(consensus_path).values())
    if len(consensus) != 250 or len({row["cve_id"] for row in consensus}) != 250:
        raise ValueError("dual-review consensus size drift")
    labels_a = [row["reviewer_a"]["discrepancy_label"] for row in consensus]
    labels_b = [row["reviewer_b"]["discrepancy_label"] for row in consensus]
    exact = sum(left == right for left, right in zip(labels_a, labels_b))
    strict = [row for row in consensus if row["strict_consensus"]]
    expected = {
        "rows": len(consensus),
        "unique_cves": len({row["cve_id"] for row in consensus}),
        "reviewer_a_label_counts": dict(sorted(Counter(labels_a).items())),
        "reviewer_b_label_counts": dict(sorted(Counter(labels_b).items())),
        "exact_label_agreement": exact,
        "exact_label_agreement_rate": exact / len(consensus),
        "cohen_kappa": cohen_kappa(labels_a, labels_b),
        "strict_consensus_rows": len(strict),
        "strict_consensus_coverage": len(strict) / len(consensus),
        "strict_label_counts": dict(
            sorted(Counter(row["consensus_label"] for row in strict).items())
        ),
    }
    for key, value in expected.items():
        if summary.get(key) != value:
            raise ValueError(f"dual-review summary drift for {key}")

    protocol = sealed["review_protocol"]
    execution = protocol["execution_contract"]
    log_a = audit_request_log(
        Path(protocol["reviewer_a_request_log"]),
        pass_id=protocol["reviewer_a_pass_id"],
        expected_samples={row["sample_id"] for row in consensus},
        execution=execution,
        input_hash=sealed["outputs"]["blind_worklist_a"]["sha256"],
        prompt_hash=sealed["inputs"]["prompt"]["sha256"],
        manifest_hash=sha256(sealed_path),
    )
    log_b = audit_request_log(
        Path(protocol["reviewer_b_request_log"]),
        pass_id=protocol["reviewer_b_pass_id"],
        expected_samples={row["sample_id"] for row in consensus},
        execution=execution,
        input_hash=sealed["outputs"]["blind_worklist_b"]["sha256"],
        prompt_hash=sealed["inputs"]["prompt"]["sha256"],
        manifest_hash=sha256(sealed_path),
    )
    for reviewer, audit in (("reviewer_a", log_a), ("reviewer_b", log_b)):
        expected_audit = {key: value for key, value in audit.items() if key != "session_ids"}
        if summary["request_log_audit"][reviewer] != expected_audit:
            raise ValueError(f"request-log audit drift for {reviewer}")
    if log_a["session_ids"] & log_b["session_ids"]:
        raise ValueError("reviewer execution sessions overlap")


def verify_evaluation(
    sealed: dict,
    merge_manifest: dict,
    result: dict,
) -> None:
    required_boundary = {
        "selected_tier": "snapshot_external",
        "snapshot_external_is_time_confirmatory": False,
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_method_gain_claim": False,
        "production_default_changed": False,
    }
    for key, value in required_boundary.items():
        if result.get(key) != value:
            raise ValueError(f"evaluation boundary drift for {key}")
    if result.get("label_source") != "selective_strict_dual_codex_expert_candidate_consensus":
        raise ValueError("evaluation label-source drift")
    if forbidden_gold_keys(result):
        raise ValueError(f"evaluation contains forbidden gold keys: {forbidden_gold_keys(result)[:5]}")

    source = load_unique(Path(sealed["outputs"]["source_rows"]["path"]))
    predictions = load_unique(Path(sealed["outputs"]["predictions"]["path"]))
    consensus = load_unique(Path(merge_manifest["outputs"]["consensus"]["path"]))
    records = build_records(source, predictions, consensus)
    strict_rows = sum(row["strict"] for row in records)
    differences = sum(len({row[method] for method in METHODS}) > 1 for row in records)
    expected_top = {
        "rows": len(records),
        "unique_cves": len({row["cve_id"] for row in records}),
        "strict_consensus_rows": strict_rows,
        "strict_consensus_coverage": safe_divide(strict_rows, len(records)),
        "candidate_profile_comparison_identifiable": differences > 0,
        "candidate_profile_prediction_difference_rows": differences,
    }
    for key, value in expected_top.items():
        if result.get(key) != value:
            raise ValueError(f"evaluation summary drift for {key}")
    for method in METHODS:
        observed = result["methods"][method]
        expected = {
            **method_metrics(records, method),
            "reviewer_a_determinate_agreement": reviewer_agreement(
                records, "reviewer_a", method
            ),
            "reviewer_b_determinate_agreement": reviewer_agreement(
                records, "reviewer_b", method
            ),
            "cve_cluster_bootstrap": cluster_bootstrap(
                records,
                method,
                observed["cve_cluster_bootstrap"]["replicates"],
                observed["cve_cluster_bootstrap"]["seed"],
            ),
        }
        if observed != expected:
            raise ValueError(f"evaluation metric drift for {method}")
        if method != "current":
            if result["paired_profile_comparisons"].get(method) != paired_profile_comparison(
                records, method
            ):
                raise ValueError(f"paired comparison drift for {method}")


def main() -> int:
    args = parse_args()
    base_dir = resolve(args.base_dir)
    review_dir = resolve(args.review_dir)
    sealed_path = base_dir / "manifest.sealed.json"
    merge_manifest_path = review_dir / "merge_manifest.json"
    evaluation_manifest_path = review_dir / "evaluation_manifest.json"
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    verify_cohort(sealed)
    merge_manifest = json.loads(merge_manifest_path.read_text(encoding="utf-8"))
    evaluation_manifest = json.loads(
        evaluation_manifest_path.read_text(encoding="utf-8")
    )
    if merge_manifest.get("artifact_type") != "rq2_post_profile_snapshot_merge_manifest":
        raise ValueError("unexpected merge manifest")
    if evaluation_manifest.get("artifact_type") != "rq2_post_profile_snapshot_evaluation_manifest":
        raise ValueError("unexpected evaluation manifest")
    merge_inputs = {
        name: checked(record, f"merge.inputs.{name}")
        for name, record in merge_manifest["inputs"].items()
    }
    merge_outputs = {
        name: checked(record, f"merge.outputs.{name}")
        for name, record in merge_manifest["outputs"].items()
    }
    for name, record in evaluation_manifest["inputs"].items():
        checked(record, f"evaluation.inputs.{name}")
    evaluation_outputs = {
        name: checked(record, f"evaluation.outputs.{name}")
        for name, record in evaluation_manifest["outputs"].items()
    }
    summary = json.loads(merge_outputs["summary"].read_text(encoding="utf-8"))
    result = json.loads(evaluation_outputs["json"].read_text(encoding="utf-8"))
    verify_merge(sealed, sealed_path, merge_manifest, summary, merge_outputs["consensus"])
    verify_evaluation(sealed, merge_manifest, result)
    print(
        "Verified post-profile results: "
        f"rows={result['rows']} strict={result['strict_consensus_rows']} "
        f"differences={result['candidate_profile_prediction_difference_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
