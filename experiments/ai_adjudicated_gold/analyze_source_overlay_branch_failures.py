#!/usr/bin/env python3
"""Diagnose branch-graph errors on strict source re-audit additions."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RQ3_DIR = PROJECT_ROOT / "experiments" / "rq3_adjudication"
if str(RQ3_DIR) not in sys.path:
    sys.path.insert(0, str(RQ3_DIR))

from affected_versions_semantic_baseline import (  # noqa: E402
    package_profile,
    range_relation,
    repository_crosswalk_package_profile,
)


DEFAULT_OVERLAY = (
    "results/ai_adjudicated_gold/source_reaudit/"
    "rq3_affected_versions_source_gold_overlay.jsonl"
)
DEFAULT_EVIDENCE = (
    "data/annotations/rq3/silver_v2/"
    "affected_versions_fc_manual_check.evidence.jsonl"
)
DEFAULT_BRANCH = (
    "results/rq3_adjudication/branch_graph/"
    "affected_versions_branch_graph_features.jsonl"
)
DEFAULT_RELEASE = (
    "results/rq3_adjudication/release_boundary/"
    "affected_versions_release_boundary_features.jsonl"
)
DEFAULT_PREDICTIONS = (
    "results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl"
)
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit"
REFERENCE_METHOD = "canonical_version_token_support_baseline"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--overlay", default=DEFAULT_OVERLAY)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--branch-features", default=DEFAULT_BRANCH)
    parser.add_argument("--release-features", default=DEFAULT_RELEASE)
    parser.add_argument("--predictions", default=DEFAULT_PREDICTIONS)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def resolve(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(
                    f"{path}:{line_number}: missing or duplicate sample_id"
                )
            rows[sample_id] = row
    return rows


def canonical_predictions(path: Path) -> dict[str, str]:
    values = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("method") == REFERENCE_METHOD:
                values[row["sample_id"]] = row["predicted_source"]
    return values


def render_markdown(artifact: dict) -> str:
    lines = [
        "# Branch-graph failures on strict source re-audit additions",
        "",
        "This is an AI-provenance failure analysis, not human-gold validation.",
        "",
        "| Sample | CVE | Gold | Canonical | Release | Branch | Direct package profile | Crosswalk comparable |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in artifact["rows"]:
        lines.append(
            f"| `{row['sample_id']}` | {row['cve_id']} | `{row['gold_source']}` | "
            f"`{row['canonical_prediction']}` | `{row['release_prediction']}` | "
            f"`{row['branch_prediction']}` | `{row['direct_package_category']}` | "
            f"`{str(row['crosswalk_comparable']).lower()}` |"
        )
    lines.extend(
        [
            "",
            "All added rows use different source package/product identifiers. Boundary events currently compare version tokens across those artifact scopes, which can create false bilateral contradictions. The required capability is evidence-bound artifact identity plus separate source-specific release graphs, not a sample-specific version exception.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    overlay_path = resolve(args.overlay)
    evidence_path = resolve(args.evidence)
    branch_path = resolve(args.branch_features)
    release_path = resolve(args.release_features)
    prediction_path = resolve(args.predictions)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    overlay = load_jsonl(overlay_path)
    evidence = load_jsonl(evidence_path)
    branch = load_jsonl(branch_path)
    release = load_jsonl(release_path)
    canonical = canonical_predictions(prediction_path)
    if not (
        set(overlay) == set(evidence) == set(branch) == set(release) == set(canonical)
    ):
        raise ValueError("all inputs must cover the same 100 sample IDs")

    added_ids = sorted(
        sample_id
        for sample_id, row in overlay.items()
        if row.get("source_decision_origin") == "dual_agent_strict_source_reaudit"
    )
    diagnostics = []
    event_counts = Counter()
    for sample_id in added_ids:
        source = evidence[sample_id]
        direct = package_profile(source)
        crosswalk = repository_crosswalk_package_profile(source)
        branch_row = branch[sample_id]
        source_events = {}
        for source_name in ("nvd", "ghsa"):
            support = Counter(
                event["kind"]
                for event in branch_row["source_profiles"][source_name][
                    "support_events"
                ]
            )
            contradiction = Counter(
                event["kind"]
                for event in branch_row["source_profiles"][source_name][
                    "contradiction_events"
                ]
            )
            event_counts.update(
                {f"{source_name}.support.{key}": value for key, value in support.items()}
            )
            event_counts.update(
                {
                    f"{source_name}.contradiction.{key}": value
                    for key, value in contradiction.items()
                }
            )
            source_events[source_name] = {
                "support_event_counts": dict(sorted(support.items())),
                "contradiction_event_counts": dict(sorted(contradiction.items())),
            }
        diagnostics.append(
            {
                "sample_id": sample_id,
                "cve_id": source.get("cve_id"),
                "gold_source": overlay[sample_id]["source_gold_label"],
                "canonical_prediction": canonical[sample_id],
                "release_prediction": release[sample_id]["predicted_source"],
                "branch_prediction": branch_row["predicted_source"],
                "direct_package_category": direct["category"],
                "nvd_package_names": direct["nvd_package_names"],
                "ghsa_package_names": direct["ghsa_package_names"],
                "crosswalk_category": crosswalk["category"],
                "crosswalk_comparable": crosswalk["comparable"],
                "range_relation": range_relation(source)["relation"],
                "source_events": source_events,
            }
        )

    artifact = {
        "artifact_type": "source_overlay_branch_failure_analysis",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "inputs": {
            "overlay": {"path": str(overlay_path), "sha256": sha256(overlay_path)},
            "evidence": {
                "path": str(evidence_path),
                "sha256": sha256(evidence_path),
            },
            "branch_features": {
                "path": str(branch_path),
                "sha256": sha256(branch_path),
            },
            "release_features": {
                "path": str(release_path),
                "sha256": sha256(release_path),
            },
            "predictions": {
                "path": str(prediction_path),
                "sha256": sha256(prediction_path),
            },
        },
        "added_rows": len(diagnostics),
        "gold_source_counts": dict(
            sorted(Counter(row["gold_source"] for row in diagnostics).items())
        ),
        "direct_package_category_counts": dict(
            sorted(
                Counter(row["direct_package_category"] for row in diagnostics).items()
            )
        ),
        "crosswalk_comparable_count": sum(
            row["crosswalk_comparable"] for row in diagnostics
        ),
        "canonical_correct": sum(
            row["canonical_prediction"] == row["gold_source"] for row in diagnostics
        ),
        "release_correct": sum(
            row["release_prediction"] == row["gold_source"] for row in diagnostics
        ),
        "branch_correct": sum(
            row["branch_prediction"] == row["gold_source"] for row in diagnostics
        ),
        "aggregate_branch_event_counts": dict(sorted(event_counts.items())),
        "required_capability": (
            "Bind evidence and release graphs to artifact identity; do not apply "
            "cross-artifact interval contradiction merely because records share a CVE "
            "or repository."
        ),
        "rows": diagnostics,
        "caution": (
            "This diagnosis follows inspection of the added labels and is post-hoc. "
            "It defines a future method requirement, not a validated v2 rule."
        ),
    }
    json_path = output_dir / "affected_versions_source_overlay_branch_failures.json"
    md_path = output_dir / "affected_versions_source_overlay_branch_failures.md"
    json_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(artifact), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
