#!/usr/bin/env python3
"""Validate two evidence-enhanced CWE reviews and merge the 17-row candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from merge_cwe_taxonomy_impact_holdout import (
    component_summary,
    evaluate_subset,
    iter_jsonl,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = (
    "results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit"
)
DEFAULT_MANIFEST = f"{DEFAULT_DIR}/cwe_taxonomy_evidence_secondary_manifest.sealed.json"
DEFAULT_AGENT_C = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_evidence_agent_c.jsonl"
)
DEFAULT_AGENT_D = (
    "data/annotations/expert_candidate/batches/"
    "rq2_cwe_taxonomy_evidence_agent_d.jsonl"
)
OUTPUT_KEYS = {
    "reviewer_id",
    "run_id",
    "review_id",
    "cve_id",
    "set_relation",
    "discrepancy_label",
    "taxonomy_support_verdict",
    "specific_mapping_verdict",
    "confidence",
    "needs_additional_review",
    "rationale",
    "supporting_cwe_paths",
    "supporting_evidence",
}
LABEL_VERDICT = {
    "representation_discrepancy": (
        "supports_granularity_only",
        "same_mechanism_supported",
    ),
    "factual_conflict": (
        "does_not_support_granularity_only",
        "materially_different_or_contradicted",
    ),
    "uncertain": ("insufficient", "insufficient"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--agent-c", default=DEFAULT_AGENT_C)
    parser.add_argument("--agent-d", default=DEFAULT_AGENT_D)
    parser.add_argument("--output-dir", default=DEFAULT_DIR)
    return parser.parse_args()


def resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def allowed_paths(source: dict) -> set[str]:
    result = set()
    for relation in source["official_cross_source_ancestor_descendant_paths"]:
        path = relation["path"]
        result.add(">".join(item["cwe_id"] for item in path))
        result.add(">".join(item["cwe_id"] for item in reversed(path)))
    return result


def evidence_by_url(source: dict) -> dict[str, str]:
    result = {}
    for record in source["evidence_context"]["records"]:
        if record.get("fetch_status") == "ok" and record.get("text_snippet"):
            result[record["source_url"]] = record["text_snippet"]
    return result


def validate_reviews(
    path: Path,
    worklist: list[dict],
    expected_reviewer_id: str,
) -> list[dict]:
    reviews = list(iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(f"review row count mismatch: {len(reviews)} != {len(worklist)}")
    run_ids = set()
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != OUTPUT_KEYS:
            raise ValueError(f"schema mismatch at {path}:{index}")
        if review["reviewer_id"] != expected_reviewer_id:
            raise ValueError(f"reviewer identity mismatch at {path}:{index}")
        if not isinstance(review["run_id"], str) or not review["run_id"].strip():
            raise ValueError(f"blank run_id at {path}:{index}")
        run_ids.add(review["run_id"])
        for key in ("review_id", "cve_id"):
            if review[key] != source[key]:
                raise ValueError(f"identity mismatch at {path}:{index} for {key}")
        contract = source["review_contract"]
        for key in (
            "set_relation",
            "discrepancy_label",
            "taxonomy_support_verdict",
            "specific_mapping_verdict",
            "confidence",
        ):
            if review[key] not in contract[key]:
                raise ValueError(f"invalid {key} at {path}:{index}")
        expected_support, expected_mapping = LABEL_VERDICT[review["discrepancy_label"]]
        if review["taxonomy_support_verdict"] != expected_support:
            raise ValueError(f"label/support mismatch at {path}:{index}")
        if review["specific_mapping_verdict"] != expected_mapping:
            raise ValueError(f"label/mapping mismatch at {path}:{index}")
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(f"needs_additional_review must be boolean at {path}:{index}")
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"low confidence must request review at {path}:{index}")
        if review["discrepancy_label"] == "uncertain" and (
            review["confidence"] != "low" or not review["needs_additional_review"]
        ):
            raise ValueError(f"uncertain row must be low/review at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(review["rationale"].strip()) < 120:
            raise ValueError(f"rationale too short at {path}:{index}")

        paths = review["supporting_cwe_paths"]
        if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
            raise ValueError(f"supporting_cwe_paths must be a string list at {path}:{index}")
        if len(paths) != len(set(paths)) or set(paths) - allowed_paths(source):
            raise ValueError(f"invalid supporting CWE path at {path}:{index}")
        if review["taxonomy_support_verdict"] == "supports_granularity_only" and not paths:
            raise ValueError(f"granularity support requires a path at {path}:{index}")

        citations = review["supporting_evidence"]
        if not isinstance(citations, list):
            raise ValueError(f"supporting_evidence must be a list at {path}:{index}")
        if review["discrepancy_label"] != "uncertain" and not citations:
            raise ValueError(f"determinate label requires evidence at {path}:{index}")
        available = evidence_by_url(source)
        seen = set()
        for citation in citations:
            if not isinstance(citation, dict) or set(citation) != {"url", "quote"}:
                raise ValueError(f"invalid evidence citation schema at {path}:{index}")
            url = citation["url"]
            quote = citation["quote"]
            if url not in available:
                raise ValueError(f"unknown evidence URL at {path}:{index}")
            if not isinstance(quote, str) or not 20 <= len(quote) <= 280:
                raise ValueError(f"invalid evidence quote length at {path}:{index}")
            if quote not in available[url]:
                raise ValueError(f"evidence quote is not literal at {path}:{index}")
            marker = (url, quote)
            if marker in seen:
                raise ValueError(f"duplicate evidence citation at {path}:{index}")
            seen.add(marker)
    if len(run_ids) != 1:
        raise ValueError(f"expected one run_id in {path}")
    return reviews


def strict_secondary(left: dict, right: dict) -> tuple[bool, str | None]:
    keys = (
        "set_relation",
        "discrepancy_label",
        "taxonomy_support_verdict",
        "specific_mapping_verdict",
    )
    agreement = all(left[key] == right[key] for key in keys)
    strict = (
        agreement
        and left["discrepancy_label"] != "uncertain"
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    return strict, left["discrepancy_label"] if strict else None


def combine_candidates(
    stage1_rows: list[dict],
    target_ids: set[str],
    secondary_by_id: dict[str, dict],
) -> list[dict]:
    combined = []
    for stage1 in stage1_rows:
        review_id = stage1["review_id"]
        if review_id in target_ids:
            secondary = secondary_by_id[review_id]
            strict = secondary["strict_consensus"]
            label = secondary["consensus_label"]
            source = "stage2_evidence_strict" if strict else "unresolved_after_stage2"
        else:
            strict = stage1["strict_consensus"]
            label = stage1["consensus_label"] if strict else None
            source = "stage1_strict" if strict else "unresolved_after_stage1"
        combined.append(
            {
                "review_id": review_id,
                "cve_id": stage1["cve_id"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "requires_human_signoff": True,
                "strict_consensus": strict,
                "consensus_label": label,
                "consensus_source": source,
                "primary_seed_overlap": stage1["primary_seed_overlap"],
                "current_prediction": stage1["current_prediction"],
                "taxonomy_v1_prediction": stage1["taxonomy_v1_prediction"],
                "stage1": stage1,
                "stage2": secondary_by_id.get(review_id),
            }
        )
    return combined


def render_markdown(summary: dict) -> str:
    combined = summary["combined_strict_evaluation"]
    disjoint = summary["combined_primary_seed_disjoint_evaluation"]
    lines = [
        "# CWE Taxonomy Evidence-Enhanced Secondary Audit",
        "",
        "This is a sealed non-human secondary audit over nine priority rows. It is not human gold.",
        "",
        f"Secondary strict consensus: `{summary['secondary_strict_rows']}/9`.",
        f"Combined strict consensus: `{summary['combined_strict_rows']}/17`.",
        "",
        "| Subset | Method | Correct/rows | Accuracy |",
        "|---|---|---:|---:|",
    ]
    for name, values in (("combined strict", combined), ("seed-disjoint", disjoint)):
        for method in ("current", "taxonomy_v1"):
            metric = values[method]
            lines.append(
                f"| {name} | {method} | {metric['correct']}/{metric['rows']} | {metric['accuracy']:.4f} |"
            )
    lines.extend(
        [
            "",
            f"Seed-disjoint paired delta: `{disjoint['taxonomy_minus_current_accuracy']:.4f}`; "
            f"95% row-bootstrap interval: `{disjoint['paired_diagnostic']['accuracy_delta_percentile_95_interval']}`; "
            f"exact sign diagnostic `p={disjoint['paired_diagnostic']['exact_two_sided_sign_test_p']:.4f}`.",
            "",
            "Production default changed: `false`. Real-human signed rows: `0`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    agent_c_path = resolve(args.agent_c)
    agent_d_path = resolve(args.agent_d)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["row_count"] != 9 or not manifest["reviewer_outputs_absent_at_seal"]:
        raise ValueError("invalid secondary manifest")

    worklist_path = Path(manifest["worklist"]["path"])
    if sha256(worklist_path) != manifest["worklist"]["sha256"]:
        raise ValueError("secondary worklist hash mismatch")
    for item in manifest["inputs"].values():
        if sha256(Path(item["path"])) != item["sha256"]:
            raise ValueError(f"sealed input hash mismatch: {item['path']}")
    if sha256(Path(manifest["code"]["path"])) != manifest["code"]["sha256"]:
        raise ValueError("secondary builder code hash mismatch")
    if agent_c_path.resolve() == agent_d_path.resolve():
        raise ValueError("secondary reviewer paths must differ")
    if not agent_c_path.exists() or not agent_d_path.exists():
        raise ValueError("both secondary reviewer outputs are required")
    if agent_c_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent C output predates secondary seal")
    if agent_d_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent D output predates secondary seal")
    if sha256(agent_c_path) == sha256(agent_d_path):
        raise ValueError("secondary reviewer outputs must not be identical")

    worklist = list(iter_jsonl(worklist_path))
    agent_c = validate_reviews(agent_c_path, worklist, "codex_cwe_evidence_c")
    agent_d = validate_reviews(agent_d_path, worklist, "codex_cwe_evidence_d")
    if agent_c[0]["run_id"] == agent_d[0]["run_id"]:
        raise ValueError("secondary reviewer run IDs must differ")

    secondary = []
    for source, left, right in zip(worklist, agent_c, agent_d):
        strict, label = strict_secondary(left, right)
        secondary.append(
            {
                "review_id": source["review_id"],
                "cve_id": source["cve_id"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_label": label,
                "agent_c": left,
                "agent_d": right,
            }
        )
    secondary_by_id = {row["review_id"]: row for row in secondary}
    stage1_path = Path(manifest["inputs"]["stage1_candidate"]["path"])
    stage1_rows = list(iter_jsonl(stage1_path))
    target_ids = {row["review_id"] for row in worklist}
    combined = combine_candidates(stage1_rows, target_ids, secondary_by_id)
    strict_rows = [row for row in combined if row["strict_consensus"]]
    disjoint_rows = [row for row in strict_rows if not row["primary_seed_overlap"]]
    strict_eval = evaluate_subset(strict_rows)
    disjoint_eval = evaluate_subset(disjoint_rows)

    secondary_strict = [row for row in secondary if row["strict_consensus"]]
    summary = {
        "artifact_type": "rq2_cwe_taxonomy_evidence_secondary_audit",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "sealed_before_reviews": True,
        "same_model_family_separate_runs": True,
        "secondary_rows": len(secondary),
        "secondary_strict_rows": len(secondary_strict),
        "secondary_component_agreement": {
            key: component_summary(agent_c, agent_d, key)
            for key in (
                "set_relation",
                "discrepancy_label",
                "taxonomy_support_verdict",
                "specific_mapping_verdict",
                "confidence",
                "needs_additional_review",
            )
        },
        "secondary_label_counts": dict(
            sorted(Counter(row["consensus_label"] for row in secondary_strict).items())
        ),
        "combined_strict_rows": len(strict_rows),
        "combined_strict_coverage": len(strict_rows) / len(combined),
        "combined_consensus_source_counts": dict(
            sorted(Counter(row["consensus_source"] for row in combined).items())
        ),
        "combined_strict_evaluation": strict_eval,
        "combined_primary_seed_disjoint_evaluation": disjoint_eval,
        "method_selection": {
            "status": "nonhuman_evidence_enhanced_development_diagnostic",
            "production_default_changed": False,
            "requires_real_human_signoff": True,
        },
        "human_signed_rows": 0,
        "inputs": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "agent_c": str(agent_c_path),
            "agent_c_sha256": sha256(agent_c_path),
            "agent_d": str(agent_d_path),
            "agent_d_sha256": sha256(agent_d_path),
        },
        "cautions": [
            "The nine secondary rows were selected after stage-one disagreement or regression.",
            "Frozen evidence availability is uneven and does not imply source independence.",
            "Both secondary reviewers are Codex runs, not real humans.",
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    secondary_path = output_dir / "cwe_taxonomy_evidence_secondary_candidate.jsonl"
    combined_path = output_dir / "cwe_taxonomy_evidence_combined_candidate.jsonl"
    json_path = output_dir / "cwe_taxonomy_evidence_secondary_audit.json"
    md_path = output_dir / "cwe_taxonomy_evidence_secondary_audit.md"
    for path, rows in ((secondary_path, secondary), (combined_path, combined)):
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    json_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {secondary_path}")
    print(f"Wrote {combined_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
