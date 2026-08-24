#!/usr/bin/env python3
"""Validate two sealed reference-identity reviews and merge the 56-row impact set."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = (
    "results/rq2_discrepancy_typing/reference_normalization_impact_validation"
)
DEFAULT_MANIFEST = (
    f"{DEFAULT_DIR}/reference_normalization_impact_manifest.sealed.json"
)
DEFAULT_AGENT_E = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_identity_agent_e.jsonl"
)
DEFAULT_AGENT_F = (
    "data/annotations/expert_candidate/batches/"
    "rq2_reference_identity_agent_f.jsonl"
)
OUTPUT_KEYS = {
    "reviewer_id",
    "run_id",
    "review_id",
    "cve_id",
    "identity_verdict",
    "final_status",
    "confidence",
    "needs_additional_review",
    "rationale",
    "group_decisions",
}
VERDICT_STATUS = {
    "all_aliases_same_resource": "incomplete",
    "one_or_more_not_same": "representation_discrepancy",
    "insufficient": "uncertain",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--agent-e", default=DEFAULT_AGENT_E)
    parser.add_argument("--agent-f", default=DEFAULT_AGENT_F)
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


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def validate_reviews(
    path: Path,
    worklist: list[dict],
    expected_reviewer_id: str,
    expected_run_id: str | None = None,
) -> list[dict]:
    reviews = list(iter_jsonl(path))
    if len(reviews) != len(worklist):
        raise ValueError(
            f"review row count mismatch: {len(reviews)} != {len(worklist)}"
        )
    run_ids = set()
    for index, (review, source) in enumerate(zip(reviews, worklist), start=1):
        if set(review) != OUTPUT_KEYS:
            raise ValueError(f"schema mismatch at {path}:{index}")
        if review["reviewer_id"] != expected_reviewer_id:
            raise ValueError(f"reviewer identity mismatch at {path}:{index}")
        if not isinstance(review["run_id"], str) or not review["run_id"].strip():
            raise ValueError(f"blank run_id at {path}:{index}")
        run_ids.add(review["run_id"])
        if expected_run_id is not None and review["run_id"] != expected_run_id:
            raise ValueError(f"run identity mismatch at {path}:{index}")
        for key in ("review_id", "cve_id"):
            if review[key] != source[key]:
                raise ValueError(f"identity mismatch at {path}:{index} for {key}")

        contract = source["review_contract"]
        for key in ("identity_verdict", "final_status", "confidence"):
            if review[key] not in contract[key]:
                raise ValueError(f"invalid {key} at {path}:{index}")
        expected_status = VERDICT_STATUS[review["identity_verdict"]]
        if review["final_status"] != expected_status:
            raise ValueError(f"verdict/status mismatch at {path}:{index}")
        if not isinstance(review["needs_additional_review"], bool):
            raise ValueError(
                f"needs_additional_review must be boolean at {path}:{index}"
            )
        if review["confidence"] == "low" and not review["needs_additional_review"]:
            raise ValueError(f"low confidence must request review at {path}:{index}")
        if review["identity_verdict"] == "insufficient" and (
            review["confidence"] != "low"
            or not review["needs_additional_review"]
        ):
            raise ValueError(f"insufficient row must be low/review at {path}:{index}")
        if not isinstance(review["rationale"], str) or len(
            review["rationale"].strip()
        ) < 120:
            raise ValueError(f"rationale too short at {path}:{index}")

        decisions = review["group_decisions"]
        groups = source["identity_groups"]
        if not isinstance(decisions, list) or len(decisions) != len(groups):
            raise ValueError(f"group decision count mismatch at {path}:{index}")
        values = []
        for group_index, (decision, group) in enumerate(
            zip(decisions, groups), start=1
        ):
            if not isinstance(decision, dict) or set(decision) != {
                "group_id",
                "same_resource",
                "reason",
            }:
                raise ValueError(
                    f"group decision schema mismatch at {path}:{index}:{group_index}"
                )
            if decision["group_id"] != group["group_id"]:
                raise ValueError(
                    f"group identity mismatch at {path}:{index}:{group_index}"
                )
            value = decision["same_resource"]
            if value is not True and value is not False and value is not None:
                raise ValueError(
                    f"invalid same_resource at {path}:{index}:{group_index}"
                )
            if not isinstance(decision["reason"], str) or len(
                decision["reason"].strip()
            ) < 40:
                raise ValueError(
                    f"group reason too short at {path}:{index}:{group_index}"
                )
            values.append(value)

        verdict = review["identity_verdict"]
        if verdict == "all_aliases_same_resource" and not all(
            value is True for value in values
        ):
            raise ValueError(f"all-alias verdict requires all true at {path}:{index}")
        if verdict == "one_or_more_not_same" and not any(
            value is False for value in values
        ):
            raise ValueError(f"not-same verdict requires false at {path}:{index}")
        if verdict == "insufficient" and (
            any(value is False for value in values)
            or not any(value is None for value in values)
        ):
            raise ValueError(
                f"insufficient verdict requires null and no false at {path}:{index}"
            )
    if reviews and len(run_ids) != 1:
        raise ValueError(f"expected one run_id in {path}")
    return reviews


def strict_secondary(left: dict, right: dict) -> tuple[bool, str | None]:
    same_groups = [
        decision["same_resource"] for decision in left["group_decisions"]
    ] == [decision["same_resource"] for decision in right["group_decisions"]]
    agreement = (
        left["identity_verdict"] == right["identity_verdict"]
        and left["final_status"] == right["final_status"]
        and same_groups
    )
    strict = (
        agreement
        and left["identity_verdict"] != "insufficient"
        and not left["needs_additional_review"]
        and not right["needs_additional_review"]
    )
    return strict, left["final_status"] if strict else None


def agreement_summary(left: list[dict], right: list[dict], key: str) -> dict:
    pairs = [(a[key], b[key]) for a, b in zip(left, right)]
    count = sum(a == b for a, b in pairs)
    labels = sorted({value for pair in pairs for value in pair})
    observed = count / len(pairs) if pairs else 0.0
    left_counts = Counter(a for a, _ in pairs)
    right_counts = Counter(b for _, b in pairs)
    expected = (
        sum(left_counts[label] * right_counts[label] for label in labels)
        / (len(pairs) ** 2)
        if pairs
        else 0.0
    )
    kappa = (
        (observed - expected) / (1 - expected)
        if pairs and expected < 1
        else None
    )
    return {
        "agreement_count": count,
        "row_count": len(pairs),
        "agreement_rate": observed,
        "cohen_kappa": kappa,
        "cohen_kappa_status": (
            "defined" if kappa is not None else "undefined_single_class_marginals"
        ),
    }


def combine_rows(
    validation_rows: list[dict], secondary_rows: list[dict]
) -> list[dict]:
    secondary_by_id = {row["review_id"]: row for row in secondary_rows}
    combined = []
    for row in validation_rows:
        secondary = secondary_by_id.get(row["review_id"])
        if secondary and secondary["strict_consensus"]:
            resolved = True
            final_status = secondary["consensus_status"]
            source = "sealed_transformation_masked_dual_evidence_review"
        else:
            resolved = False
            final_status = None
            source = "unresolved_after_evidence_review"
        combined.append(
            {
                "review_id": row["review_id"],
                "cve_id": row["cve_id"],
                "field": "references",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "requires_human_signoff": True,
                "resolved_nonhuman": resolved,
                "candidate_incomplete_supported": final_status == "incomplete",
                "resolved_status": final_status,
                "consensus_source": source,
                "automatic_validation": row,
                "secondary_review": secondary,
            }
        )
    return combined


def render_markdown(summary: dict) -> str:
    counts = summary["combined_resolved_status_counts"]
    return "\n".join(
        [
            "# Reference Normalization Evidence Validation",
            "",
            "> Complete impact-set, transformation-masked dual-review diagnostic; all labels remain non-human.",
            "",
            f"- Impact rows: `{summary['impact_rows']}`",
            f"- Network-corroborated rows: `{summary['network_corroborated_rows']}`",
            f"- Dual-review rows: `{summary['secondary_rows']}`",
            f"- Secondary strict consensus: `{summary['secondary_strict_rows']}`",
            f"- Combined non-human resolved rows: `{summary['combined_resolved_rows']}`",
            f"- Candidate `incomplete` supported: `{counts.get('incomplete', 0)}`",
            f"- Candidate rejected as representation discrepancy: `{counts.get('representation_discrepancy', 0)}`",
            f"- Unresolved: `{counts.get('unresolved', 0)}`",
            "",
            "Production default changed: `false`. Real-human signed rows: `0`.",
            "",
        ]
    )


def main() -> int:
    args = parse_args()
    manifest_path = resolve(args.manifest)
    agent_e_path = resolve(args.agent_e)
    agent_f_path = resolve(args.agent_f)
    output_dir = resolve(args.output_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not manifest.get("reviewer_outputs_absent_at_seal"):
        raise ValueError("invalid reference impact manifest")

    for item in manifest["inputs"].values():
        if sha256(Path(item["path"])) != item["sha256"]:
            raise ValueError(f"sealed input hash mismatch: {item['path']}")
    for item in manifest["outputs"].values():
        if sha256(Path(item["path"])) != item["sha256"]:
            raise ValueError(f"sealed output hash mismatch: {item['path']}")
    for item in manifest["code"].values():
        if sha256(Path(item["path"])) != item["sha256"]:
            raise ValueError(f"sealed code hash mismatch: {item['path']}")

    expected_paths = manifest["reviewer_outputs"]
    if agent_e_path != Path(expected_paths["agent_e"]):
        raise ValueError("agent E path differs from sealed path")
    if agent_f_path != Path(expected_paths["agent_f"]):
        raise ValueError("agent F path differs from sealed path")
    if agent_e_path == agent_f_path:
        raise ValueError("secondary reviewer paths must differ")
    if not agent_e_path.exists() or not agent_f_path.exists():
        raise ValueError("both secondary reviewer outputs are required")
    if agent_e_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent E output predates seal")
    if agent_f_path.stat().st_mtime_ns <= manifest["sealed_at_ns"]:
        raise ValueError("agent F output predates seal")
    if sha256(agent_e_path) == sha256(agent_f_path):
        raise ValueError("secondary reviewer outputs must not be identical")

    worklist_path = Path(manifest["outputs"]["secondary_worklist"]["path"])
    validation_path = Path(manifest["outputs"]["validation_rows"]["path"])
    worklist = list(iter_jsonl(worklist_path))
    validation_rows = list(iter_jsonl(validation_path))
    if not worklist:
        raise ValueError("no secondary rows require review")
    if len(validation_rows) != 56:
        raise ValueError("expected complete 56-row impact set")
    agent_e = validate_reviews(
        agent_e_path,
        worklist,
        "codex_reference_identity_e",
        "rq2_reference_identity_e2_20260715",
    )
    agent_f = validate_reviews(
        agent_f_path,
        worklist,
        "codex_reference_identity_f",
        "rq2_reference_identity_f2_20260715",
    )
    if agent_e[0]["run_id"] == agent_f[0]["run_id"]:
        raise ValueError("secondary reviewer run IDs must differ")

    secondary = []
    for source, left, right in zip(worklist, agent_e, agent_f):
        strict, status = strict_secondary(left, right)
        secondary.append(
            {
                "review_id": source["review_id"],
                "cve_id": source["cve_id"],
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "strict_consensus": strict,
                "consensus_status": status,
                "agent_e": left,
                "agent_f": right,
            }
        )
    combined = combine_rows(validation_rows, secondary)
    resolved = [row for row in combined if row["resolved_nonhuman"]]
    status_counts = Counter(
        row["resolved_status"] if row["resolved_nonhuman"] else "unresolved"
        for row in combined
    )
    strict_secondary_rows = [row for row in secondary if row["strict_consensus"]]
    summary = {
        "artifact_type": "rq2_reference_normalization_evidence_validation",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_confirmatory_claim": False,
        "sealed_before_reviews": True,
        "same_model_family_separate_runs": True,
        "impact_rows": len(combined),
        "network_corroborated_rows": sum(
            row["validation_status"] == "network_corroborated"
            for row in validation_rows
        ),
        "secondary_rows": len(secondary),
        "secondary_strict_rows": len(strict_secondary_rows),
        "secondary_component_agreement": {
            key: agreement_summary(agent_e, agent_f, key)
            for key in (
                "identity_verdict",
                "final_status",
                "confidence",
                "needs_additional_review",
            )
        },
        "secondary_consensus_status_counts": dict(
            sorted(Counter(row["consensus_status"] for row in strict_secondary_rows).items())
        ),
        "combined_resolved_rows": len(resolved),
        "combined_resolved_status_counts": dict(sorted(status_counts.items())),
        "production_default_changed": False,
        "human_signed_rows": 0,
        "cautions": [
            "The 56 rows are the complete post-hoc rule-impact set, not a representative sample.",
            "Both secondary reviewers are separate runs of the same AI model family.",
            "The reviews mask the candidate transformation and labels, but grouping itself still reveals the pairs under test.",
            "Network evidence and AI agreement do not constitute real-human validation.",
        ],
    }

    secondary_path = output_dir / "reference_identity_secondary_dual_review.jsonl"
    combined_path = output_dir / "reference_normalization_combined_candidate.jsonl"
    summary_path = output_dir / "reference_normalization_evidence_validation.json"
    markdown_path = output_dir / "reference_normalization_evidence_validation.md"
    merge_manifest_path = output_dir / "reference_normalization_merge_manifest.json"
    write_jsonl(secondary_path, secondary)
    write_jsonl(combined_path, combined)
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(summary), encoding="utf-8")
    merge_manifest = {
        "artifact_type": "reference_normalization_merge_manifest",
        "label_is_human": False,
        "inputs": {
            "sealed_manifest": {
                "path": str(manifest_path),
                "sha256": sha256(manifest_path),
            },
            "agent_e": {"path": str(agent_e_path), "sha256": sha256(agent_e_path)},
            "agent_f": {"path": str(agent_f_path), "sha256": sha256(agent_f_path)},
        },
        "outputs": {
            "secondary": {"path": str(secondary_path), "sha256": sha256(secondary_path)},
            "combined": {"path": str(combined_path), "sha256": sha256(combined_path)},
            "summary": {"path": str(summary_path), "sha256": sha256(summary_path)},
        },
    }
    merge_manifest_path.write_text(
        json.dumps(merge_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {secondary_path}")
    print(f"Wrote {combined_path}")
    print(f"Wrote {summary_path}")
    print(json.dumps(summary["combined_resolved_status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
