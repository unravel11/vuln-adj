#!/usr/bin/env python3
"""Validate dual-agent source re-audit and build a provenance-preserving overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASE_DIR = "data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions"
DEFAULT_EVIDENCE = f"{BASE_DIR}/evidence_refresh/source_rows.evidence.jsonl"
DEFAULT_CANDIDATES = f"{BASE_DIR}/candidate_rows.jsonl"
DEFAULT_AGENT_A = f"{BASE_DIR}/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = f"{BASE_DIR}/agent_b_decisions.jsonl"
DEFAULT_GOLD = "data/annotations/ai_adjudicated_gold/rq3_affected_versions.jsonl"
DEFAULT_OUTPUT_DIR = "results/ai_adjudicated_gold/source_reaudit"
SOURCE_LABELS = ("nvd", "ghsa", "both", "neither", "abstain")
CONFIDENCE = ("high", "medium", "low")
DECISION_KEYS = {
    "sample_id",
    "cve_id",
    "prior_source",
    "reviewed_source",
    "source_status",
    "confidence",
    "positive_support",
    "contradiction_or_scope_exclusion",
    "rationale",
    "unresolved",
    "label_is_human",
}
EVIDENCE_KEYS = {"nvd", "ghsa", "third"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--candidates", default=DEFAULT_CANDIDATES)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--gold", default=DEFAULT_GOLD)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-reaudit-rows", type=int, default=45)
    parser.add_argument(
        "--selected-base-policy",
        choices=("preserve", "replace_with_strict_consensus"),
        default="preserve",
        help=(
            "Whether selected base final-determinate rows remain authoritative or "
            "are replaced by the strict dual-agent consensus."
        ),
    )
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


def validate_evidence_map(value: object, sample_id: str, field: str) -> dict:
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise ValueError(f"{sample_id}: {field} must have keys {sorted(EVIDENCE_KEYS)}")
    for key, urls in value.items():
        if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
            raise ValueError(f"{sample_id}: {field}.{key} must be a URL list")
        if len(urls) != len(set(urls)):
            raise ValueError(f"{sample_id}: {field}.{key} has duplicate URLs")
    return value


def validate_contract(row: dict, evidence_row: dict, candidate_row: dict) -> None:
    sample_id = row.get("sample_id")
    if set(row) != DECISION_KEYS:
        raise ValueError(
            f"{sample_id}: decision keys differ; "
            f"missing={sorted(DECISION_KEYS - set(row))} "
            f"extra={sorted(set(row) - DECISION_KEYS)}"
        )
    if row["label_is_human"] is not False:
        raise ValueError(f"{sample_id}: label_is_human must be false")
    if row["cve_id"] != evidence_row.get("cve_id"):
        raise ValueError(f"{sample_id}: cve_id mismatch")
    prior_source = candidate_row.get("annotation", {}).get("adjudicated_source")
    if row["prior_source"] != prior_source:
        raise ValueError(f"{sample_id}: prior_source mismatch")
    source = row["reviewed_source"]
    if source not in SOURCE_LABELS:
        raise ValueError(f"{sample_id}: invalid reviewed_source={source}")
    expected_status = "abstain" if source == "abstain" else "determinate"
    if row["source_status"] != expected_status:
        raise ValueError(f"{sample_id}: source_status is inconsistent")
    if row["confidence"] not in CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid confidence")
    if not isinstance(row["rationale"], str) or len(row["rationale"].strip()) < 50:
        raise ValueError(f"{sample_id}: rationale is too short")
    if not isinstance(row["unresolved"], str):
        raise ValueError(f"{sample_id}: unresolved must be a string")

    positive = validate_evidence_map(
        row["positive_support"], sample_id, "positive_support"
    )
    contradiction = validate_evidence_map(
        row["contradiction_or_scope_exclusion"],
        sample_id,
        "contradiction_or_scope_exclusion",
    )
    allowed_urls = {
        record.get("url")
        for record in evidence_row.get("evidence_context", {}).get("records", [])
        if record.get("fetch_status") == "ok" and record.get("text_snippet")
    }
    used_urls = {
        url
        for evidence_map in (positive, contradiction)
        for urls in evidence_map.values()
        for url in urls
    }
    unknown = used_urls - allowed_urls
    if unknown:
        raise ValueError(f"{sample_id}: uses unavailable evidence URLs {sorted(unknown)}")

    if source == "nvd" and not (positive["nvd"] and contradiction["ghsa"]):
        raise ValueError(f"{sample_id}: nvd requires support and GHSA contradiction")
    if source == "ghsa" and not (positive["ghsa"] and contradiction["nvd"]):
        raise ValueError(f"{sample_id}: ghsa requires support and NVD contradiction")
    if source == "both" and not (positive["nvd"] and positive["ghsa"]):
        raise ValueError(f"{sample_id}: both requires support for each source")
    if source == "neither" and not (
        positive["third"] or (contradiction["nvd"] and contradiction["ghsa"])
    ):
        raise ValueError(f"{sample_id}: neither lacks third-value/bilateral evidence")


def cohen_kappa(left: list[str], right: list[str]) -> float | None:
    if len(left) != len(right) or not left:
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    expected = sum(
        left_counts[label] * right_counts[label] for label in SOURCE_LABELS
    ) / (len(left) ** 2)
    if math.isclose(expected, 1.0):
        return None
    return (observed - expected) / (1.0 - expected)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    evidence_path = resolve(args.evidence)
    candidate_path = resolve(args.candidates)
    agent_a_path = resolve(args.agent_a)
    agent_b_path = resolve(args.agent_b)
    gold_path = resolve(args.gold)
    output_dir = resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    evidence = load_jsonl(evidence_path)
    candidates = load_jsonl(candidate_path)
    agent_a = load_jsonl(agent_a_path)
    agent_b = load_jsonl(agent_b_path)
    base_gold = load_jsonl(gold_path)
    expected_ids = set(evidence)
    if len(expected_ids) != args.expected_reaudit_rows:
        raise ValueError(
            f"expected {args.expected_reaudit_rows} evidence rows, found {len(expected_ids)}"
        )
    for name, rows in (
        ("candidates", candidates),
        ("agent_a", agent_a),
        ("agent_b", agent_b),
    ):
        if set(rows) != expected_ids:
            raise ValueError(f"{name} identity coverage mismatch")
    if len(base_gold) != 100 or not expected_ids <= set(base_gold):
        raise ValueError("base gold must contain the 45 re-audit rows within 100 rows")

    for sample_id in sorted(expected_ids):
        validate_contract(agent_a[sample_id], evidence[sample_id], candidates[sample_id])
        validate_contract(agent_b[sample_id], evidence[sample_id], candidates[sample_id])

    consensus_rows = []
    for sample_id in sorted(expected_ids):
        left = agent_a[sample_id]
        right = agent_b[sample_id]
        exact_source_agreement = left["reviewed_source"] == right["reviewed_source"]
        confidence_gate = left["confidence"] != "low" and right["confidence"] != "low"
        source = left["reviewed_source"] if exact_source_agreement else "abstain"
        accepted = exact_source_agreement and source != "abstain" and confidence_gate
        consensus_rows.append(
            {
                "schema_version": "affected_versions_source_reaudit_consensus_v1",
                "sample_id": sample_id,
                "cve_id": evidence[sample_id].get("cve_id"),
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "requires_human_signoff": True,
                "agent_source_agreement": exact_source_agreement,
                "confidence_gate_passed": confidence_gate,
                "consensus_status": "final_determinate" if accepted else "final_abstain",
                "consensus_source": source if accepted else None,
                "prior_source": candidates[sample_id]["annotation"][
                    "adjudicated_source"
                ],
                "agent_a": left,
                "agent_b": right,
            }
        )

    consensus_path = output_dir / "affected_versions_source_reaudit_consensus.jsonl"
    write_jsonl(consensus_path, consensus_rows)
    consensus_by_id = {row["sample_id"]: row for row in consensus_rows}

    overlay_rows = []
    for sample_id, base in base_gold.items():
        selected_consensus = consensus_by_id.get(sample_id)
        replace_selected = (
            args.selected_base_policy == "replace_with_strict_consensus"
            and selected_consensus is not None
        )
        if replace_selected and selected_consensus[
            "consensus_status"
        ] == "final_determinate":
            source_status = "final_determinate"
            source = selected_consensus["consensus_source"]
            origin = "dual_agent_strict_reaudit_selected_base"
            reaudit = selected_consensus
        elif replace_selected:
            source_status = "final_abstain"
            source = None
            origin = "unresolved_after_strict_selected_base_reaudit"
            reaudit = selected_consensus
        elif base.get("ai_gold_status") == "final_determinate":
            source_status = "final_determinate"
            source = base["annotation"]["adjudicated_source"]
            origin = "existing_ai_gold_final_determinate"
            reaudit = None
        elif sample_id in consensus_by_id and consensus_by_id[sample_id][
            "consensus_status"
        ] == "final_determinate":
            source_status = "final_determinate"
            source = consensus_by_id[sample_id]["consensus_source"]
            origin = "dual_agent_strict_source_reaudit"
            reaudit = consensus_by_id[sample_id]
        else:
            source_status = "final_abstain"
            source = None
            origin = "unresolved_after_source_reaudit"
            reaudit = consensus_by_id.get(sample_id)
        overlay_rows.append(
            {
                "schema_version": "affected_versions_ai_source_gold_overlay_v1",
                "sample_id": sample_id,
                "cve_id": base.get("cve_id"),
                "field": "affected_versions",
                "label_is_human": False,
                "eligible_for_human_gold_claim": False,
                "eligible_for_final_paper_claim": False,
                "requires_human_signoff": True,
                "source_gold_status": source_status,
                "source_gold_label": source,
                "source_decision_origin": origin,
                "base_discrepancy_status": base.get("ai_gold_status"),
                "base_discrepancy_label": base["annotation"].get(
                    "discrepancy_label"
                ),
                "base_ai_gold_source": base["annotation"].get(
                    "adjudicated_source"
                ),
                "source_reaudit": reaudit,
            }
        )
    overlay_path = output_dir / "rq3_affected_versions_source_gold_overlay.jsonl"
    write_jsonl(overlay_path, overlay_rows)

    left_labels = [agent_a[sid]["reviewed_source"] for sid in sorted(expected_ids)]
    right_labels = [agent_b[sid]["reviewed_source"] for sid in sorted(expected_ids)]
    accepted_rows = [
        row for row in consensus_rows if row["consensus_status"] == "final_determinate"
    ]
    changed_rows = [
        row
        for row in accepted_rows
        if row["consensus_source"] != row["prior_source"]
    ]
    overlay_determinate = [
        row for row in overlay_rows if row["source_gold_status"] == "final_determinate"
    ]
    selected_base_status_counts = Counter(
        base_gold[sample_id].get("ai_gold_status") for sample_id in expected_ids
    )
    if selected_base_status_counts == {"final_determinate": len(expected_ids)}:
        selection_caution = (
            "The selected rows were prior final-determinate AI labels and were "
            "rerun under the strict dual-agent source contract."
        )
    else:
        selection_caution = (
            "The selected rows came from prior non-determinate AI labels with "
            "non-abstain source suggestions."
        )
    summary = {
        "artifact_type": "affected_versions_source_reaudit_consensus",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_final_paper_claim": False,
        "inputs": {
            "evidence": {"path": str(evidence_path), "sha256": sha256(evidence_path)},
            "candidates": {
                "path": str(candidate_path),
                "sha256": sha256(candidate_path),
            },
            "agent_a": {"path": str(agent_a_path), "sha256": sha256(agent_a_path)},
            "agent_b": {"path": str(agent_b_path), "sha256": sha256(agent_b_path)},
            "base_gold": {"path": str(gold_path), "sha256": sha256(gold_path)},
        },
        "reaudit_rows": len(consensus_rows),
        "selected_base_policy": args.selected_base_policy,
        "selected_base_status_counts": dict(sorted(selected_base_status_counts.items())),
        "exact_source_agreement_count": sum(
            row["agent_source_agreement"] for row in consensus_rows
        ),
        "exact_source_agreement_rate": sum(
            row["agent_source_agreement"] for row in consensus_rows
        )
        / len(consensus_rows),
        "cohen_kappa_including_abstain": cohen_kappa(left_labels, right_labels),
        "agent_a_source_counts": dict(sorted(Counter(left_labels).items())),
        "agent_b_source_counts": dict(sorted(Counter(right_labels).items())),
        "strict_consensus_determinate_rows": len(accepted_rows),
        "strict_consensus_source_counts": dict(
            sorted(Counter(row["consensus_source"] for row in accepted_rows).items())
        ),
        "accepted_source_changes_from_prior": len(changed_rows),
        "expanded_source_gold": {
            "rows": len(overlay_rows),
            "determinate": len(overlay_determinate),
            "abstain": len(overlay_rows) - len(overlay_determinate),
            "coverage": len(overlay_determinate) / len(overlay_rows),
            "source_counts": dict(
                sorted(
                    Counter(row["source_gold_label"] for row in overlay_determinate).items()
                )
            ),
            "origin_counts": dict(
                sorted(
                    Counter(row["source_decision_origin"] for row in overlay_rows).items()
                )
            ),
        },
        "outputs": {
            "consensus": {
                "path": str(consensus_path),
                "sha256": sha256(consensus_path),
            },
            "source_gold_overlay": {
                "path": str(overlay_path),
                "sha256": sha256(overlay_path),
            },
        },
        "cautions": [
            "Both reviewers are Codex agents, not human annotators.",
            selection_caution,
            "Only exact non-abstain agreement with no low-confidence decision is added to the source overlay.",
        ],
    }
    summary_path = output_dir / "affected_versions_source_reaudit_consensus_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
