#!/usr/bin/env python3
"""Validate dual-Codex holdout decisions and build a strict consensus overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = "data/annotations/holdout/affected_versions_v1"
DEFAULT_EVIDENCE = f"{BASE}/evidence/source_rows.evidence.jsonl"
DEFAULT_AGENT_A = f"{BASE}/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = f"{BASE}/agent_b_decisions.jsonl"
DEFAULT_BLIND_MANIFEST = f"{BASE}/blind/manifest.json"
DEFAULT_HOLDOUT_MANIFEST = f"{BASE}/manifest.json"
DEFAULT_PROMPT = "docs/prompts/affected_versions_holdout_adjudication.md"
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v1"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)
SOURCES = ("nvd", "ghsa", "both", "neither", "abstain")
CONFIDENCE = ("high", "medium", "low")
EVIDENCE_KEYS = {"nvd", "ghsa", "third"}
DECISION_KEYS = {
    "sample_id",
    "cve_id",
    "field",
    "discrepancy_label",
    "reviewed_source",
    "adjudication_status",
    "confidence",
    "positive_support",
    "contradiction_or_scope_exclusion",
    "artifact_assessment",
    "range_assessment",
    "rationale",
    "unresolved",
    "label_is_human",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--blind-manifest", default=DEFAULT_BLIND_MANIFEST)
    parser.add_argument("--holdout-manifest", default=DEFAULT_HOLDOUT_MANIFEST)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--expected-rows", type=int, default=100)
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


def load_jsonl(path: Path) -> dict[str, dict]:
    rows = {}
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            sample_id = row.get("sample_id")
            if not sample_id or sample_id in rows:
                raise ValueError(f"{path}:{line_number}: missing or duplicate sample_id")
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


def validate_contract(row: dict, evidence_row: dict) -> None:
    sample_id = row.get("sample_id")
    if set(row) != DECISION_KEYS:
        raise ValueError(
            f"{sample_id}: decision keys differ; "
            f"missing={sorted(DECISION_KEYS - set(row))} "
            f"extra={sorted(set(row) - DECISION_KEYS)}"
        )
    if row["label_is_human"] is not False:
        raise ValueError(f"{sample_id}: label_is_human must be false")
    if row["cve_id"] != evidence_row.get("cve_id") or row["field"] != "affected_versions":
        raise ValueError(f"{sample_id}: identity mismatch")
    if row["discrepancy_label"] not in LABELS:
        raise ValueError(f"{sample_id}: invalid discrepancy_label")
    if row["reviewed_source"] not in SOURCES:
        raise ValueError(f"{sample_id}: invalid reviewed_source")
    if row["confidence"] not in CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid confidence")
    expected_status = (
        "abstain"
        if row["discrepancy_label"] == "uncertain"
        or row["reviewed_source"] == "abstain"
        or row["confidence"] == "low"
        else "determinate"
    )
    if row["adjudication_status"] != expected_status:
        raise ValueError(f"{sample_id}: adjudication_status is inconsistent")
    for field, minimum in (
        ("artifact_assessment", 20),
        ("range_assessment", 20),
        ("rationale", 60),
        ("unresolved", 0),
    ):
        if not isinstance(row[field], str) or len(row[field].strip()) < minimum:
            raise ValueError(f"{sample_id}: {field} is too short or not a string")

    positive = validate_evidence_map(row["positive_support"], sample_id, "positive_support")
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
        for mapping in (positive, contradiction)
        for urls in mapping.values()
        for url in urls
    }
    unknown = used_urls - allowed_urls
    if unknown:
        raise ValueError(f"{sample_id}: uses unavailable evidence URLs {sorted(unknown)}")

    source = row["reviewed_source"]
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


def cohen_kappa(left: list[str], right: list[str], labels: tuple[str, ...]) -> float | None:
    if len(left) != len(right) or not left:
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts = Counter(left)
    right_counts = Counter(right)
    expected = sum(left_counts[label] * right_counts[label] for label in labels) / len(left) ** 2
    if math.isclose(expected, 1.0):
        return None
    return (observed - expected) / (1.0 - expected)


def strict_consensus(left: dict, right: dict) -> dict:
    exact_label = left["discrepancy_label"] == right["discrepancy_label"]
    exact_source = left["reviewed_source"] == right["reviewed_source"]
    accepted = (
        exact_label
        and exact_source
        and left["adjudication_status"] == "determinate"
        and right["adjudication_status"] == "determinate"
    )
    evidence_urls = sorted(
        {
            url
            for decision in (left, right)
            for field in ("positive_support", "contradiction_or_scope_exclusion")
            for urls in decision[field].values()
            for url in urls
        }
    )
    return {
        "artifact_type": "affected_versions_holdout_dual_codex_consensus_v1",
        "sample_id": left["sample_id"],
        "cve_id": left["cve_id"],
        "field": "affected_versions",
        "consensus_status": "strict_determinate" if accepted else "abstain",
        "discrepancy_label": left["discrepancy_label"] if accepted else "uncertain",
        "adjudicated_source": left["reviewed_source"] if accepted else "abstain",
        "exact_label_agreement": exact_label,
        "exact_source_agreement": exact_source,
        "agent_a_confidence": left["confidence"],
        "agent_b_confidence": right["confidence"],
        "evidence_urls": evidence_urls,
        "agent_a_rationale": left["rationale"],
        "agent_b_rationale": right["rationale"],
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "requires_human_signoff": True,
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    args = parse_args()
    evidence_path = resolve(args.evidence)
    agent_a_path = resolve(args.agent_a)
    agent_b_path = resolve(args.agent_b)
    blind_manifest_path = resolve(args.blind_manifest)
    holdout_manifest_path = resolve(args.holdout_manifest)
    prompt_path = resolve(args.prompt)
    output_dir = resolve(args.output_dir)
    blind_manifest = json.loads(blind_manifest_path.read_text(encoding="utf-8"))
    if blind_manifest.get("contains_labels") is not False:
        raise ValueError("blind worklist manifest does not prove label isolation")
    if blind_manifest["input"]["sha256"] != sha256(evidence_path):
        raise ValueError("blind worklist and merge use different evidence snapshots")
    evidence = load_jsonl(evidence_path)
    agent_a = load_jsonl(agent_a_path)
    agent_b = load_jsonl(agent_b_path)
    expected_ids = set(evidence)
    if len(expected_ids) != args.expected_rows:
        raise ValueError(f"expected {args.expected_rows} evidence rows, found {len(expected_ids)}")
    if set(agent_a) != expected_ids or set(agent_b) != expected_ids:
        raise ValueError("agent identity coverage mismatch")
    for sample_id in sorted(expected_ids):
        validate_contract(agent_a[sample_id], evidence[sample_id])
        validate_contract(agent_b[sample_id], evidence[sample_id])

    rows = [strict_consensus(agent_a[sample_id], agent_b[sample_id]) for sample_id in sorted(expected_ids)]
    accepted = [row for row in rows if row["consensus_status"] == "strict_determinate"]
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_consensus.jsonl"
    write_jsonl(output_path, rows)
    summary = {
        "artifact_type": "affected_versions_holdout_dual_codex_consensus_summary_v1",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_independent_human_holdout_claim": False,
        "rows": len(rows),
        "strict_determinate": len(accepted),
        "abstain": len(rows) - len(accepted),
        "coverage": len(accepted) / len(rows),
        "exact_label_agreement": sum(row["exact_label_agreement"] for row in rows),
        "exact_source_agreement": sum(row["exact_source_agreement"] for row in rows),
        "exact_joint_agreement": sum(
            row["exact_label_agreement"] and row["exact_source_agreement"] for row in rows
        ),
        "label_kappa": cohen_kappa(
            [agent_a[sample_id]["discrepancy_label"] for sample_id in sorted(expected_ids)],
            [agent_b[sample_id]["discrepancy_label"] for sample_id in sorted(expected_ids)],
            LABELS,
        ),
        "source_kappa": cohen_kappa(
            [agent_a[sample_id]["reviewed_source"] for sample_id in sorted(expected_ids)],
            [agent_b[sample_id]["reviewed_source"] for sample_id in sorted(expected_ids)],
            SOURCES,
        ),
        "strict_label_counts": dict(sorted(Counter(row["discrepancy_label"] for row in accepted).items())),
        "strict_source_counts": dict(sorted(Counter(row["adjudicated_source"] for row in accepted).items())),
        "inputs": {
            "evidence": {"path": str(evidence_path), "sha256": sha256(evidence_path)},
            "agent_a": {"path": str(agent_a_path), "sha256": sha256(agent_a_path)},
            "agent_b": {"path": str(agent_b_path), "sha256": sha256(agent_b_path)},
            "blind_manifest": {"path": str(blind_manifest_path), "sha256": sha256(blind_manifest_path)},
            "holdout_manifest": {"path": str(holdout_manifest_path), "sha256": sha256(holdout_manifest_path)},
            "prompt": {"path": str(prompt_path), "sha256": sha256(prompt_path)},
        },
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "cautions": [
            "Both reviewers are Codex agents, not human annotators.",
            "The strict overlay is an expert-adjudicated candidate requiring human signoff.",
            "The holdout is development-disjoint by CVE but not independent human-gold.",
        ],
    }
    summary_path = output_dir / "affected_versions_holdout_consensus_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
