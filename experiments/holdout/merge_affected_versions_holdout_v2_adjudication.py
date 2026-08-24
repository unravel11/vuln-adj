#!/usr/bin/env python3
"""Validate v2 dual-Codex decisions and merge type/source endpoints separately."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = "data/annotations/holdout/affected_versions_v2"
DEFAULT_EVIDENCE = f"{BASE}/evidence/source_rows.evidence.jsonl"
DEFAULT_AGENT_A = f"{BASE}/agent_a_decisions.jsonl"
DEFAULT_AGENT_B = f"{BASE}/agent_b_decisions.jsonl"
DEFAULT_BLIND_WORKLIST = f"{BASE}/blind/affected_versions_holdout_v2_blind_worklist.jsonl"
DEFAULT_BLIND_MANIFEST = f"{BASE}/blind/manifest.json"
DEFAULT_HOLDOUT_MANIFEST = f"{BASE}/manifest.json"
DEFAULT_PROMPT = "docs/prompts/affected_versions_holdout_v2_adjudication.md"
DEFAULT_OUTPUT_DIR = "results/holdout/affected_versions_v2"
LABELS = (
    "equivalent",
    "representation_discrepancy",
    "incomplete",
    "temporal_discrepancy",
    "factual_conflict",
    "uncertain",
)
ARTIFACT_RELATIONS = (
    "same_artifact",
    "different_artifact",
    "multi_artifact_scope",
    "uncertain",
)
SOURCES = ("nvd", "ghsa", "neither", "abstain", "not_applicable")
CONFIDENCE = ("high", "medium", "low")
SOURCE_CONFIDENCE = (*CONFIDENCE, "not_applicable")
EVIDENCE_KEYS = {"nvd", "ghsa", "third"}
EVIDENCE_CLAIM_KEYS = {"url", "endpoint", "target", "role", "quote", "interpretation"}
EVIDENCE_ENDPOINTS = {"type", "source"}
EVIDENCE_ROLES = {
    "type_support",
    "positive_support",
    "contradiction",
    "scope_exclusion",
    "third_value",
}
FORBIDDEN_BLIND_KEY_PARTS = (
    "annotation",
    "baseline",
    "candidate",
    "gold",
    "prediction",
    "silver",
)
DECISION_KEYS = {
    "sample_id",
    "cve_id",
    "field",
    "reviewer_id",
    "review_run_id",
    "prompt_sha256",
    "blind_worklist_sha256",
    "artifact_relation",
    "discrepancy_label",
    "type_status",
    "type_confidence",
    "type_evidence",
    "reviewed_source",
    "source_status",
    "source_confidence",
    "positive_support",
    "contradiction_or_scope_exclusion",
    "evidence_claims",
    "artifact_assessment",
    "range_assessment",
    "type_rationale",
    "source_rationale",
    "unresolved",
    "label_is_human",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE)
    parser.add_argument("--agent-a", default=DEFAULT_AGENT_A)
    parser.add_argument("--agent-b", default=DEFAULT_AGENT_B)
    parser.add_argument("--agent-a-reviewer-id", default="agent_a")
    parser.add_argument("--agent-b-reviewer-id", default="agent_b")
    parser.add_argument("--blind-worklist", default=DEFAULT_BLIND_WORKLIST)
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


def validate_distinct_reviewer_files(left: Path, right: Path) -> None:
    if left == right or os.path.samefile(left, right):
        raise ValueError("agent A/B decisions must be distinct files")
    if sha256(left) == sha256(right):
        raise ValueError("agent A/B decision contents are identical; independence not established")


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


def jsonl_sample_order(path: Path) -> list[str]:
    order = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            sample_id = json.loads(line).get("sample_id")
            if not sample_id:
                raise ValueError(f"{path}:{line_number}: missing sample_id")
            order.append(sample_id)
    if len(order) != len(set(order)):
        raise ValueError(f"{path}: duplicate sample_id in order")
    return order


def forbidden_blind_keys(value: object, prefix: str = "") -> list[str]:
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(part in str(key).lower() for part in FORBIDDEN_BLIND_KEY_PARTS):
                found.append(path)
            found.extend(forbidden_blind_keys(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(forbidden_blind_keys(child, f"{prefix}[{index}]"))
    return found


def normalize_quote(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def validate_evidence_claims(
    value: object,
    sample_id: str,
    records_by_url: dict[str, dict],
    type_evidence: dict,
    positive: dict,
    contradiction: dict,
) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError(f"{sample_id}: evidence_claims must be a list")
    seen = set()
    indexed = set()
    for index, claim in enumerate(value):
        if not isinstance(claim, dict) or set(claim) != EVIDENCE_CLAIM_KEYS:
            raise ValueError(f"{sample_id}: evidence_claims[{index}] has invalid keys")
        if claim["endpoint"] not in EVIDENCE_ENDPOINTS:
            raise ValueError(f"{sample_id}: evidence claim has invalid endpoint")
        if claim["target"] not in EVIDENCE_KEYS or claim["role"] not in EVIDENCE_ROLES:
            raise ValueError(f"{sample_id}: evidence claim has invalid target/role")
        url = claim["url"]
        if url not in records_by_url:
            raise ValueError(f"{sample_id}: evidence claim uses unavailable URL {url}")
        quote = normalize_quote(claim["quote"])
        source_text = normalize_quote(
            f"{records_by_url[url].get('title', '')} {records_by_url[url].get('text_snippet', '')}"
        )
        if len(quote) < 10 or quote not in source_text:
            raise ValueError(f"{sample_id}: evidence claim quote is not a literal frozen snippet")
        if not isinstance(claim["interpretation"], str) or len(claim["interpretation"].strip()) < 20:
            raise ValueError(f"{sample_id}: evidence claim interpretation is too short")
        key = (url, claim["endpoint"], claim["target"], claim["role"], quote)
        if key in seen:
            raise ValueError(f"{sample_id}: duplicate structured evidence claim")
        seen.add(key)
        indexed.add((url, claim["endpoint"], claim["target"], claim["role"]))

    required = set()
    for target, urls in type_evidence.items():
        required.update((url, "type", target, "type_support") for url in urls)
    for target, urls in positive.items():
        role = "third_value" if target == "third" else "positive_support"
        required.update((url, "source", target, role) for url in urls)
    for target, urls in contradiction.items():
        required.update(
            (url, "source", target, role)
            for url in urls
            for role in ("contradiction", "scope_exclusion")
        )
    missing = []
    for item in required:
        url, endpoint, target, role = item
        if role in {"contradiction", "scope_exclusion"}:
            if not any(
                candidate[:3] == (url, endpoint, target)
                and candidate[3] in {"contradiction", "scope_exclusion"}
                for candidate in indexed
            ):
                missing.append(item)
        elif item not in indexed:
            missing.append(item)
    if missing:
        raise ValueError(f"{sample_id}: cited URLs lack structured evidence claims {missing[:3]}")
    return value


def validate_evidence_map(value: object, sample_id: str, field: str) -> dict:
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise ValueError(f"{sample_id}: {field} must have keys {sorted(EVIDENCE_KEYS)}")
    for key, urls in value.items():
        if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
            raise ValueError(f"{sample_id}: {field}.{key} must be a URL list")
        if len(urls) != len(set(urls)):
            raise ValueError(f"{sample_id}: {field}.{key} has duplicate URLs")
    return value


def empty_evidence_map(value: dict) -> bool:
    return not any(value[key] for key in EVIDENCE_KEYS)


def validate_contract(
    row: dict,
    evidence_row: dict,
    expected_reviewer_id: str = "agent_a",
    expected_prompt_sha256: str = "prompt-hash",
    expected_blind_sha256: str = "blind-hash",
) -> None:
    sample_id = row.get("sample_id")
    if set(row) != DECISION_KEYS:
        raise ValueError(
            f"{sample_id}: decision keys differ; missing={sorted(DECISION_KEYS - set(row))} "
            f"extra={sorted(set(row) - DECISION_KEYS)}"
        )
    if row["label_is_human"] is not False:
        raise ValueError(f"{sample_id}: label_is_human must be false")
    if row["reviewer_id"] != expected_reviewer_id:
        raise ValueError(f"{sample_id}: reviewer_id mismatch")
    if not isinstance(row["review_run_id"], str) or len(row["review_run_id"].strip()) < 8:
        raise ValueError(f"{sample_id}: review_run_id is missing or too short")
    if row["prompt_sha256"] != expected_prompt_sha256:
        raise ValueError(f"{sample_id}: prompt_sha256 mismatch")
    if row["blind_worklist_sha256"] != expected_blind_sha256:
        raise ValueError(f"{sample_id}: blind_worklist_sha256 mismatch")
    if row["cve_id"] != evidence_row.get("cve_id") or row["field"] != "affected_versions":
        raise ValueError(f"{sample_id}: identity mismatch")
    if row["artifact_relation"] not in ARTIFACT_RELATIONS:
        raise ValueError(f"{sample_id}: invalid artifact_relation")
    if row["discrepancy_label"] not in LABELS:
        raise ValueError(f"{sample_id}: invalid discrepancy_label")
    if row["type_confidence"] not in CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid type_confidence")
    expected_type_status = (
        "abstain"
        if row["discrepancy_label"] == "uncertain" or row["type_confidence"] == "low"
        else "determinate"
    )
    if row["type_status"] != expected_type_status:
        raise ValueError(f"{sample_id}: type_status is inconsistent")
    if row["type_confidence"] == "low" and row["discrepancy_label"] != "uncertain":
        raise ValueError(f"{sample_id}: low-confidence type must be uncertain")
    label = row["discrepancy_label"]
    relation = row["artifact_relation"]
    if label in {
        "equivalent",
        "representation_discrepancy",
        "temporal_discrepancy",
        "factual_conflict",
    } and relation != "same_artifact":
        raise ValueError(f"{sample_id}: {label} requires same_artifact")
    if relation in {"different_artifact", "uncertain"} and label != "uncertain":
        raise ValueError(f"{sample_id}: unresolved artifact relation requires uncertain type")
    if relation == "multi_artifact_scope" and label not in {"incomplete", "uncertain"}:
        raise ValueError(f"{sample_id}: multi_artifact_scope requires incomplete or uncertain")
    if row["reviewed_source"] not in SOURCES:
        raise ValueError(f"{sample_id}: invalid reviewed_source")
    if row["source_confidence"] not in SOURCE_CONFIDENCE:
        raise ValueError(f"{sample_id}: invalid source_confidence")

    for field, minimum in (
        ("artifact_assessment", 20),
        ("range_assessment", 20),
        ("type_rationale", 60),
        ("source_rationale", 20),
        ("unresolved", 0),
    ):
        if not isinstance(row[field], str) or len(row[field].strip()) < minimum:
            raise ValueError(f"{sample_id}: {field} is too short or not a string")

    type_evidence = validate_evidence_map(row["type_evidence"], sample_id, "type_evidence")
    positive = validate_evidence_map(row["positive_support"], sample_id, "positive_support")
    contradiction = validate_evidence_map(
        row["contradiction_or_scope_exclusion"],
        sample_id,
        "contradiction_or_scope_exclusion",
    )
    records_by_url = {
        record.get("url"): record
        for record in evidence_row.get("evidence_context", {}).get("records", [])
        if record.get("fetch_status") == "ok" and record.get("text_snippet")
    }
    allowed_urls = set(records_by_url)
    used_urls = {
        url
        for mapping in (type_evidence, positive, contradiction)
        for urls in mapping.values()
        for url in urls
    }
    unknown = used_urls - allowed_urls
    if unknown:
        raise ValueError(f"{sample_id}: uses unavailable evidence URLs {sorted(unknown)}")
    if row["type_status"] == "determinate" and empty_evidence_map(type_evidence):
        exact_structured_equality = (
            row["discrepancy_label"] == "equivalent"
            and evidence_row.get("nvd_value") == evidence_row.get("ghsa_value")
        )
        if not exact_structured_equality:
            raise ValueError(f"{sample_id}: determinate type lacks evidence URLs")
    validate_evidence_claims(
        row["evidence_claims"],
        sample_id,
        records_by_url,
        type_evidence,
        positive,
        contradiction,
    )

    if row["discrepancy_label"] != "factual_conflict":
        if not (
            row["reviewed_source"] == "not_applicable"
            and row["source_status"] == "not_applicable"
            and row["source_confidence"] == "not_applicable"
            and empty_evidence_map(positive)
            and empty_evidence_map(contradiction)
        ):
            raise ValueError(f"{sample_id}: non-FC source task must be not_applicable")
        return

    if row["reviewed_source"] == "not_applicable" or row["source_confidence"] == "not_applicable":
        raise ValueError(f"{sample_id}: FC source task cannot be not_applicable")
    expected_source_status = (
        "abstain"
        if row["reviewed_source"] == "abstain" or row["source_confidence"] == "low"
        else "determinate"
    )
    if row["source_status"] != expected_source_status:
        raise ValueError(f"{sample_id}: source_status is inconsistent")
    if row["source_confidence"] == "low" and row["reviewed_source"] != "abstain":
        raise ValueError(f"{sample_id}: low-confidence source must abstain")
    source = row["reviewed_source"]
    if source == "nvd" and not (positive["nvd"] and contradiction["ghsa"]):
        raise ValueError(f"{sample_id}: nvd requires support and GHSA contradiction")
    if source == "ghsa" and not (positive["ghsa"] and contradiction["nvd"]):
        raise ValueError(f"{sample_id}: ghsa requires support and NVD contradiction")
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


def merge_decisions(left: dict, right: dict) -> dict:
    exact_label = left["discrepancy_label"] == right["discrepancy_label"]
    exact_artifact = left["artifact_relation"] == right["artifact_relation"]
    type_accepted = (
        exact_label
        and exact_artifact
        and left["type_status"] == "determinate"
        and right["type_status"] == "determinate"
    )
    accepted_label = left["discrepancy_label"] if type_accepted else "uncertain"
    source_accepted = False
    if type_accepted and accepted_label != "factual_conflict":
        source_status = "not_applicable"
        source = "not_applicable"
        exact_source = True
    elif type_accepted:
        exact_source = left["reviewed_source"] == right["reviewed_source"]
        source_accepted = (
            exact_source
            and left["source_status"] == "determinate"
            and right["source_status"] == "determinate"
        )
        source_status = "strict_determinate" if source_accepted else "abstain"
        source = left["reviewed_source"] if source_accepted else "abstain"
    else:
        exact_source = left["reviewed_source"] == right["reviewed_source"]
        source_status = "not_eligible"
        source = "abstain"
    audit_evidence_urls = sorted(
        {
            url
            for decision in (left, right)
            for field in (
                "type_evidence",
                "positive_support",
                "contradiction_or_scope_exclusion",
            )
            for urls in decision[field].values()
            for url in urls
        }
    )
    type_evidence_urls = (
        sorted(
            {
                url
                for decision in (left, right)
                for urls in decision["type_evidence"].values()
                for url in urls
            }
        )
        if type_accepted
        else []
    )
    source_evidence_urls = (
        sorted(
            {
                url
                for decision in (left, right)
                for field in ("positive_support", "contradiction_or_scope_exclusion")
                for urls in decision[field].values()
                for url in urls
            }
        )
        if source_accepted
        else []
    )
    return {
        "artifact_type": "affected_versions_holdout_v2_dual_codex_consensus",
        "sample_id": left["sample_id"],
        "cve_id": left["cve_id"],
        "field": "affected_versions",
        "type_consensus_status": "strict_determinate" if type_accepted else "abstain",
        "artifact_relation": left["artifact_relation"] if type_accepted else "uncertain",
        "discrepancy_label": accepted_label,
        "source_consensus_status": source_status,
        "adjudicated_source": source,
        "exact_label_agreement": exact_label,
        "exact_artifact_agreement": exact_artifact,
        "exact_source_agreement": exact_source,
        "agent_a_type_confidence": left["type_confidence"],
        "agent_b_type_confidence": right["type_confidence"],
        "agent_a_source_confidence": left["source_confidence"],
        "agent_b_source_confidence": right["source_confidence"],
        "type_consensus_evidence_urls": type_evidence_urls,
        "source_consensus_evidence_urls": source_evidence_urls,
        "per_agent_audit_evidence_urls": audit_evidence_urls,
        "agent_a_type_rationale": left["type_rationale"],
        "agent_b_type_rationale": right["type_rationale"],
        "agent_a_source_rationale": left["source_rationale"],
        "agent_b_source_rationale": right["source_rationale"],
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
    blind_worklist_path = resolve(args.blind_worklist)
    blind_manifest_path = resolve(args.blind_manifest)
    holdout_manifest_path = resolve(args.holdout_manifest)
    prompt_path = resolve(args.prompt)
    output_dir = resolve(args.output_dir)
    validate_distinct_reviewer_files(agent_a_path, agent_b_path)

    blind_manifest = json.loads(blind_manifest_path.read_text(encoding="utf-8"))
    if not all(
        blind_manifest.get(key) is False
        for key in ("contains_labels", "contains_method_predictions", "contains_prior_candidates")
    ):
        raise ValueError("blind manifest does not prove label isolation")
    if blind_manifest["input"]["sha256"] != sha256(evidence_path):
        raise ValueError("blind worklist and merge use different evidence snapshots")
    if blind_manifest["output"]["sha256"] != sha256(blind_worklist_path):
        raise ValueError("blind worklist hash differs from its manifest")

    evidence = load_jsonl(evidence_path)
    blind = load_jsonl(blind_worklist_path)
    agent_a = load_jsonl(agent_a_path)
    agent_b = load_jsonl(agent_b_path)
    expected_ids = set(evidence)
    if len(expected_ids) != args.expected_rows:
        raise ValueError(f"expected {args.expected_rows} evidence rows, found {len(expected_ids)}")
    if set(blind) != expected_ids or set(agent_a) != expected_ids or set(agent_b) != expected_ids:
        raise ValueError("agent identity coverage mismatch")
    expected_top_level_keys = set(blind_manifest["allowed_top_level_keys"])
    for sample_id, row in blind.items():
        if set(row) != expected_top_level_keys:
            raise ValueError(f"{sample_id}: blind top-level keys differ from manifest")
        forbidden = forbidden_blind_keys(row)
        if forbidden:
            raise ValueError(f"{sample_id}: forbidden blind keys remain {forbidden[:3]}")

    evidence_order = jsonl_sample_order(evidence_path)
    blind_order = jsonl_sample_order(blind_worklist_path)
    agent_a_order = jsonl_sample_order(agent_a_path)
    agent_b_order = jsonl_sample_order(agent_b_path)
    if not (evidence_order == blind_order == agent_a_order == agent_b_order):
        raise ValueError("evidence, blind worklist, and reviewer output order must match")
    prompt_hash = sha256(prompt_path)
    blind_hash = sha256(blind_worklist_path)
    for sample_id in evidence_order:
        validate_contract(
            agent_a[sample_id],
            evidence[sample_id],
            args.agent_a_reviewer_id,
            prompt_hash,
            blind_hash,
        )
        validate_contract(
            agent_b[sample_id],
            evidence[sample_id],
            args.agent_b_reviewer_id,
            prompt_hash,
            blind_hash,
        )
    agent_a_run_ids = {row["review_run_id"] for row in agent_a.values()}
    agent_b_run_ids = {row["review_run_id"] for row in agent_b.values()}
    if len(agent_a_run_ids) != 1 or len(agent_b_run_ids) != 1:
        raise ValueError("each reviewer file must use one review_run_id")
    if agent_a_run_ids == agent_b_run_ids:
        raise ValueError("review_run_id must differ between reviewers")

    rows = [merge_decisions(agent_a[sample_id], agent_b[sample_id]) for sample_id in evidence_order]
    strict_type = [row for row in rows if row["type_consensus_status"] == "strict_determinate"]
    strict_fc = [row for row in strict_type if row["discrepancy_label"] == "factual_conflict"]
    strict_source = [row for row in strict_fc if row["source_consensus_status"] == "strict_determinate"]
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "affected_versions_holdout_v2_consensus.jsonl"
    write_jsonl(output_path, rows)
    ordered_ids = evidence_order
    strict_fc_ids = {row["sample_id"] for row in strict_fc}
    exact_source_on_fc = sum(row["exact_source_agreement"] for row in strict_fc)
    summary = {
        "artifact_type": "affected_versions_holdout_v2_dual_codex_consensus_summary",
        "label_is_human": False,
        "eligible_for_human_gold_claim": False,
        "eligible_for_independent_human_holdout_claim": False,
        "rows": len(rows),
        "exact_label_agreement": sum(row["exact_label_agreement"] for row in rows),
        "exact_artifact_agreement": sum(row["exact_artifact_agreement"] for row in rows),
        "strict_type_determinate": len(strict_type),
        "strict_type_coverage": len(strict_type) / len(rows),
        "strict_type_counts": dict(sorted(Counter(row["discrepancy_label"] for row in strict_type).items())),
        "strict_fc_rows": len(strict_fc),
        "exact_source_agreement_on_strict_fc": exact_source_on_fc,
        "strict_source_determinate": len(strict_source),
        "strict_source_coverage_within_fc": (
            len(strict_source) / len(strict_fc) if strict_fc else None
        ),
        "strict_source_counts": dict(sorted(Counter(row["adjudicated_source"] for row in strict_source).items())),
        "label_kappa": cohen_kappa(
            [agent_a[sample_id]["discrepancy_label"] for sample_id in ordered_ids],
            [agent_b[sample_id]["discrepancy_label"] for sample_id in ordered_ids],
            LABELS,
        ),
        "artifact_kappa": cohen_kappa(
            [agent_a[sample_id]["artifact_relation"] for sample_id in ordered_ids],
            [agent_b[sample_id]["artifact_relation"] for sample_id in ordered_ids],
            ARTIFACT_RELATIONS,
        ),
        "source_kappa_on_strict_fc": cohen_kappa(
            [agent_a[sample_id]["reviewed_source"] for sample_id in ordered_ids if sample_id in strict_fc_ids],
            [agent_b[sample_id]["reviewed_source"] for sample_id in ordered_ids if sample_id in strict_fc_ids],
            ("nvd", "ghsa", "neither", "abstain"),
        ),
        "inputs": {
            "evidence": {"path": str(evidence_path), "sha256": sha256(evidence_path)},
            "agent_a": {"path": str(agent_a_path), "sha256": sha256(agent_a_path)},
            "agent_b": {"path": str(agent_b_path), "sha256": sha256(agent_b_path)},
            "blind_worklist": {"path": str(blind_worklist_path), "sha256": blind_hash},
            "blind_manifest": {"path": str(blind_manifest_path), "sha256": sha256(blind_manifest_path)},
            "holdout_manifest": {"path": str(holdout_manifest_path), "sha256": sha256(holdout_manifest_path)},
            "prompt": {"path": str(prompt_path), "sha256": sha256(prompt_path)},
        },
        "output": {"path": str(output_path), "sha256": sha256(output_path)},
        "cautions": [
            "Both reviewers are Codex agents, not human annotators.",
            "Type and FC-source consensus are merged as separate endpoints.",
            "All accepted rows remain expert candidates requiring real human signoff.",
        ],
    }
    summary_path = output_dir / "affected_versions_holdout_v2_consensus_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {output_path}")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
