#!/usr/bin/env python3

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

import merge_affected_versions_holdout_v2_adjudication as target


URL = "https://example.com/CVE-2026-0001"
QUOTE = "literal evidence snippet for test"


def evidence() -> dict:
    return {
        "cve_id": "CVE-2026-0001",
        "evidence_context": {
            "records": [{"url": URL, "fetch_status": "ok", "text_snippet": QUOTE}]
        },
    }


def mapping(nvd=None, ghsa=None, third=None) -> dict:
    return {"nvd": nvd or [], "ghsa": ghsa or [], "third": third or []}


def decision(label: str = "representation_discrepancy", source: str = "not_applicable") -> dict:
    fc = label == "factual_conflict"
    claims = [
        {
            "url": URL,
            "endpoint": "type",
            "target": "nvd",
            "role": "type_support",
            "quote": QUOTE,
            "interpretation": "The literal test quote supports the selected discrepancy type.",
        }
    ]
    if fc and source == "nvd":
        claims.extend(
            [
                {
                    "url": URL,
                    "endpoint": "source",
                    "target": "nvd",
                    "role": "positive_support",
                    "quote": QUOTE,
                    "interpretation": "The literal test quote positively supports the NVD value.",
                },
                {
                    "url": URL,
                    "endpoint": "source",
                    "target": "ghsa",
                    "role": "contradiction",
                    "quote": QUOTE,
                    "interpretation": "The literal test quote contradicts the GHSA value in scope.",
                },
            ]
        )
    return {
        "sample_id": "affected_versions_holdout_v2:001",
        "cve_id": "CVE-2026-0001",
        "field": "affected_versions",
        "reviewer_id": "agent_a",
        "review_run_id": "agent-a-test-run",
        "prompt_sha256": "prompt-hash",
        "blind_worklist_sha256": "blind-hash",
        "artifact_relation": "same_artifact",
        "discrepancy_label": label,
        "type_status": "determinate",
        "type_confidence": "high",
        "type_evidence": mapping(nvd=[URL]),
        "reviewed_source": source,
        "source_status": "determinate" if fc and source != "abstain" else ("abstain" if fc else "not_applicable"),
        "source_confidence": "high" if fc else "not_applicable",
        "positive_support": mapping(nvd=[URL]) if fc and source == "nvd" else mapping(),
        "contradiction_or_scope_exclusion": mapping(ghsa=[URL]) if fc and source == "nvd" else mapping(),
        "evidence_claims": claims,
        "artifact_assessment": "The two source records describe the same test artifact.",
        "range_assessment": "The range relation is explicitly assessed for the test.",
        "type_rationale": "The available structured values and cited evidence support this discrepancy type for the test row.",
        "source_rationale": "Source task is not applicable for this non-conflict type." if not fc else "NVD is supported and GHSA is contradicted.",
        "unresolved": "",
        "label_is_human": False,
    }


class V2MergeTests(unittest.TestCase):
    def test_non_fc_requires_not_applicable_source(self) -> None:
        row = decision()
        row["reviewed_source"] = "abstain"
        row["source_status"] = "abstain"
        row["source_confidence"] = "low"
        with self.assertRaisesRegex(ValueError, "must be not_applicable"):
            target.validate_contract(row, evidence())

    def test_valid_one_sided_fc_contract(self) -> None:
        target.validate_contract(decision("factual_conflict", "nvd"), evidence())

    def test_type_consensus_survives_fc_source_disagreement(self) -> None:
        left = decision("factual_conflict", "nvd")
        right = copy.deepcopy(left)
        right["reviewed_source"] = "abstain"
        right["source_status"] = "abstain"
        right["source_confidence"] = "medium"
        right["positive_support"] = mapping()
        right["contradiction_or_scope_exclusion"] = mapping()
        merged = target.merge_decisions(left, right)
        self.assertEqual(merged["type_consensus_status"], "strict_determinate")
        self.assertEqual(merged["discrepancy_label"], "factual_conflict")
        self.assertEqual(merged["source_consensus_status"], "abstain")

    def test_non_fc_consensus_has_not_applicable_source(self) -> None:
        merged = target.merge_decisions(decision(), decision())
        self.assertEqual(merged["type_consensus_status"], "strict_determinate")
        self.assertEqual(merged["source_consensus_status"], "not_applicable")
        self.assertEqual(merged["adjudicated_source"], "not_applicable")

    def test_fc_requires_same_artifact(self) -> None:
        row = decision("factual_conflict", "nvd")
        row["artifact_relation"] = "multi_artifact_scope"
        with self.assertRaisesRegex(ValueError, "requires same_artifact"):
            target.validate_contract(row, evidence())

    def test_low_confidence_type_must_be_uncertain(self) -> None:
        row = decision()
        row["type_confidence"] = "low"
        row["type_status"] = "abstain"
        with self.assertRaisesRegex(ValueError, "must be uncertain"):
            target.validate_contract(row, evidence())

    def test_identical_reviewer_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = Path(directory) / "a.jsonl"
            right = Path(directory) / "b.jsonl"
            left.write_text("same\n", encoding="utf-8")
            right.write_text("same\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contents are identical"):
                target.validate_distinct_reviewer_files(left, right)


if __name__ == "__main__":
    unittest.main()
