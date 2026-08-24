#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import merge_cwe_taxonomy_evidence_secondary_audit as target


URL = "https://github.com/acme/project/commit/abc"
QUOTE = "The vulnerable function passes attacker input to an operating system shell command."


def worklist_row() -> dict:
    return {
        "review_id": "rq2_cwe_taxonomy_impact:001",
        "cve_id": "CVE-2026-0001",
        "official_cross_source_ancestor_descendant_paths": [
            {"path": [{"cwe_id": "CWE-78"}, {"cwe_id": "CWE-77"}]}
        ],
        "evidence_context": {
            "records": [
                {
                    "source_url": URL,
                    "fetch_status": "ok",
                    "text_snippet": f"Patch note. {QUOTE} Upgrade now.",
                }
            ]
        },
        "review_contract": {
            "set_relation": ["fully_ancestor_descendant_compatible"],
            "discrepancy_label": [
                "representation_discrepancy",
                "factual_conflict",
                "uncertain",
            ],
            "taxonomy_support_verdict": [
                "supports_granularity_only",
                "does_not_support_granularity_only",
                "insufficient",
            ],
            "specific_mapping_verdict": [
                "same_mechanism_supported",
                "materially_different_or_contradicted",
                "insufficient",
            ],
            "confidence": ["high", "medium", "low"],
        },
    }


def review() -> dict:
    return {
        "reviewer_id": "codex_cwe_evidence_c",
        "run_id": "run-c",
        "review_id": "rq2_cwe_taxonomy_impact:001",
        "cve_id": "CVE-2026-0001",
        "set_relation": "fully_ancestor_descendant_compatible",
        "discrepancy_label": "representation_discrepancy",
        "taxonomy_support_verdict": "supports_granularity_only",
        "specific_mapping_verdict": "same_mechanism_supported",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The official path makes OS command injection a subtype of command "
            "injection, while the literal patch evidence establishes an operating "
            "system shell command and therefore supports both mappings as one mechanism."
        ),
        "supporting_cwe_paths": ["CWE-78>CWE-77"],
        "supporting_evidence": [{"url": URL, "quote": QUOTE}],
    }


def validate_one(row: dict) -> list[dict]:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "review.jsonl"
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        return target.validate_reviews(
            path, [worklist_row()], "codex_cwe_evidence_c"
        )


class MergeCweTaxonomyEvidenceSecondaryAuditTests(unittest.TestCase):
    def test_literal_evidence_review_is_valid(self) -> None:
        self.assertEqual(validate_one(review())[0]["discrepancy_label"], "representation_discrepancy")

    def test_nonliteral_quote_is_rejected(self) -> None:
        row = review()
        row["supporting_evidence"][0]["quote"] = "This quote does not occur in the frozen evidence record."
        with self.assertRaisesRegex(ValueError, "not literal"):
            validate_one(row)

    def test_uncertain_requires_low_confidence_and_review(self) -> None:
        row = review()
        row.update(
            {
                "discrepancy_label": "uncertain",
                "taxonomy_support_verdict": "insufficient",
                "specific_mapping_verdict": "insufficient",
                "confidence": "medium",
                "needs_additional_review": False,
                "supporting_evidence": [],
            }
        )
        with self.assertRaisesRegex(ValueError, "uncertain row"):
            validate_one(row)

    def test_secondary_unresolved_does_not_fallback_to_stage_one(self) -> None:
        stage1 = {
            "review_id": "rq2_cwe_taxonomy_impact:001",
            "cve_id": "CVE-2026-0001",
            "strict_consensus": True,
            "consensus_label": "factual_conflict",
            "primary_seed_overlap": False,
            "current_prediction": "factual_conflict",
            "taxonomy_v1_prediction": "representation_discrepancy",
        }
        secondary = {
            "review_id": stage1["review_id"],
            "strict_consensus": False,
            "consensus_label": None,
        }
        combined = target.combine_candidates(
            [stage1], {stage1["review_id"]}, {stage1["review_id"]: secondary}
        )
        self.assertFalse(combined[0]["strict_consensus"])
        self.assertEqual(combined[0]["consensus_source"], "unresolved_after_stage2")


if __name__ == "__main__":
    unittest.main()
