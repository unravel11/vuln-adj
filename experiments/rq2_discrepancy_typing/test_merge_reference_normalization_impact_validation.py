#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import merge_reference_normalization_impact_validation as target


def worklist_row() -> dict:
    return {
        "review_id": "rq2_reference_identity:001",
        "cve_id": "CVE-2026-0001",
        "identity_groups": [
            {
                "group_id": "rq2_reference_identity:001:group:01",
                "members": [],
            }
        ],
        "review_contract": {
            "identity_verdict": [
                "all_aliases_same_resource",
                "one_or_more_not_same",
                "insufficient",
            ],
            "final_status": [
                "incomplete",
                "representation_discrepancy",
                "uncertain",
            ],
            "confidence": ["high", "medium", "low"],
        },
    }


def review() -> dict:
    return {
        "reviewer_id": "codex_reference_identity_e",
        "run_id": "run-e",
        "review_id": "rq2_reference_identity:001",
        "cve_id": "CVE-2026-0001",
        "identity_verdict": "all_aliases_same_resource",
        "final_status": "incomplete",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "Both frozen URLs carry the exact same GHSA identifier, and the supplied "
            "HTTP records expose that identifier in each identity's final URL or page "
            "text. The repository and global paths therefore denote one advisory resource."
        ),
        "group_decisions": [
            {
                "group_id": "rq2_reference_identity:001:group:01",
                "same_resource": True,
                "reason": (
                    "The exact GHSA identifier is preserved by both URL path forms "
                    "and appears in the frozen evidence for each identity."
                ),
            }
        ],
    }


def validate_one(value: dict) -> list[dict]:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "review.jsonl"
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        return target.validate_reviews(
            path, [worklist_row()], "codex_reference_identity_e", "run-e"
        )


class MergeReferenceNormalizationImpactValidationTests(unittest.TestCase):
    def test_valid_same_resource_review(self) -> None:
        self.assertEqual(
            validate_one(review())[0]["final_status"], "incomplete"
        )

    def test_same_resource_verdict_requires_true_group(self) -> None:
        value = review()
        value["group_decisions"][0]["same_resource"] = None
        with self.assertRaisesRegex(ValueError, "requires all true"):
            validate_one(value)

    def test_insufficient_requires_null_and_low_review(self) -> None:
        value = review()
        value.update(
            {
                "identity_verdict": "insufficient",
                "final_status": "uncertain",
                "confidence": "low",
                "needs_additional_review": True,
            }
        )
        value["group_decisions"][0]["same_resource"] = None
        self.assertEqual(
            validate_one(value)[0]["identity_verdict"], "insufficient"
        )

    def test_strict_consensus_requires_matching_group_decisions(self) -> None:
        left = review()
        right = copy.deepcopy(left)
        right["group_decisions"][0]["same_resource"] = False
        strict, status = target.strict_secondary(left, right)
        self.assertFalse(strict)
        self.assertIsNone(status)

    def test_unresolved_secondary_does_not_inherit_automatic_candidate(self) -> None:
        automatic = {
            "review_id": "rq2_reference_identity:001",
            "cve_id": "CVE-2026-0001",
            "validation_status": "structural_only",
        }
        secondary = {
            "review_id": automatic["review_id"],
            "strict_consensus": False,
            "consensus_status": None,
        }
        combined = target.combine_rows([automatic], [secondary])
        self.assertFalse(combined[0]["resolved_nonhuman"])
        self.assertIsNone(combined[0]["resolved_status"])


if __name__ == "__main__":
    unittest.main()
