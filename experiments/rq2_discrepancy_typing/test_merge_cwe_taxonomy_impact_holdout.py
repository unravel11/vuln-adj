#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import merge_cwe_taxonomy_impact_holdout as target


def source_row() -> dict:
    return {
        "review_id": "rq2_cwe_taxonomy_impact:001",
        "cve_id": "CVE-2026-0001",
        "official_cross_source_ancestor_descendant_paths": [
            {
                "path": [
                    {"cwe_id": "CWE-1"},
                    {"cwe_id": "CWE-2"},
                ]
            }
        ],
        "review_contract": {
            "set_relation": ["fully_ancestor_descendant_compatible"],
            "discrepancy_label": ["representation_discrepancy"],
            "taxonomy_support_verdict": ["supports_granularity_only"],
            "confidence": ["high", "low"],
        },
    }


def review_row() -> dict:
    return {
        "reviewer_id": "codex_cwe_impact_a",
        "run_id": "run-a",
        "review_id": "rq2_cwe_taxonomy_impact:001",
        "cve_id": "CVE-2026-0001",
        "set_relation": "fully_ancestor_descendant_compatible",
        "discrepancy_label": "representation_discrepancy",
        "taxonomy_support_verdict": "supports_granularity_only",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The official path establishes a granularity relation, and the supplied "
            "CVE context describes the same weakness mechanism at both abstraction levels."
        ),
        "supporting_cwe_paths": ["CWE-1>CWE-2"],
    }


class MergeCweTaxonomyImpactHoldoutTests(unittest.TestCase):
    def write_review(self, row: dict) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        with handle:
            handle.write(json.dumps(row) + "\n")
        return Path(handle.name)

    def test_validate_reviews_accepts_contract_row(self) -> None:
        path = self.write_review(review_row())
        self.addCleanup(path.unlink)
        rows = target.validate_reviews(path, [source_row()], "codex_cwe_impact_a")
        self.assertEqual(len(rows), 1)

    def test_validate_reviews_rejects_unknown_path(self) -> None:
        row = review_row()
        row["supporting_cwe_paths"] = ["CWE-1>CWE-9"]
        path = self.write_review(row)
        self.addCleanup(path.unlink)
        with self.assertRaisesRegex(ValueError, "unknown supporting paths"):
            target.validate_reviews(path, [source_row()], "codex_cwe_impact_a")

    def test_evaluate_subset_counts_methods(self) -> None:
        result = target.evaluate_subset(
            [
                {
                    "consensus_label": "representation_discrepancy",
                    "current_prediction": "factual_conflict",
                    "taxonomy_v1_prediction": "representation_discrepancy",
                }
            ]
        )
        self.assertEqual(result["current"]["correct"], 0)
        self.assertEqual(result["taxonomy_v1"]["correct"], 1)
        self.assertEqual(result["taxonomy_minus_current_accuracy"], 1.0)
        self.assertEqual(result["paired_diagnostic"]["taxonomy_wins"], 1)
        self.assertEqual(result["paired_diagnostic"]["current_wins"], 0)

    def test_priority_reason_selects_unresolved_and_regression(self) -> None:
        unresolved = {
            "agent_a": {"discrepancy_label": "uncertain"},
            "agent_b": {"discrepancy_label": "uncertain"},
            "strict_consensus": False,
            "consensus_label": "uncertain",
            "current_prediction": "factual_conflict",
            "taxonomy_v1_prediction": "representation_discrepancy",
        }
        self.assertEqual(
            target.priority_reason(unresolved), "dual_codex_label_unresolved"
        )
        regression = {
            "agent_a": {"discrepancy_label": "factual_conflict"},
            "agent_b": {"discrepancy_label": "factual_conflict"},
            "strict_consensus": True,
            "consensus_label": "factual_conflict",
            "current_prediction": "factual_conflict",
            "taxonomy_v1_prediction": "representation_discrepancy",
        }
        self.assertEqual(
            target.priority_reason(regression),
            "candidate_regression_on_strict_consensus",
        )


if __name__ == "__main__":
    unittest.main()
