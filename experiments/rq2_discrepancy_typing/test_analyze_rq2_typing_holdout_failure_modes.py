#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_rq2_typing_holdout_failure_modes as target


def severity(label: str, score, vector: str | None) -> dict:
    return {"label": label, "score": score, "vector": vector}


class AnalyzeRQ2TypingHoldoutFailureModesTests(unittest.TestCase):
    def test_moderate_and_medium_are_canonical_aliases(self) -> None:
        self.assertEqual(
            target.canonical_severity(severity("MODERATE", None, None)),
            "MEDIUM",
        )

    def test_vector_prefix_is_distinguished_from_exact(self) -> None:
        short = severity("MEDIUM", None, "CVSS:4.0/AV:N/AC:L")
        long = severity("MEDIUM", 5.0, "CVSS:4.0/AV:N/AC:L/E:X")
        self.assertEqual(target.vector_relation(short, long), "strict_prefix")

    def test_missing_score_with_same_claim_is_incomplete_diagnostic(self) -> None:
        row = {
            "field": "severity",
            "baseline_status": "equivalent",
            "nvd_value": severity("HIGH", 7.5, "CVSS:3.1/AV:N/AC:L"),
            "ghsa_value": severity("HIGH", None, "CVSS:3.1/AV:N/AC:L"),
        }
        self.assertEqual(target.post_hoc_candidate(row)[0], "incomplete")

    def test_same_label_with_different_vectors_is_conflict_diagnostic(self) -> None:
        row = {
            "field": "severity",
            "baseline_status": "representation_discrepancy",
            "nvd_value": severity("MEDIUM", 5.0, "CVSS:3.1/AV:N/AC:L"),
            "ghsa_value": severity("MODERATE", None, "CVSS:3.1/AV:N/AC:H"),
        }
        self.assertEqual(target.post_hoc_candidate(row)[0], "factual_conflict")

    def test_introduced_zero_without_upper_bound_is_unbounded(self) -> None:
        claim = [
            {
                "vulnerable": True,
                "package_name": "example",
                "introduced": "0",
                "version_start_including": "0",
                "fixed": None,
                "version": None,
                "version_end_excluding": None,
                "version_end_including": None,
                "version_start_excluding": None,
            }
        ]
        self.assertTrue(target.is_unbounded_affected_claim(claim))

    def test_one_sided_unbounded_claim_is_incomplete_diagnostic(self) -> None:
        row = {
            "field": "affected_versions",
            "baseline_status": "equivalent",
            "nvd_value": [],
            "ghsa_value": [
                {
                    "vulnerable": True,
                    "package_name": "example",
                    "introduced": "0",
                    "version_start_including": "0",
                }
            ],
        }
        self.assertEqual(target.post_hoc_candidate(row)[0], "incomplete")

    def test_bounded_claim_is_not_retyped_by_projection_diagnostic(self) -> None:
        row = {
            "field": "affected_versions",
            "baseline_status": "equivalent",
            "nvd_value": [],
            "ghsa_value": [
                {
                    "vulnerable": True,
                    "package_name": "example",
                    "introduced": "0",
                    "fixed": "2.0.0",
                }
            ],
        }
        self.assertEqual(target.post_hoc_candidate(row)[0], "equivalent")


if __name__ == "__main__":
    unittest.main()
