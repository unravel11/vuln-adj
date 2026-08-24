#!/usr/bin/env python3
"""Contract tests for dual-agent affected-version source re-audit."""

from __future__ import annotations

import unittest

from merge_affected_versions_source_reaudit import cohen_kappa, validate_contract


SAMPLE_ID = "affected_versions_fc_manual_check:test"
NVD_URL = "https://nvd.example/CVE-2026-0001"
GHSA_URL = "https://github.example/GHSA-test"
FAILED_URL = "https://vendor.example/failed"


def evidence_row() -> dict:
    return {
        "sample_id": SAMPLE_ID,
        "cve_id": "CVE-2026-0001",
        "evidence_context": {
            "records": [
                {
                    "url": NVD_URL,
                    "fetch_status": "ok",
                    "text_snippet": "NVD version evidence",
                },
                {
                    "url": GHSA_URL,
                    "fetch_status": "ok",
                    "text_snippet": "GHSA contradiction evidence",
                },
                {
                    "url": FAILED_URL,
                    "fetch_status": "timeout",
                    "text_snippet": "",
                },
            ]
        },
    }


def candidate_row() -> dict:
    return {"annotation": {"adjudicated_source": "nvd"}}


def decision() -> dict:
    return {
        "sample_id": SAMPLE_ID,
        "cve_id": "CVE-2026-0001",
        "prior_source": "nvd",
        "reviewed_source": "nvd",
        "source_status": "determinate",
        "confidence": "medium",
        "positive_support": {"nvd": [NVD_URL], "ghsa": [], "third": []},
        "contradiction_or_scope_exclusion": {
            "nvd": [],
            "ghsa": [GHSA_URL],
            "third": [],
        },
        "rationale": (
            "The first record supports the complete NVD value and the second "
            "affirmatively excludes the GHSA package scope."
        ),
        "unresolved": "",
        "label_is_human": False,
    }


class SourceReauditContractTests(unittest.TestCase):
    def test_one_sided_source_requires_positive_contradiction(self):
        row = decision()
        row["contradiction_or_scope_exclusion"]["ghsa"] = []
        with self.assertRaisesRegex(ValueError, "requires support and GHSA contradiction"):
            validate_contract(row, evidence_row(), candidate_row())

    def test_failed_fetch_cannot_be_cited(self):
        row = decision()
        row["contradiction_or_scope_exclusion"]["ghsa"] = [FAILED_URL]
        with self.assertRaisesRegex(ValueError, "unavailable evidence URLs"):
            validate_contract(row, evidence_row(), candidate_row())

    def test_valid_one_sided_source_passes(self):
        validate_contract(decision(), evidence_row(), candidate_row())

    def test_kappa_handles_exact_and_opposed_labels(self):
        self.assertEqual(cohen_kappa(["nvd", "ghsa"], ["nvd", "ghsa"]), 1.0)
        self.assertEqual(cohen_kappa(["nvd", "ghsa"], ["ghsa", "nvd"]), -1.0)


if __name__ == "__main__":
    unittest.main()
