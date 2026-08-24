#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import merge_affected_versions_holdout_adjudication as target


URL_NVD = "https://example.test/nvd"
URL_GHSA = "https://example.test/ghsa"


def evidence() -> dict:
    return {
        "sample_id": "affected_versions_holdout_v1:001",
        "cve_id": "CVE-2026-0001",
        "evidence_context": {
            "records": [
                {"url": URL_NVD, "fetch_status": "ok", "text_snippet": "nvd evidence"},
                {"url": URL_GHSA, "fetch_status": "ok", "text_snippet": "ghsa evidence"},
            ]
        },
    }


def decision() -> dict:
    return {
        "sample_id": "affected_versions_holdout_v1:001",
        "cve_id": "CVE-2026-0001",
        "field": "affected_versions",
        "discrepancy_label": "factual_conflict",
        "reviewed_source": "both",
        "adjudication_status": "determinate",
        "confidence": "high",
        "positive_support": {"nvd": [URL_NVD], "ghsa": [URL_GHSA], "third": []},
        "contradiction_or_scope_exclusion": {"nvd": [], "ghsa": [], "third": []},
        "artifact_assessment": "The records describe the same package artifact.",
        "range_assessment": "The two supported ranges have different fixed bounds.",
        "rationale": "Both source-specific values have direct positive support, while their fixed bounds remain incompatible.",
        "unresolved": "",
        "label_is_human": False,
    }


class HoldoutMergeTests(unittest.TestCase):
    def test_valid_both_contract_and_consensus(self) -> None:
        left = decision()
        right = copy.deepcopy(left)
        target.validate_contract(left, evidence())
        row = target.strict_consensus(left, right)
        self.assertEqual(row["consensus_status"], "strict_determinate")
        self.assertFalse(row["label_is_human"])

    def test_unknown_evidence_url_is_rejected(self) -> None:
        row = decision()
        row["positive_support"]["nvd"] = ["https://unknown.test/"]
        with self.assertRaisesRegex(ValueError, "unavailable evidence"):
            target.validate_contract(row, evidence())

    def test_unilateral_source_requires_other_side_contradiction(self) -> None:
        row = decision()
        row["reviewed_source"] = "nvd"
        row["positive_support"]["ghsa"] = []
        with self.assertRaisesRegex(ValueError, "GHSA contradiction"):
            target.validate_contract(row, evidence())

    def test_low_confidence_must_abstain(self) -> None:
        row = decision()
        row["confidence"] = "low"
        with self.assertRaisesRegex(ValueError, "adjudication_status"):
            target.validate_contract(row, evidence())


if __name__ == "__main__":
    unittest.main()
