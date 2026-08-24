#!/usr/bin/env python3

from __future__ import annotations

import unittest

import verify_rq2_post_profile_paired_outcome_envelope as target


class VerifyPairedOutcomeEnvelopeTests(unittest.TestCase):
    def test_recompute_is_symmetric_without_label_prior(self) -> None:
        source = []
        predictions = []
        fields = (
            "affected_versions",
            "cwe_ids",
            "published",
            "references",
            "severity",
        )
        for index in range(250):
            field = fields[index // 50]
            sample_id = f"sample:{index + 1:03d}"
            source.append(
                {"sample_id": sample_id, "cve_id": f"CVE-2026-{index + 1}", "field": field}
            )
            current = candidate = "equivalent"
            if field == "cwe_ids" and index in {50, 51, 52}:
                current = "factual_conflict"
                candidate = "representation_discrepancy"
            predictions.append(
                {
                    "sample_id": sample_id,
                    "current": current,
                    "cwe_taxonomy_v1": candidate,
                }
            )
        result = target.recompute(source, predictions)
        self.assertEqual(result["candidate_better"], 40)
        self.assertEqual(result["current_better"], 40)
        self.assertEqual(result["tied"], 45)
        self.assertEqual(result["delta_counts"]["3"], 1)
        self.assertEqual(result["delta_counts"]["-3"], 1)


if __name__ == "__main__":
    unittest.main()
