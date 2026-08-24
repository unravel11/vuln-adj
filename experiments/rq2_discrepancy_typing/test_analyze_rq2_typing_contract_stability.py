#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_rq2_typing_contract_stability as target


def severity_seed() -> dict:
    return {
        "sample_id": "rq2_discrepancy_typing:001",
        "cve_id": "CVE-2026-0001",
        "field": "severity",
        "baseline_status": "equivalent",
        "nvd_value": "HIGH",
        "ghsa_value": "HIGH",
        "field_context": {
            "nvd": {
                "label": "HIGH",
                "score": 7.5,
                "vector": "CVSS:3.1/AV:N/AC:L",
            },
            "ghsa": {
                "label": "HIGH",
                "score": None,
                "vector": "CVSS:3.1/AV:N/AC:L",
            },
        },
    }


class AnalyzeRQ2TypingContractStabilityTests(unittest.TestCase):
    def test_seed_severity_uses_structured_context(self) -> None:
        projected = target.seed_severity_candidate_row(severity_seed())
        self.assertEqual(projected["nvd_value"]["score"], 7.5)
        self.assertIsNone(projected["ghsa_value"]["score"])

    def test_old_equivalent_label_penalizes_new_missing_score_contract(self) -> None:
        source = target.seed_severity_candidate_row(severity_seed())
        metrics, cases = target.evaluate_severity(
            "old", [(source, "equivalent")]
        )
        self.assertEqual(metrics["baseline_correct"], 1)
        self.assertEqual(metrics["new_contract_projection_correct"], 0)
        self.assertEqual(metrics["correct_delta"], -1)
        self.assertEqual(cases[0]["new_contract_projection"], "incomplete")

    def test_fresh_incomplete_label_favors_new_missing_score_contract(self) -> None:
        source = target.seed_severity_candidate_row(severity_seed())
        metrics, _cases = target.evaluate_severity(
            "fresh", [(source, "incomplete")]
        )
        self.assertEqual(metrics["baseline_correct"], 0)
        self.assertEqual(metrics["new_contract_projection_correct"], 1)
        self.assertEqual(metrics["correct_delta"], 1)

    def test_old_affected_projection_loss_is_detected_without_inventing_raw_value(self) -> None:
        source = {
            "sample_id": "rq2_discrepancy_typing:181",
            "cve_id": "CVE-2026-0002",
            "field": "affected_versions",
            "baseline_status": "equivalent",
            "nvd_value": [],
            "ghsa_value": [],
            "package_names": {"nvd": [], "ghsa": ["example/package"]},
        }
        primary = {
            source["sample_id"]: {
                "annotation": {"discrepancy_label": "equivalent"}
            }
        }
        cases = target.old_affected_projection_cases([source], primary)
        self.assertEqual(len(cases), 1)
        self.assertFalse(cases[0]["raw_claim_available_to_labeler"])
        self.assertNotIn("new_contract_projection", cases[0])

    def test_fresh_unbounded_claim_is_preserved(self) -> None:
        source = {
            "sample_id": "rq2_typing_holdout_v1:001",
            "cve_id": "CVE-2026-0003",
            "field": "affected_versions",
            "baseline_status": "equivalent",
            "nvd_value": [],
            "ghsa_value": [
                {
                    "vulnerable": True,
                    "package_name": "example/package",
                    "introduced": "0",
                    "version_start_including": "0",
                }
            ],
        }
        consensus = {
            source["sample_id"]: {
                "strict_consensus": True,
                "consensus_label": "incomplete",
            }
        }
        cases = target.fresh_affected_projection_cases([source], consensus)
        self.assertEqual(len(cases), 1)
        self.assertTrue(cases[0]["raw_claim_available_to_labeler"])
        self.assertEqual(cases[0]["new_contract_projection"], "incomplete")

    def test_gate_rejects_direction_reversal_and_missing_human_contract(self) -> None:
        severity = {
            "old": {"correct_delta": -2},
            "fresh": {"correct_delta": 3},
        }
        gate = target.build_gate(
            severity,
            [{"sample_id": "old"}],
            [{"sample_id": "fresh"}],
            signed_human_rows=0,
        )
        self.assertFalse(gate["passed"])
        self.assertEqual(gate["status"], "no_go_protocol_incompatible")
        self.assertFalse(gate["severity_direction_stable"])
        self.assertFalse(gate["affected_input_comparable"])
        self.assertFalse(gate["human_contract_available"])


if __name__ == "__main__":
    unittest.main()
