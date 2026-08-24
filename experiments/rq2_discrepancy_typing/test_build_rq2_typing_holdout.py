#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_rq2_typing_holdout as target


class BuildRq2TypingHoldoutTests(unittest.TestCase):
    def test_openai_contract_is_explicit(self) -> None:
        contract = target.openai_contract("gpt-5.5", 512)
        self.assertEqual(contract["backend"], "openai")
        self.assertEqual(contract["api_route"], "primary")
        self.assertEqual(contract["model"], "gpt-5.5")
        self.assertEqual(contract["max_output_tokens"], 512)
        self.assertEqual(contract["response_format"], "strict_json_schema")

    def test_equal_waterfill_covers_rare_stratum_and_balances_rest(self) -> None:
        quotas = target.equal_waterfill_quotas(
            {
                "factual_conflict": 3,
                "incomplete": 7000,
                "representation_discrepancy": 300,
            },
            60,
        )
        self.assertEqual(quotas["factual_conflict"], 3)
        self.assertEqual(sum(quotas.values()), 60)
        self.assertLessEqual(
            abs(quotas["incomplete"] - quotas["representation_discrepancy"]), 1
        )

    def test_hybrid_allocation_preserves_rare_coverage_and_total(self) -> None:
        quotas = target.hybrid_stratum_quotas(
            {
                "factual_conflict": 3,
                "incomplete": 7000,
                "representation_discrepancy": 300,
            },
            250,
        )
        self.assertEqual(quotas["factual_conflict"], 3)
        self.assertEqual(sum(quotas.values()), 250)
        self.assertGreater(quotas["incomplete"], quotas["representation_discrepancy"])

    def test_blind_row_omits_predictions_and_selection_stratum(self) -> None:
        row = {
            "sample_id": "rq2_typing_holdout_v1:001",
            "cve_id": "CVE-2026-0001",
            "nvd_source_id": "CVE-2026-0001",
            "ghsa_source_id": "GHSA-test",
            "field": "severity",
            "nvd_value": "HIGH",
            "ghsa_value": "LOW",
            "field_context": {},
            "package_names": {},
            "reference_context": {},
            "baseline_status": "factual_conflict",
            "sampling_stratum": {"baseline_status": "factual_conflict"},
        }
        blind = target.blind_row(row)
        self.assertNotIn("baseline_status", blind)
        self.assertNotIn("sampling_stratum", blind)
        self.assertEqual(target.forbidden_blind_keys(blind), [])

    def test_global_selector_skips_cve_already_used_by_another_field(self) -> None:
        selected = target.select_globally_unique_strata(
            {
                ("severity", "equivalent"): [
                    {"cve_id": "CVE-2026-0001"},
                    {"cve_id": "CVE-2026-0002"},
                ],
                ("published", "equivalent"): [
                    {"cve_id": "CVE-2026-0001"},
                    {"cve_id": "CVE-2026-0003"},
                ],
            },
            {
                ("severity", "equivalent"): 1,
                ("published", "equivalent"): 1,
            },
        )
        self.assertEqual(len({row["cve_id"] for row, _field, _status in selected}), 2)
        self.assertEqual({field for _row, field, _status in selected}, {"severity", "published"})

    def test_raw_reference_projection_does_not_apply_profile_normalization(self) -> None:
        encoded = "https://example.test/advisory%23L10-L20"
        nvd, ghsa = target.raw_field_values(
            {
                "cve_id": "CVE-2026-0001",
                "nvd": {"references": [{"url": encoded}]},
                "ghsa": [{"references": [{"url": "https://example.test/advisory"}]}],
            },
            "references",
        )
        self.assertEqual(nvd, [encoded])
        self.assertEqual(ghsa, ["https://example.test/advisory"])

    def test_prediction_row_keeps_non_target_fields_unchanged(self) -> None:
        source = {
            "sample_id": "rq2_typing_holdout_v1:001",
            "cve_id": "CVE-2026-0001",
            "field": "severity",
            "baseline_status": "factual_conflict",
        }
        row = target.prediction_row(
            source,
            {"CVE-2026-0001": "incomplete"},
            {"CVE-2026-0001": "incomplete"},
            {"CVE-2026-0001": "representation_discrepancy"},
        )
        self.assertEqual(
            {
                row["current"],
                row["reference_resource_identity_original_v1"],
                row["reference_resource_identity_audited_v1"],
                row["cwe_taxonomy_v1"],
                row["combined_original_v1"],
                row["combined_audited_v1"],
            },
            {"factual_conflict"},
        )


if __name__ == "__main__":
    unittest.main()
