#!/usr/bin/env python3

from __future__ import annotations

import unittest

import analyze_reference_normalization_audited_profile as target


class AnalyzeReferenceNormalizationAuditedProfileTests(unittest.TestCase):
    def test_profile_excludes_encoded_line_stripping(self) -> None:
        self.assertTrue(target.AUDITED_SETTINGS["force_https"])
        self.assertFalse(target.AUDITED_SETTINGS["strip_encoded_line_suffix"])
        self.assertTrue(target.AUDITED_SETTINGS["drop_known_presentation_query"])
        self.assertTrue(target.AUDITED_SETTINGS["resource_aliases"])

    def test_impact_alignment_requires_exact_supported_set(self) -> None:
        automatic = {
            "proof_required_groups": [
                {
                    "structural_eligibility": {
                        "rules": ["transport_upgrade"]
                    }
                }
            ]
        }
        combined = [
            {
                "cve_id": "CVE-2026-0001",
                "label_is_human": False,
                "requires_human_signoff": True,
                "candidate_incomplete_supported": True,
                "resolved_nonhuman": True,
                "automatic_validation": automatic,
            }
        ]
        full = {
            "changed_cve_ids": ["CVE-2026-0001"],
            "changed_vs_current_transitions": {
                "representation_discrepancy->incomplete": 1
            },
        }
        with self.assertRaisesRegex(ValueError, "56 unique"):
            target.validate_impact_alignment(combined, full)

    def test_metric_delta_reports_corrections_and_regressions(self) -> None:
        current = {
            "scope": {
                "agreement_count": 2,
                "agreement": 0.5,
                "macro_f1_over_supported_candidate_labels": 0.4,
                "corrections_vs_current": [],
                "regressions_vs_current": [],
            }
        }
        audited = {
            "scope": {
                "agreement_count": 3,
                "agreement": 0.75,
                "macro_f1_over_supported_candidate_labels": 0.6,
                "corrections_vs_current": ["a", "b"],
                "regressions_vs_current": ["c"],
            }
        }
        delta = target.metric_deltas(current, audited)["scope"]
        self.assertEqual(delta["agreement_count"], 1)
        self.assertEqual(delta["corrections_vs_current"], 2)
        self.assertEqual(delta["regressions_vs_current"], 1)


if __name__ == "__main__":
    unittest.main()
