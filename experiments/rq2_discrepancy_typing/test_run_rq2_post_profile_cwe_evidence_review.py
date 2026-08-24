import unittest

from run_rq2_post_profile_cwe_evidence_review import (
    ITEM_KEYS,
    output_schema,
    validate_model_rows,
)


def worklist_row():
    return {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "allowed_cwe_path_strings": ["CWE-770>CWE-400"],
        "review_contract": {
            "set_relation": ["fully_ancestor_descendant_compatible"],
            "discrepancy_label": ["representation_discrepancy", "factual_conflict", "uncertain"],
            "taxonomy_support_verdict": ["supports_granularity_only", "does_not_support_granularity_only", "insufficient"],
            "specific_mapping_verdict": ["same_mechanism_supported", "materially_different_or_contradicted", "insufficient"],
            "confidence": ["high", "medium", "low"],
        },
        "conditional_constraints": {
            "representation_discrepancy": {
                "taxonomy_support_verdict": "supports_granularity_only",
                "specific_mapping_verdict": "same_mechanism_supported",
                "confidence": ["high", "medium"],
                "needs_additional_review": False,
                "requires_cwe_path": True,
                "requires_frozen_evidence": True,
            },
            "factual_conflict": {
                "taxonomy_support_verdict": "does_not_support_granularity_only",
                "specific_mapping_verdict": "materially_different_or_contradicted",
                "confidence": ["high", "medium"],
                "needs_additional_review": False,
                "requires_frozen_evidence": True,
            },
            "uncertain": {
                "taxonomy_support_verdict": "insufficient",
                "specific_mapping_verdict": "insufficient",
                "confidence": "low",
                "needs_additional_review": True,
            },
        },
    }


def model_row():
    row = {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "set_relation": "fully_ancestor_descendant_compatible",
        "discrepancy_label": "uncertain",
        "taxonomy_support_verdict": "insufficient",
        "specific_mapping_verdict": "insufficient",
        "confidence": "low",
        "needs_additional_review": True,
        "rationale": "x",
        "supporting_cwe_paths": [],
        "supporting_evidence": [],
    }
    assert set(row) == ITEM_KEYS
    return row


class RunPostProfileCweEvidenceReviewTests(unittest.TestCase):
    def test_schema_binds_exact_row_count(self):
        schema = output_schema(3)
        items = schema["properties"]["items"]
        self.assertEqual(items["minItems"], 3)
        self.assertEqual(items["maxItems"], 3)

    def test_model_rows_preserve_identity_and_contract(self):
        validate_model_rows([model_row()], [worklist_row()])

    def test_identity_mismatch_is_rejected(self):
        row = model_row()
        row["cve_id"] = "CVE-2026-9999"
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            validate_model_rows([row], [worklist_row()])

    def test_uncertain_medium_confidence_is_rejected_before_write(self):
        row = model_row()
        row["confidence"] = "medium"
        with self.assertRaisesRegex(ValueError, "conditional confidence"):
            validate_model_rows([row], [worklist_row()])

    def test_reformatted_cwe_path_is_rejected_before_write(self):
        row = model_row()
        row.update(
            {
                "discrepancy_label": "representation_discrepancy",
                "taxonomy_support_verdict": "supports_granularity_only",
                "specific_mapping_verdict": "same_mechanism_supported",
                "confidence": "high",
                "needs_additional_review": False,
                "supporting_cwe_paths": ["CWE-770 -> CWE-400"],
                "supporting_evidence": [{"url": "x", "quote": "y"}],
            }
        )
        with self.assertRaisesRegex(ValueError, "nonliteral CWE path"):
            validate_model_rows([row], [worklist_row()])


if __name__ == "__main__":
    unittest.main()
