import unittest

from run_rq2_post_profile_cwe_all50_review import (
    ITEM_KEYS,
    output_schema,
    validate_model_row,
)


def source(relation="disjoint"):
    return {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "deterministic_set_relation": relation,
        "allowed_cwe_path_strings": ["CWE-770>CWE-400"],
        "evidence_context": {
            "records": [
                {
                    "source_url": "https://example.test/advisory",
                    "fetch_status": "ok",
                    "text_snippet": "The parser allocates memory without a fixed limit and can exhaust available resources.",
                }
            ]
        },
    }


def row(label="representation_discrepancy"):
    result = {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "set_relation": "disjoint",
        "discrepancy_label": label,
        "taxonomy_compatibility": "full",
        "specific_mapping_verdict": "same_mechanism_or_not_needed",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The official taxonomy path and the frozen advisory describe one concrete "
            "resource-exhaustion mechanism at different levels, so this row is a "
            "granularity-only representation discrepancy rather than a conflict."
        ),
        "supporting_cwe_paths": ["CWE-770>CWE-400"],
        "supporting_evidence": [
            {
                "url": "https://example.test/advisory",
                "quote": "allocates memory without a fixed limit and can exhaust available resources",
            }
        ],
    }
    assert set(result) == ITEM_KEYS
    return result


class RunPostProfileCweAll50ReviewTests(unittest.TestCase):
    def test_schema_binds_batch_size(self):
        schema = output_schema(5)["properties"]["items"]
        self.assertEqual(schema["minItems"], 5)
        self.assertEqual(schema["maxItems"], 5)

    def test_disjoint_representation_requires_literal_path_and_evidence(self):
        validate_model_row(row(), source())
        invalid = row()
        invalid["supporting_cwe_paths"] = ["CWE-770 -> CWE-400"]
        with self.assertRaisesRegex(ValueError, "nonliteral CWE path"):
            validate_model_row(invalid, source())
        invalid = row()
        invalid["supporting_evidence"] = []
        with self.assertRaisesRegex(ValueError, "omits evidence"):
            validate_model_row(invalid, source())

    def test_exact_and_subset_controls_have_fixed_labels(self):
        exact = row("equivalent")
        exact.update(
            {
                "set_relation": "exact_set",
                "taxonomy_compatibility": "not_needed",
                "supporting_cwe_paths": [],
                "supporting_evidence": [],
            }
        )
        validate_model_row(exact, source("exact_set"))
        subset = {
            **exact,
            "set_relation": "literal_strict_subset",
            "discrepancy_label": "incomplete",
            "supporting_evidence": [
                {
                    "url": "https://example.test/advisory",
                    "quote": "allocates memory without a fixed limit and can exhaust available resources",
                }
            ],
        }
        validate_model_row(subset, source("literal_strict_subset"))

        conflict = {
            **subset,
            "discrepancy_label": "factual_conflict",
            "taxonomy_compatibility": "none",
            "specific_mapping_verdict": "materially_different_or_contradicted",
        }
        validate_model_row(conflict, source("literal_strict_subset"))

    def test_uncertain_is_fail_closed(self):
        uncertain = row("uncertain")
        uncertain.update(
            {
                "taxonomy_compatibility": "insufficient",
                "specific_mapping_verdict": "insufficient",
                "confidence": "low",
                "needs_additional_review": True,
                "supporting_cwe_paths": [],
                "supporting_evidence": [],
            }
        )
        validate_model_row(uncertain, source())
        uncertain["confidence"] = "medium"
        with self.assertRaisesRegex(ValueError, "invalid uncertain"):
            validate_model_row(uncertain, source())

    def test_nonliteral_quote_is_rejected_before_write(self):
        invalid = row()
        invalid["supporting_evidence"][0]["quote"] = (
            "This quote is not present in the frozen evidence record."
        )
        with self.assertRaisesRegex(ValueError, "literal frozen substring"):
            validate_model_row(invalid, source())


if __name__ == "__main__":
    unittest.main()
