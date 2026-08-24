import json
import tempfile
import unittest
from pathlib import Path

from merge_rq2_post_profile_cwe_evidence_secondary import (
    strict_consensus,
    validate_reviews,
)


def source_row():
    snippet = "The parser allocates memory without a fixed limit and can exhaust available resources."
    return {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "review_contract": {
            "set_relation": ["fully_ancestor_descendant_compatible"],
            "discrepancy_label": ["representation_discrepancy", "factual_conflict", "uncertain"],
            "taxonomy_support_verdict": ["supports_granularity_only", "does_not_support_granularity_only", "insufficient"],
            "specific_mapping_verdict": ["same_mechanism_supported", "materially_different_or_contradicted", "insufficient"],
            "confidence": ["high", "medium", "low"],
        },
        "official_taxonomy": {
            "relation_profile": {
                "ancestor_descendant_paths": [
                    {"path": [{"cwe_id": "CWE-770"}, {"cwe_id": "CWE-400"}]}
                ]
            }
        },
        "evidence_context": {
            "records": [
                {
                    "source_url": "https://example.test/advisory",
                    "fetch_status": "ok",
                    "text_snippet": snippet,
                }
            ]
        },
    }


def review_row(reviewer_id="reviewer"):
    quote = "allocates memory without a fixed limit and can exhaust available resources"
    return {
        "reviewer_id": reviewer_id,
        "run_id": f"{reviewer_id}:run",
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "set_relation": "fully_ancestor_descendant_compatible",
        "discrepancy_label": "representation_discrepancy",
        "taxonomy_support_verdict": "supports_granularity_only",
        "specific_mapping_verdict": "same_mechanism_supported",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": "CWE-770 is the specific allocation-without-limits weakness under CWE-400, and the frozen advisory explicitly describes memory allocation without a fixed limit, so both assignments describe the same resource-exhaustion mechanism at different granularity.",
        "supporting_cwe_paths": ["CWE-770>CWE-400"],
        "supporting_evidence": [
            {"url": "https://example.test/advisory", "quote": quote}
        ],
    }


class MergePostProfileCweEvidenceSecondaryTests(unittest.TestCase):
    def test_literal_evidence_review_validates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            worklist = root / "worklist.jsonl"
            reviews = root / "reviews.jsonl"
            worklist.write_text(json.dumps(source_row()) + "\n", encoding="utf-8")
            reviews.write_text(json.dumps(review_row("reviewer")) + "\n", encoding="utf-8")
            validated = validate_reviews(reviews, worklist, "reviewer")
            self.assertEqual(len(validated), 1)

    def test_nonliteral_quote_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            worklist = root / "worklist.jsonl"
            reviews = root / "reviews.jsonl"
            invalid = review_row("reviewer")
            invalid["supporting_evidence"][0]["quote"] = "This quote is not present in the frozen evidence snippet."
            worklist.write_text(json.dumps(source_row()) + "\n", encoding="utf-8")
            reviews.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "literal frozen substring"):
                validate_reviews(reviews, worklist, "reviewer")

    def test_strict_consensus_requires_determinate_exact_agreement(self):
        left = review_row("left")
        right = review_row("right")
        self.assertEqual(
            strict_consensus(left, right),
            (True, "representation_discrepancy"),
        )
        right["specific_mapping_verdict"] = "insufficient"
        self.assertEqual(strict_consensus(left, right), (False, None))


if __name__ == "__main__":
    unittest.main()
