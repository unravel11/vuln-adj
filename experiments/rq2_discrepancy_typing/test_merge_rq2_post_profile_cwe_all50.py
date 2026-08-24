import json
import tempfile
import unittest
from pathlib import Path

from merge_rq2_post_profile_cwe_all50 import strict_consensus, validate_reviews


SNIPPET = "The parser allocates memory without a fixed limit and can exhaust available resources."


def worklist_row():
    return {
        "review_id": "review:1",
        "original_sample_id": "sample:1",
        "cve_id": "CVE-2026-0001",
        "deterministic_set_relation": "disjoint",
        "allowed_cwe_path_strings": ["CWE-770>CWE-400"],
        "evidence_context": {
            "records": [
                {
                    "source_url": "https://example.test/advisory",
                    "fetch_status": "ok",
                    "text_snippet": SNIPPET,
                }
            ]
        },
    }


def review(reviewer="reviewer"):
    return {
        "reviewer_id": reviewer,
        "run_id": f"{reviewer}:run",
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "set_relation": "disjoint",
        "discrepancy_label": "representation_discrepancy",
        "taxonomy_compatibility": "full",
        "specific_mapping_verdict": "same_mechanism_or_not_needed",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The official path makes the two assignments ancestor/descendant compatible, "
            "and the frozen advisory describes one concrete unbounded-allocation mechanism, "
            "so the sources differ in granularity rather than vulnerability mechanism."
        ),
        "supporting_cwe_paths": ["CWE-770>CWE-400"],
        "supporting_evidence": [
            {
                "url": "https://example.test/advisory",
                "quote": "allocates memory without a fixed limit and can exhaust available resources",
            }
        ],
    }


class MergePostProfileCweAll50Tests(unittest.TestCase):
    def test_literal_evidence_and_path_validate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            worklist = root / "worklist.jsonl"
            reviews = root / "reviews.jsonl"
            worklist.write_text(json.dumps(worklist_row()) + "\n", encoding="utf-8")
            reviews.write_text(json.dumps(review()) + "\n", encoding="utf-8")
            self.assertEqual(len(validate_reviews(reviews, worklist, "reviewer")), 1)

    def test_nonliteral_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            worklist = root / "worklist.jsonl"
            reviews = root / "reviews.jsonl"
            invalid = review()
            invalid["supporting_evidence"][0]["quote"] = "This sentence does not occur in the frozen source snippet."
            worklist.write_text(json.dumps(worklist_row()) + "\n", encoding="utf-8")
            reviews.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "literal frozen substring"):
                validate_reviews(reviews, worklist, "reviewer")

    def test_strict_consensus_requires_four_component_agreement(self):
        left, right = review("left"), review("right")
        self.assertEqual(strict_consensus(left, right), (True, "representation_discrepancy"))
        right["taxonomy_compatibility"] = "partial"
        self.assertEqual(strict_consensus(left, right), (False, None))


if __name__ == "__main__":
    unittest.main()
