import copy
import unittest

from build_rq2_post_profile_eligible_universe_cwe_difference_evidence import (
    select_cwe_differences,
)
from merge_rq2_post_profile_eligible_universe_cwe_difference_reviews import (
    exact_two_sided_p,
)
from run_rq2_post_profile_cwe_all50_review import validate_model_row
from verify_rq2_post_profile_eligible_universe_cwe_difference_review import (
    exact_p,
    independent_strict,
)


SNIPPET = "The parser allocates memory without a fixed limit and exhausts resources."


def difference_rows() -> list[dict]:
    return [
        {
            "sample_id": f"universe:cwe:{index:02d}",
            "cve_id": f"CVE-2026-{index:04d}",
            "field": "cwe_ids",
            "current": "factual_conflict",
            "cwe_taxonomy_v1": "representation_discrepancy",
            "label_is_human": False,
        }
        for index in range(29)
    ]


def blind_row() -> dict:
    return {
        "review_id": "review:1",
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


def review() -> dict:
    return {
        "review_id": "review:1",
        "cve_id": "CVE-2026-0001",
        "set_relation": "disjoint",
        "discrepancy_label": "representation_discrepancy",
        "taxonomy_compatibility": "full",
        "specific_mapping_verdict": "same_mechanism_or_not_needed",
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The official ancestor path connects the two CWE assignments, while the "
            "frozen advisory describes one concrete unbounded-allocation mechanism; "
            "the difference is therefore taxonomy granularity rather than mechanism."
        ),
        "supporting_cwe_paths": ["CWE-770>CWE-400"],
        "supporting_evidence": [
            {
                "url": "https://example.test/advisory",
                "quote": "allocates memory without a fixed limit and exhausts resources",
            }
        ],
    }


class EligibleUniverseCweDifferenceReviewTests(unittest.TestCase):
    def test_selection_requires_complete_unique_directional_set(self):
        rows = difference_rows() + [{"field": "references"}]
        self.assertEqual(len(select_cwe_differences(rows)), 29)

        with self.assertRaisesRegex(ValueError, "expected 29 CWE differences"):
            select_cwe_differences(rows[1:])

        duplicate = difference_rows()
        duplicate[-1]["cve_id"] = duplicate[0]["cve_id"]
        with self.assertRaisesRegex(ValueError, "not unique"):
            select_cwe_differences(duplicate)

        drift = difference_rows()
        drift[-1]["cwe_taxonomy_v1"] = "factual_conflict"
        with self.assertRaisesRegex(ValueError, "taxonomy prediction drift"):
            select_cwe_differences(drift)

    def test_exact_conditional_p_is_recomputed_two_ways(self):
        for candidate, current, expected in ((0, 0, 1.0), (5, 0, 0.0625), (6, 0, 0.03125)):
            self.assertEqual(exact_two_sided_p(candidate, current), expected)
            self.assertEqual(exact_p(candidate, current), expected)

    def test_strict_consensus_requires_all_four_components(self):
        left = review()
        right = copy.deepcopy(left)
        self.assertEqual(independent_strict(left, right), (True, "representation_discrepancy"))
        right["specific_mapping_verdict"] = "materially_different_or_contradicted"
        self.assertEqual(independent_strict(left, right), (False, None))

    def test_literal_frozen_evidence_contract_is_reused(self):
        validate_model_row(review(), blind_row())
        invalid = review()
        invalid["supporting_evidence"][0]["quote"] = (
            "This altered sentence is not in the frozen evidence snippet."
        )
        with self.assertRaisesRegex(ValueError, "literal frozen substring"):
            validate_model_row(invalid, blind_row())


if __name__ == "__main__":
    unittest.main()
