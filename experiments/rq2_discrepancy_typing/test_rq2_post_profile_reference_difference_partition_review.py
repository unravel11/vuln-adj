import copy
import unittest

from build_rq2_post_profile_reference_difference_partition import (
    select_reference_differences,
)
from merge_rq2_post_profile_reference_difference_partition_reviews import (
    exact_two_sided_p,
    profile_pair_metrics,
    status_from_partition,
    strict_partition,
)
from run_rq2_post_profile_reference_difference_partition_review import (
    canonical_partition,
    validate_model_row,
)


def differences() -> list[dict]:
    rows = []
    for index in range(5):
        rows.append(
            {
                "sample_id": f"reference:{index}",
                "cve_id": f"CVE-2026-{index:04d}",
                "field": "references",
                "label_is_human": False,
                "current": "representation_discrepancy",
                "reference_resource_identity_original_v1": "incomplete",
                "reference_resource_identity_audited_v1": (
                    "incomplete" if index < 3 else "representation_discrepancy"
                ),
            }
        )
    return rows


def worklist_row() -> dict:
    return {
        "review_id": "review:1",
        "members": [
            {"member_id": "m1", "url": "https://example.test/a", "frozen_probe": {}},
            {"member_id": "m2", "url": "https://example.test/b", "frozen_probe": {}},
            {"member_id": "m3", "url": "https://other.test/c", "frozen_probe": {}},
        ],
    }


def definition(partition=None) -> dict:
    partition = partition or [["m1", "m2"], ["m3"]]
    return {
        "verdict": "determinate",
        "partition": partition,
        "confidence": "high",
        "needs_additional_review": False,
        "rationale": (
            "The first two URLs carry the same stable resource identity under the frozen "
            "definition, while the third URL identifies a separate document and remains "
            "a singleton in the complete member partition."
        ),
        "merge_justifications": [
            {
                "member_ids": ["m1", "m2"],
                "basis": "stable_identifier",
                "reason": (
                    "Both members expose the same stable advisory identifier and therefore "
                    "refer to one persistent underlying resource."
                ),
            }
        ],
    }


def model_row() -> dict:
    underlying = definition()
    http = copy.deepcopy(underlying)
    http["merge_justifications"][0]["basis"] = "same_final_url"
    return {
        "review_id": "review:1",
        "underlying_reference_resource_v1": underlying,
        "frozen_http_resource_v1": http,
    }


class ReferenceDifferencePartitionReviewTests(unittest.TestCase):
    def test_selection_requires_five_three_two_partition(self):
        self.assertEqual(len(select_reference_differences(differences())), 5)
        with self.assertRaisesRegex(ValueError, "expected 5 reference differences"):
            select_reference_differences(differences()[:-1])
        drift = differences()
        drift[-1]["reference_resource_identity_audited_v1"] = "incomplete"
        with self.assertRaisesRegex(ValueError, "partition counts drift"):
            select_reference_differences(drift)

    def test_partition_validation_is_order_invariant_and_complete(self):
        validate_model_row(model_row(), worklist_row())
        self.assertEqual(
            canonical_partition([["m3"], ["m2", "m1"]]),
            canonical_partition([["m1", "m2"], ["m3"]]),
        )
        invalid = model_row()
        invalid["underlying_reference_resource_v1"]["partition"] = [["m1", "m2"]]
        with self.assertRaisesRegex(ValueError, "partition coverage drift"):
            validate_model_row(invalid, worklist_row())

    def test_strict_partition_and_status_restore_source_side_after_review(self):
        left = definition()
        right = definition([["m3"], ["m2", "m1"]])
        strict, partition = strict_partition(left, right)
        self.assertTrue(strict)
        mapping = {
            "members": [
                {"member_id": "m1", "url": "https://example.test/a", "sides": ["nvd"]},
                {"member_id": "m2", "url": "https://example.test/b", "sides": ["ghsa"]},
                {"member_id": "m3", "url": "https://other.test/c", "sides": ["ghsa"]},
            ]
        }
        self.assertEqual(status_from_partition(partition, mapping), "incomplete")

    def test_profile_metrics_keep_common_denominator_and_exact_test(self):
        rows = []
        for index in range(5):
            rows.append(
                {
                    "predictions": {
                        "current": "representation_discrepancy",
                        "original": "incomplete",
                    },
                    "definitions": {
                        "underlying_reference_resource_v1": {
                            "strict_consensus": True,
                            "consensus_status": "incomplete",
                        }
                    },
                }
            )
        metrics = profile_pair_metrics(
            rows, "underlying_reference_resource_v1", "current", "original"
        )
        self.assertEqual(metrics["common_union_rows"], 5)
        self.assertEqual(metrics["right_direction_rows"], 5)
        self.assertEqual(metrics["conditional_exact_two_sided_mcnemar_p"], 0.0625)
        self.assertEqual(exact_two_sided_p(3, 0), 0.25)


if __name__ == "__main__":
    unittest.main()
