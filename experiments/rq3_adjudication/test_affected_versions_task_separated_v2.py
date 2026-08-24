#!/usr/bin/env python3

from __future__ import annotations

import unittest
from unittest.mock import patch

import affected_versions_task_separated_v2 as target


def profiles(relation: str, contradictions: int) -> tuple[dict, dict, dict, dict]:
    package = {"comparable": True}
    legacy = {"relation": "not_proven_equivalent"}
    structured = {"relation": relation}
    branch = {
        "source_profiles": {
            "nvd": {"contradiction_events": [{}] * contradictions},
            "ghsa": {"contradiction_events": []},
        }
    }
    return package, legacy, structured, branch


class TaskSeparatedV2Tests(unittest.TestCase):
    def predict(
        self, relation: str, contradictions: int = 0, package_comparable: bool = True
    ) -> dict:
        package, legacy, structured, branch = profiles(relation, contradictions)
        package["comparable"] = package_comparable
        with (
            patch.object(target, "repository_crosswalk_package_profile", return_value=package),
            patch.object(target, "range_relation", return_value=legacy),
            patch.object(target, "structured_range_set_relation", return_value=structured),
            patch.object(target, "extract_branch_graph_features", return_value=branch),
        ):
            return target.predict_discrepancy_type_v2({})

    def test_disjoint_sets_are_factual_conflict(self) -> None:
        self.assertEqual(
            self.predict("disjoint_parseable_sets")["predicted_discrepancy_label"],
            "factual_conflict",
        )

    def test_clean_ghsa_superset_is_representation(self) -> None:
        self.assertEqual(
            self.predict("ghsa_strict_superset")["predicted_discrepancy_label"],
            "representation_discrepancy",
        )

    def test_partial_overlap_with_contradiction_is_incomplete(self) -> None:
        self.assertEqual(
            self.predict("partial_overlap_without_containment", 1)[
                "predicted_discrepancy_label"
            ],
            "incomplete",
        )

    def test_ambiguous_superset_abstains(self) -> None:
        prediction = self.predict("ghsa_strict_superset", 1)
        self.assertEqual(prediction["predicted_discrepancy_label"], "uncertain")
        self.assertEqual(prediction["type_prediction_status"], "abstain")

    def test_noncomparable_package_abstains(self) -> None:
        prediction = self.predict("disjoint_parseable_sets", package_comparable=False)
        self.assertEqual(prediction["predicted_discrepancy_label"], "uncertain")
        self.assertEqual(
            prediction["type_prediction_reason"], "package_identity_not_comparable"
        )


if __name__ == "__main__":
    unittest.main()
