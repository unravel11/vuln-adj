#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_cwe_taxonomy_impact_holdout as target


class BuildCweTaxonomyImpactHoldoutTests(unittest.TestCase):
    def test_recursive_keys_find_nested_prediction_key(self) -> None:
        keys = target.recursive_keys({"outer": [{"gold_label": "x"}]})
        self.assertIn("gold_label", keys)

    def test_validate_blind_row_rejects_prediction_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "prediction keys"):
            target.validate_blind_row(
                {"review_id": "x", "nested": {"taxonomy_v1_status": "x"}}
            )

    def test_validate_blind_row_accepts_taxonomy_context(self) -> None:
        target.validate_blind_row(
            {
                "review_id": "x",
                "taxonomy_source": {"catalog_version": "4.20"},
                "review_contract": {"discrepancy_label": ["uncertain"]},
            }
        )


if __name__ == "__main__":
    unittest.main()
