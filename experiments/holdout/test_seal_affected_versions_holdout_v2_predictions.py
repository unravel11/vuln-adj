#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import seal_affected_versions_holdout_v2_predictions as target


class V2PredictionSealTests(unittest.TestCase):
    def test_existing_reviewer_decision_blocks_seal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decision = Path(directory) / "agent.jsonl"
            decision.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "review decisions already exist"):
                target.assert_unsealed([decision], [])

    def test_existing_output_blocks_reseal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "predictions.jsonl"
            output.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "refusing overwrite"):
                target.assert_unsealed([], [output])

    def test_no_existing_paths_allows_first_seal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target.assert_unsealed(
                [Path(directory) / "agent.jsonl"],
                [Path(directory) / "predictions.jsonl"],
            )


if __name__ == "__main__":
    unittest.main()
