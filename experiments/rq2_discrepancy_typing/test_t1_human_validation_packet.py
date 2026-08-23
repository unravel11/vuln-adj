#!/usr/bin/env python3
"""Tests for the JSS T1 prepare-only packet builder and validator."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


TEST_DIR = Path(__file__).resolve().parent
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

import build_t1_human_validation_packet as builder
import validate_t1_human_validation_packet as validator


class T1HumanValidationPacketTest(unittest.TestCase):
    def build_in_temp(self, root: Path) -> Path:
        output_dir = root / "packet"
        builder.build_packet(
            field_view_path=builder.resolve_path(builder.DEFAULT_FIELD_VIEW),
            guideline_path=builder.resolve_path(builder.DEFAULT_GUIDELINE),
            protocol_path=builder.resolve_path(builder.DEFAULT_PROTOCOL),
            output_dir=output_dir,
        )
        return output_dir

    def test_allocation_retains_evaluation_row_in_rare_stratum(self) -> None:
        counts = {
            "equivalent": 0,
            "representation_discrepancy": 29,
            "incomplete": 28,
            "temporal_discrepancy": 0,
            "factual_conflict": 3,
        }
        allocation = builder.allocate_calibration_targets(counts, 10)
        self.assertEqual(sum(allocation.values()), 10)
        self.assertLessEqual(allocation["factual_conflict"], 2)
        for status, count in counts.items():
            if count:
                self.assertGreater(count - allocation.get(status, 0), 0)

    def test_build_and_validate_prepare_only_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = self.build_in_temp(Path(temp_dir))
            errors = validator.validate_packet_dir(output_dir)
            self.assertEqual(errors, [])

            manifest = json.loads(
                (output_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["distribution_allowed"])
            self.assertEqual(manifest["counts"]["calibration"], 50)
            self.assertEqual(manifest["counts"]["evaluation"], 250)

            packet_text = (
                output_dir / "reviewer_a" / "evaluation_packet.jsonl"
            ).read_text(encoding="utf-8")
            self.assertNotIn('"baseline_status"', packet_text)
            self.assertNotIn('"nvd_source_id"', packet_text)
            self.assertNotIn('"ghsa_source_id"', packet_text)
            packet_rows = [
                json.loads(line) for line in packet_text.splitlines() if line.strip()
            ]
            for row in packet_rows:
                self.assertEqual(validator.find_banned_keys(row), [])

    def test_distribution_ready_gate_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = self.build_in_temp(Path(temp_dir))
            errors = validator.validate_packet_dir(
                output_dir, require_distribution_ready=True
            )
            self.assertIn("Distribution is blocked by the current manifest", errors)

    def test_builder_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = self.build_in_temp(Path(temp_dir))
            with self.assertRaises(FileExistsError):
                builder.build_packet(
                    field_view_path=builder.resolve_path(builder.DEFAULT_FIELD_VIEW),
                    guideline_path=builder.resolve_path(builder.DEFAULT_GUIDELINE),
                    protocol_path=builder.resolve_path(builder.DEFAULT_PROTOCOL),
                    output_dir=output_dir,
                )


if __name__ == "__main__":
    unittest.main()
