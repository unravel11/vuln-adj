from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_t1_human_validation_distribution_v3_1 as builder
import validate_t1_human_validation_distribution_v3_1 as validator


class T1HumanValidationDistributionV31Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packet_dir = builder.resolve(builder.DEFAULT_PACKET_DIR)
        cls.approval_path = builder.resolve(builder.DEFAULT_APPROVAL_RECORD)
        cls.approval = json.loads(
            cls.approval_path.read_text(encoding="utf-8")
        )

    def setUp(self) -> None:
        # Production revalidates the full source view on the authoritative host.
        # Unit tests use the already tracked, sealed reviewer packets.
        self.packet_seal_patch = mock.patch.object(
            validator.packet_validator, "validate_packet_dir", return_value=[]
        )
        self.packet_seal_patch.start()

    def tearDown(self) -> None:
        self.packet_seal_patch.stop()

    def write_approval(self, root: Path, approval: dict) -> Path:
        path = root / "approval.json"
        path.write_text(
            json.dumps(approval, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def build_valid_fixture(self, root: Path) -> tuple[Path, Path, dict]:
        approval = copy.deepcopy(self.approval)
        approval_path = self.write_approval(root, approval)
        output = root / "bundles"
        self.assertEqual(
            builder.validate_approval_record(approval, self.packet_dir), []
        )
        builder.build_bundles(
            approval, self.packet_dir, output, approval_path
        )
        return output, approval_path, approval

    def test_minimal_author_attestation_is_ready(self) -> None:
        self.assertEqual(
            builder.validate_approval_record(self.approval, self.packet_dir), []
        )
        self.assertEqual(
            self.approval["author_attestation"]["evidence_level"],
            builder.ATTESTATION_LEVEL,
        )
        self.assertEqual(self.approval["human_labels"], 0)

    def test_builds_and_validates_action_only_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, approval_path, _ = self.build_valid_fixture(root)
            errors = validator.validate_bundle_root(
                self.packet_dir, approval_path, output
            )
            self.assertEqual(errors, [])
            for reviewer in builder.REVIEWERS:
                self.assertEqual(
                    {path.name for path in (output / reviewer).iterdir()},
                    validator.EXPECTED_FILES,
                )

    def test_unknown_bundle_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, approval_path, _ = self.build_valid_fixture(root)
            (output / "reviewer_a" / "baseline_hint_v2.json").write_text(
                "{}\n", encoding="utf-8"
            )
            errors = validator.validate_bundle_root(
                self.packet_dir, approval_path, output
            )
            self.assertTrue(any("file set" in error for error in errors))

    def test_reason_packet_in_bundle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, approval_path, _ = self.build_valid_fixture(root)
            source = (
                self.packet_dir
                / "reviewer_a"
                / "calibration_1_reason_packet.csv"
            )
            (output / "reviewer_a" / source.name).write_bytes(source.read_bytes())
            errors = validator.validate_bundle_root(
                self.packet_dir, approval_path, output
            )
            self.assertTrue(any("file set" in error for error in errors))

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, approval_path, _ = self.build_valid_fixture(root)
            packet = output / "reviewer_b" / "calibration_1_action_packet.csv"
            packet.write_text(
                packet.read_text(encoding="utf-8").replace(
                    ",,,,\n", ",conflict_escalation,test rationale,,\n", 1
                ),
                encoding="utf-8",
            )
            errors = validator.validate_bundle_root(
                self.packet_dir, approval_path, output
            )
            self.assertTrue(
                any("differs from frozen blank packet" in error for error in errors)
            )

    def test_false_author_attestation_is_rejected(self) -> None:
        approval = copy.deepcopy(self.approval)
        approval["author_attestation"]["independent_no_discussion_no_ai"] = False
        errors = builder.validate_approval_record(approval, self.packet_dir)
        self.assertTrue(
            any("independent_no_discussion_no_ai" in error for error in errors)
        )

    def test_builder_refuses_to_overwrite_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, approval_path, approval = self.build_valid_fixture(root)
            with self.assertRaises(FileExistsError):
                builder.build_bundles(
                    approval, self.packet_dir, output, approval_path
                )


if __name__ == "__main__":
    unittest.main()
