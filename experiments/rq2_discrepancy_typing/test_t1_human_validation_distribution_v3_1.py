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
        cls.template_path = builder.resolve(builder.DEFAULT_APPROVAL_RECORD)
        cls.template = json.loads(cls.template_path.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        # The tracked frozen packets are sufficient for these unit tests. The
        # full source field view is intentionally absent from many local clones
        # and is revalidated by the production command on the authoritative host.
        self.packet_seal_patch = mock.patch.object(
            validator.packet_validator, "validate_packet_dir", return_value=[]
        )
        self.packet_seal_patch.start()

    def tearDown(self) -> None:
        self.packet_seal_patch.stop()

    def complete_approval(self) -> dict:
        approval = copy.deepcopy(self.template)
        approval["guideline_approval"].update(
            {
                "approval_basis": (
                    "Author reviewed and approved the exact frozen guideline."
                ),
                "approved_by": "Author-01",
                "signature_recorded": True,
            }
        )
        for reviewer, private_hash in (
            ("reviewer_a", "a" * 64),
            ("reviewer_b", "b" * 64),
        ):
            approval["reviewer_governance"][reviewer].update(
                {
                    "real_person_identity_verified": True,
                    "doctoral_status_verified": True,
                    "relevant_experience_summary": (
                        "Doctoral researcher trained on advisory, CVSS, and "
                        "version-range examples."
                    ),
                    "independence_signed": True,
                    "conflict_disclosed": True,
                    "compensation_disclosed": True,
                    "consent_signed": True,
                    "private_record_sha256": private_hash,
                }
            )
        approval["ethics_recruitment"].update(
            {
                "determination_recorded": True,
                "determination": "not_required_with_recorded_rationale",
                "identifier_or_written_rationale": (
                    "Recorded minimal-risk determination."
                ),
                "recruitment_method": (
                    "Direct invitation using the frozen role criteria."
                ),
                "information_sheet_sha256": "c" * 64,
            }
        )
        approval["author_distribution_approval"].update(
            {
                "approved": True,
                "approved_by": "Author-01",
                "approved_at": "2026-08-25",
                "two_distinct_reviewers_verified": True,
                "scope_and_hashes_verified": True,
                "policy_output_blinding_commitment_signed": True,
            }
        )
        approval["distribution_allowed"] = True
        return approval

    def write_approval(self, root: Path, approval: dict) -> Path:
        path = root / "approval.json"
        path.write_text(
            json.dumps(approval, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def build_valid_fixture(self, root: Path) -> tuple[Path, Path, dict]:
        approval = self.complete_approval()
        approval_path = self.write_approval(root, approval)
        output = root / "bundles"
        self.assertEqual(
            builder.validate_approval_record(approval, self.packet_dir), []
        )
        builder.build_bundles(
            approval, self.packet_dir, output, approval_path
        )
        return output, approval_path, approval

    def test_current_template_remains_distribution_blocked(self) -> None:
        errors = builder.validate_approval_record(self.template, self.packet_dir)
        self.assertGreater(len(errors), 10)
        self.assertTrue(
            any("named-author signature" in error for error in errors)
        )
        self.assertTrue(
            any("real_person_identity_verified" in error for error in errors)
        )
        self.assertTrue(
            any("determination is not recorded" in error for error in errors)
        )
        self.assertTrue(
            any("distribution_allowed" in error for error in errors)
        )

    def test_complete_record_builds_and_validates_action_only_bundles(self) -> None:
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

    def test_practitioner_claim_is_rejected(self) -> None:
        approval = self.complete_approval()
        approval["reviewer_governance"]["reviewer_a"][
            "practitioner_expertise_claimed"
        ] = True
        errors = builder.validate_approval_record(approval, self.packet_dir)
        self.assertTrue(
            any(
                "practitioner expertise may not be claimed" in error
                for error in errors
            )
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
