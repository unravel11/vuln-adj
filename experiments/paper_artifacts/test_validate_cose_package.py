#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import validate_cose_package as target


def readiness(artifact_type: str, rows: int, *, tampered: bool = False) -> dict:
    artifact = {
        "artifact_type": artifact_type,
        "packet_label_is_human": tampered,
        "eligible_for_human_gold_claim": False,
        "rows": rows,
        "signed_final_rows": 0,
        "excluded_rows": 0,
        "pending_rows": rows,
        "validation_error_count": 0,
        "external_identity_verification_required": True,
    }
    if artifact_type == "rq2_typing_human_review_readiness":
        artifact["workflow_complete"] = False
    else:
        artifact.update(
            {
                "file_workflow_complete": False,
                "human_gold_promotion_performed": False,
                "validator_can_prove_real_person_identity": False,
            }
        )
    return artifact


class ValidateRQ2TypingHumanReviewTests(unittest.TestCase):
    def write_inputs(self, root: Path, *, tampered: bool = False) -> None:
        for name, spec in target.RQ2_TYPING_HUMAN_REVIEW_SPECS.items():
            path = root / spec["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    readiness(
                        spec["artifact_type"],
                        spec["expected_rows"],
                        tampered=tampered and name == "typing_v1",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

    def test_pending_packets_are_valid_readiness_but_submission_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_inputs(root)
            ctx = target.ValidationContext()
            manifest = {}
            with mock.patch.object(target, "PROJECT_ROOT", root):
                target.validate_rq2_typing_human_review(ctx, manifest)
            self.assertEqual([check["status"] for check in ctx.checks], ["pass", "pass"])
            self.assertEqual(len(ctx.blockers), 1)
            self.assertIn("0/1250", ctx.blockers[0])
            self.assertIn("0/250", ctx.blockers[0])
            self.assertFalse(
                manifest["rq2_typing_human_review"]["typing_v1"][
                    "file_workflow_complete"
                ]
            )

    def test_packet_cannot_claim_human_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_inputs(root, tampered=True)
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", root):
                target.validate_rq2_typing_human_review(ctx, {})
            checks = {check["name"]: check for check in ctx.checks}
            self.assertEqual(
                checks["rq2_typing_v1_typing_human_review_readiness_shape"][
                    "status"
                ],
                "fail",
            )

    def test_missing_readiness_artifact_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", root):
                target.validate_rq2_typing_human_review(ctx, {})
            self.assertEqual([check["status"] for check in ctx.checks], ["fail", "fail"])
            self.assertEqual(len(ctx.blockers), 1)


class ValidatePostProfileUnresolvedEvidenceTests(unittest.TestCase):
    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.validate_rq2_post_profile_unresolved_evidence(ctx, {})
            self.assertEqual(len(ctx.checks), 1)
            self.assertEqual(ctx.checks[0]["status"], "fail")


class ValidatePostProfilePairedTestIdentifiabilityTests(unittest.TestCase):
    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.validate_rq2_post_profile_paired_test_identifiability(ctx, {})
            self.assertEqual(len(ctx.checks), 1)
            self.assertEqual(ctx.checks[0]["status"], "fail")


class ValidatePostProfileEligibleUniverseCensusTests(unittest.TestCase):
    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.validate_rq2_post_profile_eligible_universe_census(ctx, {})
            self.assertEqual(len(ctx.checks), 1)
            self.assertEqual(ctx.checks[0]["status"], "fail")


class ValidatePostProfileAcquisitionDeltaTests(unittest.TestCase):
    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.validate_rq2_post_profile_acquisition_delta(ctx, {})
            self.assertEqual(len(ctx.checks), 1)
            self.assertEqual(ctx.checks[0]["status"], "fail")


class ValidatePostProfileCompleteDifferenceReviewsTests(unittest.TestCase):
    def test_missing_results_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.validate_rq2_post_profile_complete_difference_reviews(ctx, {})
            self.assertEqual(len(ctx.checks), 2)
            self.assertEqual([check["status"] for check in ctx.checks], ["fail", "fail"])


class BuildPDFContactSheetTests(unittest.TestCase):
    def test_missing_pdf_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            ctx = target.ValidationContext()
            with mock.patch.object(target, "PROJECT_ROOT", Path(temp)):
                target.build_pdf_contact_sheet(ctx)
            self.assertEqual(ctx.checks, [
                {
                    "name": "pdf_contact_sheet_build",
                    "status": "fail",
                    "details": f"missing source PDF: {Path(temp) / 'paper/cose/latex/main.pdf'}",
                }
            ])

    def test_generator_is_invoked_for_existing_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pdf_path = root / "paper/cose/latex/main.pdf"
            pdf_path.parent.mkdir(parents=True)
            pdf_path.write_bytes(b"pdf")
            completed = mock.Mock(returncode=0, stdout="Rendered 1 pages")
            ctx = target.ValidationContext()
            with (
                mock.patch.object(target, "PROJECT_ROOT", root),
                mock.patch.object(target, "run_command", return_value=completed) as run,
            ):
                target.build_pdf_contact_sheet(ctx)
            self.assertEqual(ctx.checks[0]["status"], "pass")
            run.assert_called_once_with(
                [
                    target.PYTHON_EXECUTABLE,
                    "experiments/paper_artifacts/build_pdf_contact_sheet.py",
                ]
            )


class PDFContactSheetConsistencyTests(unittest.TestCase):
    def metadata(self) -> dict:
        return {
            "source_pdf": {
                "path": "paper/cose/latex/main.pdf",
                "sha256": "pdf-sha",
                "size_bytes": 100,
                "page_count": 3,
            },
            "rendered_pages": [1, 2, 3],
            "rendered_page_count": 3,
            "contact_sheet": {
                "path": target.PDF_CONTACT_SHEET_PATH,
                "sha256": "png-sha",
                "size_bytes": 200,
                "dimensions": [900, 700],
            },
        }

    def consistency(self, metadata: dict) -> dict[str, bool]:
        return target.pdf_contact_sheet_consistency(
            metadata,
            pdf_sha256="pdf-sha",
            pdf_size_bytes=100,
            pdf_page_count=3,
            contact_sheet_sha256="png-sha",
            contact_sheet_size_bytes=200,
            contact_sheet_dimensions=(900, 700),
        )

    def test_exact_page_sequence_passes(self) -> None:
        self.assertEqual(
            self.consistency(self.metadata()),
            {
                "source_identity": True,
                "complete_page_coverage": True,
                "output_identity": True,
            },
        )

    def test_missing_final_page_fails_coverage(self) -> None:
        metadata = self.metadata()
        metadata["rendered_pages"] = [1, 2]
        metadata["rendered_page_count"] = 2
        consistency = self.consistency(metadata)
        self.assertTrue(consistency["source_identity"])
        self.assertFalse(consistency["complete_page_coverage"])
        self.assertTrue(consistency["output_identity"])


if __name__ == "__main__":
    unittest.main()
