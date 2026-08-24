#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import build_rq2_typing_human_review_packet as builder
import validate_rq2_typing_human_review as target


EVIDENCE_URL = "https://example.test/advisory/1"


def source_row() -> dict:
    return {
        "sample_id": "rq2_typing_holdout_v1:001",
        "cve_id": "CVE-2026-0001",
        "field": "severity",
        "baseline_status": "equivalent",
        "baseline_note": "hidden baseline note",
        "sampling_stratum": {"baseline_status": "equivalent"},
        "nvd_source_id": "CVE-2026-0001",
        "ghsa_source_id": "GHSA-1111-2222-3333",
        "nvd_value": {"label": "HIGH", "score": 7.5},
        "ghsa_value": {"label": "HIGH", "score": None},
        "field_context": {"summary": "Example vulnerability context."},
        "reference_context": {"nvd_urls": [EVIDENCE_URL], "ghsa_urls": []},
        "package_names": {"nvd": ["example"], "ghsa": ["example"]},
    }


def decision(human_id: str, label: str = "incomplete") -> dict:
    return {
        "human_id": human_id,
        "discrepancy_label": label,
        "confidence": "medium",
        "rationale": (
            "The two frozen severity records were compared field by field, including "
            "their canonical labels and the one-sided score value in the supplied snapshot."
        ),
        "construct_notes": "",
        "evidence_urls": [EVIDENCE_URL],
        "reviewed_at": "2026-07-19T12:00:00+00:00",
    }


def final_packet() -> dict:
    row = builder.packet_row(source_row())
    row["human_review"] = {
        "review_status": "final",
        "annotator": decision("human-a"),
        "independent_reviewer": decision("human-b"),
        "resolution": {
            "final_label": "incomplete",
            "resolution_basis": "agreement",
            "resolution_rationale": (
                "Both independent reviewers applied the frozen label definitions and "
                "agreed that the missing score is a compatible strict information subset."
            ),
            "author_id": "author-c",
            "author_signoff": "signed",
            "signed_at": "2026-07-19T14:00:00+00:00",
        },
        "exclusion_reason": "",
    }
    return row


class ValidateRQ2TypingHumanReviewTests(unittest.TestCase):
    def test_builder_is_blind_and_leaves_human_fields_blank(self) -> None:
        row = builder.packet_row(source_row())
        self.assertEqual(row["human_review"], builder.empty_human_review())
        self.assertFalse(row["label_is_human"])
        self.assertFalse(row["eligible_for_human_gold_claim"])
        self.assertFalse(builder.FORBIDDEN_BLIND_KEYS & set(row))
        self.assertNotIn("baseline_status", row["source_snapshot"])

    def test_pending_packet_is_valid_but_not_signed(self) -> None:
        self.assertEqual(target.validate_row(builder.packet_row(source_row()), source_row()), [])

    def test_complete_three_stage_packet_is_valid(self) -> None:
        self.assertEqual(target.validate_row(final_packet(), source_row()), [])

    def test_source_snapshot_is_bound(self) -> None:
        row = final_packet()
        row["source_snapshot"]["nvd_value"]["score"] = 9.8
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("source_snapshot" in error for error in errors))

    def test_pending_packet_cannot_hide_partial_content(self) -> None:
        row = builder.packet_row(source_row())
        row["human_review"]["annotator"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must not contain" in error for error in errors))

    def test_reviewer_must_differ_from_annotator(self) -> None:
        row = final_packet()
        row["human_review"]["independent_reviewer"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must differ" in error for error in errors))

    def test_uncertain_decision_requires_construct_notes(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"] = decision("human-a", "uncertain")
        row["human_review"]["resolution"]["resolution_basis"] = "adjudicated"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("construct_notes" in error for error in errors))

    def test_evidence_urls_must_come_from_frozen_snapshot(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["evidence_urls"] = [
            "https://outside.test/evidence"
        ]
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("outside the frozen snapshot" in error for error in errors))

    def test_agreement_resolution_requires_matching_labels(self) -> None:
        row = final_packet()
        row["human_review"]["independent_reviewer"][
            "discrepancy_label"
        ] = "equivalent"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("requires matching" in error for error in errors))

    def test_timestamps_must_include_timezone(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["reviewed_at"] = "2026-07-19T12:00:00"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("ISO timezone" in error for error in errors))

    def test_packet_cannot_mark_itself_human_gold(self) -> None:
        row = copy.deepcopy(final_packet())
        row["label_is_human"] = True
        row["eligible_for_human_gold_claim"] = True
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("label_is_human" in error for error in errors))
        self.assertTrue(any("eligible_for_human_gold_claim" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
