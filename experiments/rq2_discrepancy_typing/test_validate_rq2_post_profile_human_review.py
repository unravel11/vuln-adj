#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import build_rq2_post_profile_human_review_packet as builder
import validate_rq2_post_profile_human_review as target


EVIDENCE_URL = "https://example.test/advisory/1"


def source_row() -> dict:
    return {
        "sample_id": "rq2_post_profile_snapshot_v1:001",
        "cve_id": "CVE-2026-0001",
        "field": "cwe_ids",
        "baseline_status": "incomplete",
        "baseline_note": "hidden baseline note",
        "sampling_stratum": {"baseline_status": "incomplete"},
        "nvd_source_id": "CVE-2026-0001",
        "ghsa_source_id": "GHSA-1111-2222-3333",
        "nvd_value": ["CWE-79", "CWE-80"],
        "ghsa_value": ["CWE-79"],
        "field_context": {"summary": "Example vulnerability context."},
        "reference_context": {
            "nvd_urls": [EVIDENCE_URL],
            "ghsa_urls": [],
        },
        "package_names": {"nvd": ["example"], "ghsa": ["example"]},
    }


def prediction_row(current: str = "incomplete", candidate: str = "incomplete") -> dict:
    return {
        "sample_id": source_row()["sample_id"],
        "current": current,
        "cwe_taxonomy_v1": candidate,
    }


def consensus_row(strict: bool = True, label: str | None = "incomplete") -> dict:
    return {
        "sample_id": source_row()["sample_id"],
        "strict_consensus": strict,
        "consensus_label": label,
    }


def evidence_row(
    strict: bool = True,
    label: str | None = "incomplete",
    prior_label: str | None = "incomplete",
) -> dict:
    return {
        "original_sample_id": source_row()["sample_id"],
        "strict_consensus": strict,
        "consensus_label": label,
        "prior_strict_consensus": True,
        "prior_consensus_label": prior_label,
    }


def decision(human_id: str, label: str = "incomplete") -> dict:
    return {
        "human_id": human_id,
        "discrepancy_label": label,
        "confidence": "medium",
        "rationale": (
            "The two frozen CWE records were compared using only the supplied values, "
            "taxonomy context, and source references in the bound review snapshot."
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
                "Both independent reviewers applied the frozen definitions and agreed "
                "that one compatible CWE set is a strict information subset of the other."
            ),
            "author_id": "author-c",
            "author_signoff": "signed",
            "signed_at": "2026-07-19T14:00:00+00:00",
        },
        "exclusion_reason": "",
    }
    return row


class ValidateRQ2PostProfileHumanReviewTests(unittest.TestCase):
    def test_builder_is_blind_and_blank(self) -> None:
        row = builder.packet_row(source_row())
        self.assertEqual(row["human_review"], builder.empty_human_review())
        self.assertFalse(row["label_is_human"])
        self.assertFalse(row["eligible_for_human_gold_claim"])
        self.assertFalse(builder.FORBIDDEN_BLIND_KEYS & set(row))
        self.assertNotIn("baseline_status", row["source_snapshot"])

    def test_scheduler_contains_signals_but_no_labels(self) -> None:
        row = builder.schedule_row(
            source_row(), prediction_row(), consensus_row(), evidence_row()
        )
        self.assertEqual(row["queue_tier"], 4)
        self.assertNotIn("consensus_label", row)
        self.assertNotIn("baseline_status", row)

    def test_original_non_strict_rows_are_first_tier(self) -> None:
        row = builder.schedule_row(
            source_row(),
            prediction_row(),
            consensus_row(False, None),
            evidence_row(False, None),
        )
        self.assertEqual(row["queue_tier"], 1)

    def test_profile_difference_rows_are_second_tier(self) -> None:
        row = builder.schedule_row(
            source_row(),
            prediction_row("incomplete", "representation_discrepancy"),
            consensus_row(),
            evidence_row(),
        )
        self.assertEqual(row["queue_tier"], 2)

    def test_evidence_shift_rows_are_second_tier(self) -> None:
        row = builder.schedule_row(
            source_row(),
            prediction_row(),
            consensus_row(),
            evidence_row(True, "factual_conflict", "incomplete"),
        )
        self.assertEqual(row["queue_tier"], 2)

    def test_pending_packet_is_valid(self) -> None:
        self.assertEqual(
            target.validate_row(builder.packet_row(source_row()), source_row()), []
        )

    def test_complete_three_stage_packet_is_valid(self) -> None:
        self.assertEqual(target.validate_row(final_packet(), source_row()), [])

    def test_source_snapshot_is_bound(self) -> None:
        row = final_packet()
        row["source_snapshot"]["nvd_value"] = ["CWE-999"]
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("source_snapshot" in error for error in errors))

    def test_reviewer_must_differ_from_annotator(self) -> None:
        row = final_packet()
        row["human_review"]["independent_reviewer"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must differ" in error for error in errors))

    def test_evidence_url_must_be_frozen(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["evidence_urls"] = [
            "https://outside.test/evidence"
        ]
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("outside the frozen snapshot" in error for error in errors))

    def test_pending_packet_cannot_hide_partial_content(self) -> None:
        row = builder.packet_row(source_row())
        row["human_review"]["annotator"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must not contain" in error for error in errors))

    def test_packet_cannot_mark_itself_human_gold(self) -> None:
        row = copy.deepcopy(final_packet())
        row["label_is_human"] = True
        row["eligible_for_human_gold_claim"] = True
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("label_is_human" in error for error in errors))
        self.assertTrue(any("eligible_for_human_gold_claim" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
