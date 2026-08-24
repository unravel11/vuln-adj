#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import build_reference_normalization_human_review_packet as builder
import validate_reference_normalization_human_review as target


def source_row(encoded_line: bool = False) -> dict:
    first_url = "https://example.test/project/blob/rev/file.py"
    if encoded_line:
        first_url += "%23L10-L20"
    return {
        "review_id": "rq2_reference_identity:001",
        "cve_id": "CVE-2026-0001",
        "field": "references",
        "identity_groups": [
            {
                "group_id": "rq2_reference_identity:001:group:01",
                "members": [
                    {"side": "nvd", "url": first_url},
                    {
                        "side": "ghsa",
                        "url": "https://example.test/project/blob/rev/file.py",
                    },
                ],
                "probe_records": [
                    {
                        "url": first_url,
                        "status": "ok",
                        "http_status": 200,
                    }
                ],
            }
        ],
        "review_contract": {
            "identity_verdict": sorted(target.IDENTITY_VERDICTS),
            "final_status": sorted(target.FINAL_STATUSES),
            "confidence": sorted(target.CONFIDENCE),
        },
    }


def packet_row(encoded_line: bool = False) -> dict:
    return builder.packet_row(source_row(encoded_line=encoded_line))


def human_decision(human_id: str, same_resource: bool | None = True) -> dict:
    if same_resource is True:
        verdict = "all_aliases_same_resource"
    elif same_resource is False:
        verdict = "one_or_more_not_same"
    else:
        verdict = "insufficient"
    return {
        "human_id": human_id,
        "identity_definition": "underlying_content_resource",
        "custom_identity_definition": "",
        "identity_verdict": verdict,
        "final_status": target.STATUS_MAPPING[verdict],
        "confidence": "medium",
        "rationale": (
            "The supplied URLs, immutable identifiers, and frozen probe records were "
            "examined under the explicitly selected resource-identity definition."
        ),
        "group_decisions": [
            {
                "group_id": "rq2_reference_identity:001:group:01",
                "same_resource": same_resource,
                "reason": "The URL members satisfy the selected resource definition.",
            }
        ],
        "reviewed_at": "2026-07-15T12:00:00+00:00",
    }


def final_packet() -> dict:
    row = packet_row()
    row["human_review"] = {
        "review_status": "final",
        "annotator": human_decision("human-a"),
        "independent_reviewer": human_decision("human-b"),
        "resolution": {
            "final_identity_definition": "underlying_content_resource",
            "custom_identity_definition": "",
            "final_identity_verdict": "all_aliases_same_resource",
            "final_status": "incomplete",
            "group_decisions": [
                {
                    "group_id": "rq2_reference_identity:001:group:01",
                    "same_resource": True,
                    "reason": "The final decision applies the recorded underlying-content definition.",
                }
            ],
            "resolution_rationale": (
                "Both independent reviews used the stated definition and reached the same group decision."
            ),
            "author_id": "author-c",
            "author_signoff": "signed",
            "signed_at": "2026-07-15T14:00:00+00:00",
        },
        "exclusion_reason": "",
    }
    return row


class ValidateReferenceNormalizationHumanReviewTests(unittest.TestCase):
    def test_builder_leaves_all_human_fields_blank(self) -> None:
        row = packet_row(encoded_line=True)
        self.assertEqual(row["human_review"], target.empty_human_review())
        self.assertFalse(row["label_is_human"])
        self.assertFalse(row["eligible_for_human_gold_claim"])
        self.assertEqual(row["priority_tier"], "definition_sensitive")

    def test_pending_packet_is_valid_but_not_signed(self) -> None:
        self.assertEqual(target.validate_row(packet_row(), source_row()), [])

    def test_complete_three_stage_packet_is_valid(self) -> None:
        self.assertEqual(target.validate_row(final_packet(), source_row()), [])

    def test_source_urls_and_probe_records_are_bound(self) -> None:
        row = final_packet()
        row["identity_groups"][0]["members"][0]["url"] = "https://altered.test"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("identity_groups" in error for error in errors))

    def test_pending_packet_must_not_hide_partial_review_content(self) -> None:
        row = packet_row()
        row["human_review"]["annotator"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must not contain" in error for error in errors))

    def test_reviewer_must_differ_from_annotator(self) -> None:
        row = final_packet()
        row["human_review"]["independent_reviewer"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must differ" in error for error in errors))

    def test_verdict_status_mapping_is_enforced(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["final_status"] = "uncertain"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("mapping is inconsistent" in error for error in errors))

    def test_group_ids_and_order_are_enforced(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["group_decisions"][0][
            "group_id"
        ] = "unknown"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("group IDs and order" in error for error in errors))

    def test_all_aliases_verdict_requires_true_groups(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["group_decisions"][0][
            "same_resource"
        ] = False
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("requires all groups true" in error for error in errors))

    def test_numeric_group_decision_is_not_accepted_as_boolean(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"]["group_decisions"][0][
            "same_resource"
        ] = 1
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("same_resource value" in error for error in errors))

    def test_custom_definition_must_be_explicit(self) -> None:
        row = final_packet()
        row["human_review"]["annotator"][
            "identity_definition"
        ] = "other_explicit_definition"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("custom_identity_definition" in error for error in errors))

    def test_packet_cannot_mark_itself_human_gold(self) -> None:
        row = copy.deepcopy(final_packet())
        row["label_is_human"] = True
        row["eligible_for_human_gold_claim"] = True
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("label_is_human" in error for error in errors))
        self.assertTrue(any("eligible_for_human_gold_claim" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
