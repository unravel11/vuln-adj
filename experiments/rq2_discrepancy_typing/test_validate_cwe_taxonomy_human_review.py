#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import validate_cwe_taxonomy_human_review as target


def source_row() -> dict:
    return {
        "review_id": "rq2_cwe_taxonomy_impact:001",
        "cve_id": "CVE-2026-0001",
        "field": "cwe_ids",
        "nvd_value": ["CWE-1"],
        "ghsa_value": ["CWE-2"],
        "vulnerability_context": {"summary": "test context"},
        "official_cwe_entries": [
            {"cwe_id": "CWE-1", "name": "Parent"},
            {"cwe_id": "CWE-2", "name": "Child"},
        ],
        "official_cross_source_ancestor_descendant_paths": [
            {"path": [{"cwe_id": "CWE-1"}, {"cwe_id": "CWE-2"}]}
        ],
        "taxonomy_source": {"name": "MITRE CWE"},
    }


def packet_row() -> dict:
    return {
        "schema_version": target.SCHEMA_VERSION,
        "label_is_human": False,
        **source_row(),
        "human_review": {
            "review_status": "pending",
            "annotator": {
                "human_id": "",
                "label": "",
                "rationale": "",
                "supporting_cwe_paths": [],
                "reviewed_at": "",
            },
            "independent_reviewer": {
                "human_id": "",
                "label": "",
                "rationale": "",
                "supporting_cwe_paths": [],
                "reviewed_at": "",
            },
            "resolution": {
                "final_label": "",
                "resolution_rationale": "",
                "author_id": "",
                "author_signoff": "pending",
                "signed_at": "",
            },
            "exclusion_reason": "",
        },
    }


def final_packet() -> dict:
    row = packet_row()
    rationale = (
        "The official ancestor path and supplied CVE context describe the same "
        "underlying weakness at two different CWE abstraction levels."
    )
    row["human_review"] = {
        "review_status": "final",
        "annotator": {
            "human_id": "human-a",
            "label": "representation_discrepancy",
            "rationale": rationale,
            "supporting_cwe_paths": ["CWE-1>CWE-2"],
            "reviewed_at": "2026-07-15T12:00:00+00:00",
        },
        "independent_reviewer": {
            "human_id": "human-b",
            "label": "representation_discrepancy",
            "rationale": rationale,
            "supporting_cwe_paths": ["CWE-1>CWE-2"],
            "reviewed_at": "2026-07-15T13:00:00+00:00",
        },
        "resolution": {
            "final_label": "representation_discrepancy",
            "resolution_rationale": "Both independent human decisions agree and cite the supplied official path.",
            "author_id": "author-c",
            "author_signoff": "signed",
            "signed_at": "2026-07-15T14:00:00+00:00",
        },
        "exclusion_reason": "",
    }
    return row


class ValidateCweTaxonomyHumanReviewTests(unittest.TestCase):
    def test_pending_packet_is_valid_but_not_signed(self) -> None:
        self.assertEqual(target.validate_row(packet_row(), source_row()), [])

    def test_complete_three_stage_packet_is_valid(self) -> None:
        self.assertEqual(target.validate_row(final_packet(), source_row()), [])

    def test_official_context_is_bound_to_sealed_source(self) -> None:
        row = final_packet()
        row["official_cwe_entries"][0]["name"] = "Altered"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("official_cwe_entries" in error for error in errors))

    def test_pending_packet_must_not_hide_review_content(self) -> None:
        row = packet_row()
        row["human_review"]["annotator"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must not contain" in error for error in errors))

    def test_reviewer_must_differ_from_annotator(self) -> None:
        row = final_packet()
        row["human_review"]["independent_reviewer"]["human_id"] = "human-a"
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("must differ" in error for error in errors))

    def test_representation_label_requires_official_path(self) -> None:
        row = copy.deepcopy(final_packet())
        row["human_review"]["annotator"]["supporting_cwe_paths"] = []
        errors = target.validate_row(row, source_row())
        self.assertTrue(any("requires a CWE path" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
