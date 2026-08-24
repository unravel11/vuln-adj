import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import build_rq2_post_profile_unresolved_evidence_secondary as builder
import merge_rq2_post_profile_unresolved_evidence_secondary as merger
import verify_rq2_post_profile_unresolved_evidence_secondary as verifier


def annotation(label="incomplete", evidence_urls=None):
    return {
        "discrepancy_label": label,
        "confidence": "high",
        "needs_human_review": False,
        "evidence_urls": evidence_urls or [],
    }


class PostProfileUnresolvedEvidenceSecondaryTests(unittest.TestCase):
    def test_selection_excludes_three_strict_cwe_rows(self):
        main = []
        index = 0
        for field, count in builder.EXPECTED_FIELD_COUNTS.items():
            for _ in range(count):
                index += 1
                main.append(
                    {
                        "sample_id": f"sample:{index:03d}",
                        "field": field,
                        "strict_consensus": False,
                    }
                )
        for _ in range(builder.EXPECTED_EXCLUDED_CWE_ROWS):
            index += 1
            main.append(
                {
                    "sample_id": f"sample:{index:03d}",
                    "field": "cwe_ids",
                    "strict_consensus": False,
                }
            )
        cwe = [
            {"original_sample_id": row["sample_id"], "strict_consensus": True}
            for row in main
            if row["field"] == "cwe_ids"
        ]
        selected, excluded = builder.selection(main, cwe)
        self.assertEqual(len(selected), 16)
        self.assertEqual(len(excluded), 3)
        self.assertNotIn("cwe_ids", {row["field"] for row in selected})

    def test_selection_fails_closed_without_strict_cwe_result(self):
        main = []
        index = 0
        for field, count in builder.EXPECTED_FIELD_COUNTS.items():
            for _ in range(count):
                index += 1
                main.append(
                    {"sample_id": f"s:{index}", "field": field, "strict_consensus": False}
                )
        cwe = []
        for _ in range(3):
            index += 1
            row = {"sample_id": f"s:{index}", "field": "cwe_ids", "strict_consensus": False}
            main.append(row)
            cwe.append(
                {"original_sample_id": row["sample_id"], "strict_consensus": len(cwe) != 2}
            )
        with self.assertRaisesRegex(ValueError, "lacks strict all-50 result"):
            builder.selection(main, cwe)

    def test_citation_gate_requires_frozen_successful_url(self):
        blind = {
            "evidence_context": {
                "records": [
                    {"url": "https://example.test/ok", "fetch_status": "ok", "text_snippet": "evidence"},
                    {"url": "https://example.test/empty", "fetch_status": "ok", "text_snippet": ""},
                ]
            }
        }
        left = annotation(evidence_urls=["https://example.test/ok"])
        right = annotation(evidence_urls=["https://example.test/ok"])
        self.assertTrue(merger.strict_secondary(left, right, blind, True))
        right["evidence_urls"] = ["https://example.test/empty"]
        self.assertFalse(merger.strict_secondary(left, right, blind, True))
        self.assertTrue(merger.strict_secondary(left, right, blind, False))

    def test_fixed_gate_matches_independent_verifier(self):
        passed = merger.build_gate(0.75, 7, 241)
        self.assertTrue(passed["passed"])
        self.assertEqual(passed, verifier.expected_gate(0.75, 7, 241))
        failed = merger.build_gate(0.75, 6, 240)
        self.assertFalse(failed["passed"])
        self.assertIn("minimum_secondary_strict_resolution", failed["failed_checks"])

    def test_review_sessions_does_not_assume_sample_id(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "reviews.jsonl"
            path.write_text(
                '{"review_id":"r:1","execution_session_id":"session-1"}\n'
                '{"review_id":"r:2","execution_session_id":"session-2"}\n',
                encoding="utf-8",
            )
            self.assertEqual(merger.review_sessions(path), {"session-1", "session-2"})
            self.assertEqual(verifier.review_sessions(path), {"session-1", "session-2"})

    def test_request_sessions_reads_specialized_runner_logs(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "requests.jsonl"
            path.write_text(
                '{"request_index":1,"session_id":"session-a"}\n'
                '{"request_index":2,"session_id":"session-b"}\n',
                encoding="utf-8",
            )
            self.assertEqual(merger.request_sessions(path), {"session-a", "session-b"})
            self.assertEqual(verifier.request_sessions(path), {"session-a", "session-b"})


if __name__ == "__main__":
    unittest.main()
