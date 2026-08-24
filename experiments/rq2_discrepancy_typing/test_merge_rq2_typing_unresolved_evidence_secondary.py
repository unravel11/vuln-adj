import unittest

import merge_rq2_typing_unresolved_evidence_secondary as subject


class MergeUnresolvedEvidenceSecondaryTests(unittest.TestCase):
    def test_successful_urls_require_ok_nonempty_text(self):
        blind = {
            "evidence_context": {
                "records": [
                    {"url": "https://ok", "fetch_status": "ok", "text_snippet": "evidence"},
                    {"url": "https://empty", "fetch_status": "ok", "text_snippet": ""},
                    {"url": "https://404", "fetch_status": "http_404", "text_snippet": "body"},
                ]
            }
        }
        self.assertEqual(subject.successful_urls(blind), {"https://ok"})

    def test_required_citation_must_hit_successful_url(self):
        blind = {
            "evidence_context": {
                "records": [{"url": "https://ok", "fetch_status": "ok", "text_snippet": "evidence"}]
            }
        }
        self.assertTrue(subject.citation_passed({"evidence_urls": ["https://ok"]}, blind, True))
        self.assertFalse(subject.citation_passed({"evidence_urls": []}, blind, True))
        self.assertTrue(subject.citation_passed({"evidence_urls": []}, blind, False))

    def test_gate_passes_only_at_all_fixed_thresholds(self):
        passed = subject.build_gate(0.75, 15, 1228)
        self.assertTrue(passed["passed"])
        self.assertEqual(passed["status"], "pass_non_human_evidence_secondary_development_only")
        self.assertFalse(subject.build_gate(0.74, 15, 1228)["passed"])
        self.assertFalse(subject.build_gate(0.75, 14, 1228)["passed"])
        self.assertFalse(subject.build_gate(0.75, 15, 1227)["passed"])


if __name__ == "__main__":
    unittest.main()
