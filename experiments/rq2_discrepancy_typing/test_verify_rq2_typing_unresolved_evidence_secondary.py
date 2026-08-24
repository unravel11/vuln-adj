import unittest

import verify_rq2_typing_unresolved_evidence_secondary as subject


def review(label="incomplete", confidence="medium", needs_review=False, urls=None):
    return {
        "discrepancy_label": label,
        "confidence": confidence,
        "needs_human_review": needs_review,
        "evidence_urls": urls or [],
    }


class VerifyUnresolvedEvidenceSecondaryTests(unittest.TestCase):
    def test_strict_pair_rejects_uncertain_low_and_review_requests(self):
        self.assertTrue(subject.strict_pair(review(), review()))
        self.assertFalse(subject.strict_pair(review("uncertain"), review("uncertain")))
        self.assertFalse(subject.strict_pair(review(confidence="low"), review()))
        self.assertFalse(subject.strict_pair(review(needs_review=True), review()))

    def test_citation_check_is_independent_of_strict_label(self):
        blind = {
            "evidence_context": {
                "records": [{"url": "https://ok", "fetch_status": "ok", "text_snippet": "body"}]
            }
        }
        self.assertTrue(subject.citation_ok(review(urls=["https://ok"]), blind, True))
        self.assertFalse(subject.citation_ok(review(), blind, True))

    def test_independent_gate_matches_boundary(self):
        gate = subject.gate(1.0, 37, 1250)
        self.assertTrue(gate["passed"])
        self.assertFalse(gate["human_gold_claim_allowed"])
        self.assertFalse(gate["accuracy_claim_allowed"])
        self.assertFalse(gate["production_switch_allowed"])


if __name__ == "__main__":
    unittest.main()
