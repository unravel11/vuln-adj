import unittest

import analyze_rq2_staged_adjudication_frontier as target


def request(*sample_ids):
    return {
        "event_type": "request",
        "items": [{"sample_id": sample_id} for sample_id in sample_ids],
    }


def success(*sample_ids, input_tokens=0):
    return {
        "event_type": "response_success",
        "sample_ids": list(sample_ids),
        "execution_usage": {"input_tokens": input_tokens},
    }


class RequestAuditTests(unittest.TestCase):
    def test_exact_duplicate_gap_is_ambiguous(self):
        audit = target.audit_events(
            [request("a", "b"), request("a", "b"), success("a", "b", input_tokens=9)],
            "reviewer_x",
        )
        self.assertEqual(audit["unpaired_request_attempts"], 1)
        self.assertEqual(audit["retry_row_overhead"], 2)
        self.assertTrue(audit["gap_payload_groups"][0]["attempt_identity_ambiguous"])
        self.assertTrue(audit["gap_payload_groups"][0]["all_rows_eventually_successful"])
        self.assertEqual(audit["recorded_success_usage"]["input_tokens"], 9)

    def test_split_retry_keeps_original_payload_gap(self):
        audit = target.audit_events(
            [
                request("a", "b", "c"),
                request("a"),
                success("a"),
                request("b", "c"),
                success("b", "c"),
            ],
            "reviewer_x",
        )
        self.assertEqual(audit["unpaired_request_attempts"], 1)
        self.assertEqual(audit["request_row_attempts"], 6)
        self.assertEqual(audit["successful_reviewer_rows"], 3)
        self.assertFalse(audit["gap_payload_groups"][0]["attempt_identity_ambiguous"])
        self.assertTrue(audit["gap_payload_groups"][0]["all_rows_eventually_successful"])

    def test_unknown_event_fails_closed(self):
        with self.assertRaises(ValueError):
            target.audit_events([{"event_type": "response_error"}], "reviewer_x")


class FrontierTests(unittest.TestCase):
    def test_safe_divide_handles_zero(self):
        self.assertEqual(target.safe_divide(3, 0), 0.0)


if __name__ == "__main__":
    unittest.main()
