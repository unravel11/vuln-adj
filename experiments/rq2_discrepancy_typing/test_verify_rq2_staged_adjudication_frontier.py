import unittest

import verify_rq2_staged_adjudication_frontier as target


class IndependentRequestStatsTests(unittest.TestCase):
    def test_counts_duplicate_request_gap(self):
        events = [
            {"event_type": "request", "items": [{"sample_id": "a"}]},
            {"event_type": "request", "items": [{"sample_id": "a"}]},
            {
                "event_type": "response_success",
                "sample_ids": ["a"],
                "execution_usage": {"output_tokens": 4},
            },
        ]
        stats = target.independent_log_stats(events)
        self.assertEqual(stats["unpaired_request_attempts"], 1)
        self.assertEqual(stats["retry_row_overhead"], 1)
        self.assertEqual(stats["ambiguous_gap_group_count"], 1)
        self.assertEqual(stats["recorded_success_usage"]["output_tokens"], 4)

    def test_rejects_unknown_event(self):
        with self.assertRaises(ValueError):
            target.independent_log_stats([{"event_type": "response_error"}])


if __name__ == "__main__":
    unittest.main()
