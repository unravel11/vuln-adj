import unittest

from build_t1_human_validation_packet_v3 import (
    calibration_match,
    evaluation_cell,
    stable_select,
)


class T1HumanValidationPacketV3BuilderTest(unittest.TestCase):
    def test_severity_disagreement_cell_keeps_status_and_pair(self) -> None:
        self.assertEqual(
            evaluation_cell(
                "severity",
                "factual_conflict",
                "conflict_escalation->abstain",
            ),
            "disagreement|factual_conflict|conflict_escalation->abstain",
        )

    def test_affected_agreement_cell_collapses_action(self) -> None:
        self.assertEqual(
            evaluation_cell(
                "affected_versions", "incomplete", "enrich_record->enrich_record"
            ),
            "agreement|incomplete",
        )

    def test_published_cell_is_status_only(self) -> None:
        self.assertEqual(
            evaluation_cell(
                "published", "temporal_discrepancy", "wait_for_sync->wait_for_sync"
            ),
            "status|temporal_discrepancy",
        )

    def test_stable_selection_is_input_order_independent(self) -> None:
        rows = [
            {"sample_id": f"row-{index}", "cve_id": f"CVE-2026-{index:04d}"}
            for index in range(10)
        ]
        first = stable_select(rows, 4, "seed", "scope")
        second = stable_select(list(reversed(rows)), 4, "seed", "scope")
        self.assertEqual(
            [row["sample_id"] for row in first],
            [row["sample_id"] for row in second],
        )

    def test_calibration_match_enforces_pair_and_status(self) -> None:
        row = {
            "field": "affected_versions",
            "baseline_status": "equivalent",
            "main_action_pair": "no_action->abstain",
        }
        self.assertTrue(
            calibration_match(
                row,
                {
                    "field": "affected_versions",
                    "status": "equivalent",
                    "pair": "no_action->abstain",
                },
            )
        )
        self.assertFalse(
            calibration_match(
                row,
                {
                    "field": "affected_versions",
                    "status": "representation_discrepancy",
                    "pair": "no_action->abstain",
                },
            )
        )


if __name__ == "__main__":
    unittest.main()
