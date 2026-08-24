import unittest

from validate_t1_human_validation_packet_v3 import (
    calibration_objective_matches,
    evaluation_cell,
    find_banned_keys,
    packet_without_stage,
)


class T1HumanValidationPacketV3ValidatorTest(unittest.TestCase):
    def test_banned_keys_are_found_recursively(self) -> None:
        value = {"left": {"value": 1}, "annotation": {"policy_output": ""}}
        self.assertEqual(find_banned_keys(value), ["annotation.policy_output"])

    def test_neutral_packet_keys_are_not_banned(self) -> None:
        value = {
            "left": {
                "value": "HIGH",
                "field_context": {},
                "package_names": [],
                "reference_urls": [],
                "reference_hosts": [],
            },
            "annotation": {"action_label": ""},
        }
        self.assertEqual(find_banned_keys(value), [])

    def test_validator_cell_logic_matches_frozen_shape(self) -> None:
        self.assertEqual(
            evaluation_cell(
                "references",
                "representation_discrepancy",
                "enrich_record->no_action",
            ),
            "status|representation_discrepancy",
        )

    def test_calibration_objective_rejects_wrong_status(self) -> None:
        row = {
            "calibration_objective": "severity_equivalent_agreement",
            "field": "severity",
            "baseline_status": "incomplete",
            "main_action_pair": "no_action->no_action",
        }
        self.assertFalse(calibration_objective_matches(row))

    def test_stage_normalization_removes_only_stage_fields(self) -> None:
        row = {
            "case_id": "case",
            "stage": "action",
            "packet_position": 1,
            "annotation": {"action_label": ""},
            "left": {"value": 1},
        }
        self.assertEqual(
            packet_without_stage(row),
            {"case_id": "case", "left": {"value": 1}},
        )


if __name__ == "__main__":
    unittest.main()
