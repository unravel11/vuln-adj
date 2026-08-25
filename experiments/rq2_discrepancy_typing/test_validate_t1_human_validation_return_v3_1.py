import copy
import unittest

from validate_t1_human_validation_return_v3_1 import validate_return_rows


def blank_row() -> dict:
    side = {
        "value": "HIGH",
        "field_context": {
            "canonical_label": "HIGH",
            "label": "HIGH",
            "score": 8.1,
            "vector": "CVSS:3.1/AV:N",
        },
        "package_names": [],
        "reference_urls": [],
        "reference_hosts": [],
    }
    return {
        "schema_version": "t1_action_reason_packet_v3_1",
        "protocol_id": "vuln-adj-jss-t1-human-validation-v3.1",
        "phase": "evaluation",
        "stage": "action",
        "packet_position": 1,
        "case_id": "t1v31-eval-example",
        "cve_id": "CVE-2026-0001",
        "field": "severity",
        "left": side,
        "right": copy.deepcopy(side),
        "annotation": {
            "action_label": "",
            "action_rationale": "",
            "action_uncertainty": "",
            "reviewer_notes": "",
        },
    }


class T1HumanValidationReturnV31Test(unittest.TestCase):
    def completed(self) -> tuple[dict, dict]:
        blank = blank_row()
        returned = copy.deepcopy(blank)
        returned["annotation"]["action_label"] = "conflict_escalation"
        returned["annotation"]["action_rationale"] = "The comparable labels conflict."
        return blank, returned

    def test_complete_return_passes(self) -> None:
        blank, returned = self.completed()
        self.assertEqual(
            validate_return_rows(
                [blank], [returned], "reviewer_a", "evaluation", "action"
            ),
            [],
        )

    def test_blank_rationale_fails(self) -> None:
        blank, returned = self.completed()
        returned["annotation"]["action_rationale"] = ""
        errors = validate_return_rows(
            [blank], [returned], "reviewer_a", "evaluation", "action"
        )
        self.assertTrue(any("rationale is required" in error for error in errors))

    def test_context_modification_fails(self) -> None:
        blank, returned = self.completed()
        returned["left"]["value"] = "LOW"
        errors = validate_return_rows(
            [blank], [returned], "reviewer_a", "evaluation", "action"
        )
        self.assertTrue(
            any("sealed packet content was modified" in error for error in errors)
        )

    def test_case_reordering_fails(self) -> None:
        first_blank, first_return = self.completed()
        second_blank = copy.deepcopy(first_blank)
        second_return = copy.deepcopy(first_return)
        second_blank["case_id"] = "second"
        second_return["case_id"] = "second"
        errors = validate_return_rows(
            [first_blank, second_blank],
            [second_return, first_return],
            "reviewer_a",
            "evaluation",
            "action",
        )
        self.assertTrue(any("case set or order differs" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
