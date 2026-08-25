import unittest

from validate_t1_human_validation_packet_v3_1 import (
    find_banned_keys,
    validate_packet_row,
)


def severity_packet() -> dict:
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
        "right": dict(side),
        "annotation": {
            "action_label": "",
            "action_rationale": "",
            "action_uncertainty": "",
            "reviewer_notes": "",
        },
    }


class T1HumanValidationPacketV31ValidatorTest(unittest.TestCase):
    def test_valid_recursive_allowlist_row_passes(self) -> None:
        errors: list[str] = []
        validate_packet_row(
            severity_packet(), "evaluation", "action", 1, "case", errors
        )
        self.assertEqual(errors, [])

    def test_novel_nested_key_fails_even_when_name_is_not_denylisted(self) -> None:
        row = severity_packet()
        row["left"]["field_context"]["harmless_new_hint"] = "answer"
        errors: list[str] = []
        validate_packet_row(row, "evaluation", "action", 1, "case", errors)
        self.assertTrue(any("keys must equal allowlist" in error for error in errors))
        self.assertEqual(find_banned_keys(row), [])

    def test_baseline_hint_v2_is_blocked_by_allowlist_and_denylist(self) -> None:
        row = severity_packet()
        row["left"]["field_context"]["baseline_hint_v2"] = "equivalent"
        errors: list[str] = []
        validate_packet_row(row, "evaluation", "action", 1, "case", errors)
        self.assertTrue(any("keys must equal allowlist" in error for error in errors))
        self.assertIn(
            "left.field_context.baseline_hint_v2",
            find_banned_keys(row),
        )

    def test_historical_nested_ai_candidate_is_blocked(self) -> None:
        row = severity_packet()
        row["left"]["ai_candidate"] = {"label": "factual_conflict"}
        errors: list[str] = []
        validate_packet_row(row, "evaluation", "action", 1, "case", errors)
        self.assertTrue(any("keys must equal allowlist" in error for error in errors))
        self.assertIn("left.ai_candidate", find_banned_keys(row))

    def test_discrepancy_type_is_blocked(self) -> None:
        row = severity_packet()
        row["right"]["field_context"]["discrepancy_type"] = "equivalent"
        errors: list[str] = []
        validate_packet_row(row, "evaluation", "action", 1, "case", errors)
        self.assertTrue(any("keys must equal allowlist" in error for error in errors))
        self.assertIn(
            "right.field_context.discrepancy_type",
            find_banned_keys(row),
        )


if __name__ == "__main__":
    unittest.main()
