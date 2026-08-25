import unittest

from seal_t1_human_validation_stage_v3_1 import raw_agreement


def row(case_id: str, label: str, stage: str = "action") -> dict:
    key = "action_label" if stage == "action" else "reason_label"
    return {"case_id": case_id, "annotation": {key: label}}


class SealT1HumanValidationStageV31Test(unittest.TestCase):
    def test_raw_agreement_uses_case_identity(self) -> None:
        rows_a = [row("one", "no_action"), row("two", "abstain")]
        rows_b = [row("two", "abstain"), row("one", "enrich_record")]
        agreements, total, rate = raw_agreement(rows_a, rows_b, "action")
        self.assertEqual((agreements, total), (1, 2))
        self.assertEqual(rate, 0.5)


if __name__ == "__main__":
    unittest.main()
