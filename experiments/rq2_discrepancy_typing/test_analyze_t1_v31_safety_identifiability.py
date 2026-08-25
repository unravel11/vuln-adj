import unittest

from analyze_t1_v31_safety_identifiability import (
    minimum_zero_event_n,
    one_sided_cp_upper,
)


class T1V31SafetyIdentifiabilityTest(unittest.TestCase):
    def test_zero_event_bounds_match_closed_form(self) -> None:
        for total in (1, 25, 29, 34, 59):
            expected = 1.0 - (0.05 ** (1.0 / total))
            self.assertAlmostEqual(
                one_sided_cp_upper(0, total),
                expected,
                places=12,
            )

    def test_selected_ten_percent_margin_needs_29_zero_loss_cases(self) -> None:
        self.assertEqual(minimum_zero_event_n(0.10), 29)
        self.assertGreater(one_sided_cp_upper(0, 28), 0.10)
        self.assertLess(one_sided_cp_upper(0, 29), 0.10)

    def test_five_and_fifteen_percent_reference_margins(self) -> None:
        self.assertEqual(minimum_zero_event_n(0.05), 59)
        self.assertEqual(minimum_zero_event_n(0.15), 19)

    def test_general_upper_bound_is_monotone_in_event_count(self) -> None:
        self.assertLess(
            one_sided_cp_upper(0, 50),
            one_sided_cp_upper(1, 50),
        )


if __name__ == "__main__":
    unittest.main()
