import unittest

import analyze_hutool_maven_external_application as target


class AnalyzeHutoolExternalApplicationTests(unittest.TestCase):
    def test_boundaries_ignore_introduced_zero(self):
        items = [{
            "version_start_including": "0",
            "version_end_excluding": "5.8.21",
            "fixed": "5.8.21",
        }]
        self.assertEqual(target.claim_boundaries(items), {"5.8.21"})

    def test_affected_set_handles_singleton(self):
        items = [{"version": "5.8.21"}]
        domain = {"5.8.20", "5.8.21", "5.8.22"}
        self.assertEqual(target.affected_set(items, domain), {"5.8.21"})

    def test_affected_set_handles_exclusive_upper(self):
        items = [{"version_start_including": "0", "version_end_excluding": "5.8.21"}]
        domain = {"5.8.20", "5.8.21", "5.8.22"}
        self.assertEqual(target.affected_set(items, domain), {"5.8.20"})


if __name__ == "__main__":
    unittest.main()
