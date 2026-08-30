import unittest
import urllib.parse

import fetch_e0_nvd_current as target


class RequestTests(unittest.TestCase):
    def test_build_url_uses_plural_cve_ids_and_sorted_batch(self):
        url = target.build_url(["CVE-2023-0002", "CVE-2023-0001"])
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(
            query,
            {"cveIds": ["CVE-2023-0001,CVE-2023-0002"]},
        )

    def test_build_url_rejects_more_than_100(self):
        with self.assertRaises(ValueError):
            target.build_url([f"CVE-2023-{index:04d}" for index in range(101)])


if __name__ == "__main__":
    unittest.main()

