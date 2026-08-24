import unittest

import build_hutool_maven_external_application as target


def aligned_row(cve_id="CVE-test", package="cn.hutool:hutool-core"):
    return {
        "cve_id": cve_id,
        "nvd": {"affected": [{
            "product": "hutool", "package_name": "hutool", "vulnerable": True,
        }]},
        "ghsa": [{"affected": [{
            "package_name": package, "ecosystem": "Maven", "vulnerable": True,
        }]}],
    }


class BuildHutoolExternalApplicationTests(unittest.TestCase):
    def test_component_route_is_selected(self):
        result = target.hutool_family_row(aligned_row())
        self.assertEqual(result["route"], "product_via_aggregate_component")

    def test_aggregate_route_is_selected(self):
        result = target.hutool_family_row(aligned_row(package=target.AGGREGATE))
        self.assertEqual(result["route"], "product_to_aggregate_direct")

    def test_unfrozen_component_is_out_of_scope(self):
        result = target.hutool_family_row(aligned_row(package="cn.hutool:hutool-extra"))
        self.assertEqual(result["route"], "out_of_scope_coordinate")

    def test_non_hutool_product_is_not_selected(self):
        row = aligned_row()
        row["nvd"]["affected"][0]["product"] = "other"
        row["nvd"]["affected"][0]["package_name"] = "other"
        self.assertIsNone(target.hutool_family_row(row))


if __name__ == "__main__":
    unittest.main()
