import unittest

import build_artifact_lineage_unseen_ecosystem_cohort as target


def affected(subject, ecosystem, start, end):
    return {
        "product": subject,
        "package_name": subject,
        "ecosystem": ecosystem,
        "introduced": start,
        "fixed": end,
        "version_start_including": start,
        "version_end_excluding": end,
        "vulnerable": True,
    }


def aligned(cve_id, ecosystem="PyPI", second_end="3.0.0"):
    return {
        "_input_line_number": 1,
        "cve_id": cve_id,
        "nvd": {
            "affected": [affected("demo", None, "1.0.0", "2.0.0")],
            "references": [],
        },
        "ghsa": [
            {
                "source_id": "GHSA-test",
                "affected": [
                    affected("demo-core", ecosystem, "1.0.0", "2.0.0"),
                    affected("demo-extra", ecosystem, "1.0.0", second_end),
                ],
                "references": [],
            }
        ],
    }


class BuildArtifactLineageUnseenEcosystemCohortTests(unittest.TestCase):
    def test_heterogeneous_two_component_row_is_eligible(self):
        row = target.eligible_row(aligned("CVE-2099-0001"))
        self.assertIsNotNone(row)
        self.assertEqual(row["ghsa_subjects"], ["demo-core", "demo-extra"])
        self.assertFalse(row["selection_uses_reviewer_labels"])
        self.assertFalse(row["upstream_source_conditioned_on_non_human_consensus"])

    def test_equal_component_ranges_are_excluded(self):
        self.assertIsNone(target.eligible_row(aligned("CVE-2099-0001", second_end="2.0.0")))

    def test_range_order_does_not_create_false_heterogeneity(self):
        row = aligned("CVE-2099-0001", second_end="2.0.0")
        first = affected("demo-core", "PyPI", "3.0.0", "4.0.0")
        second = affected("demo-extra", "PyPI", "3.0.0", "4.0.0")
        row["ghsa"][0]["affected"].insert(0, first)
        row["ghsa"][0]["affected"].append(second)
        self.assertIsNone(target.eligible_row(row))

    def test_minimum_hash_rank_is_selected_per_ecosystem(self):
        original = target.EXPECTED_CVES
        rows = []
        expected = {}
        for ecosystem in target.TARGET_ECOSYSTEMS:
            candidates = [
                aligned(f"CVE-2099-{index:04d}", ecosystem=ecosystem)
                for index in (1, 2)
            ]
            rows.extend(candidates)
            selected = min(
                candidates,
                key=lambda row: target.hashlib.sha256(row["cve_id"].encode()).hexdigest(),
            )
            expected[ecosystem] = selected["cve_id"]
        try:
            target.EXPECTED_CVES = expected
            cohort, counts = target.build_cohort(rows)
        finally:
            target.EXPECTED_CVES = original
        self.assertEqual({row["ecosystem"]: row["cve_id"] for row in cohort}, expected)
        self.assertEqual(counts, {ecosystem: 2 for ecosystem in target.TARGET_ECOSYSTEMS})


if __name__ == "__main__":
    unittest.main()
