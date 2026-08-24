import unittest

from build_rq2_post_profile_cwe_all50_evidence import cwe_rows, set_relation


class BuildPostProfileCweAll50EvidenceTests(unittest.TestCase):
    def test_relation_categories_are_projected_without_profile_labels(self):
        self.assertEqual(set_relation("exact_set"), "exact_set")
        self.assertEqual(set_relation("literal_strict_subset"), "literal_strict_subset")
        self.assertEqual(
            set_relation("overlap_partial_taxonomy_coverage"),
            "overlap_non_subset",
        )
        self.assertEqual(
            set_relation("disjoint_full_taxonomy_coverage"),
            "disjoint",
        )

    def test_selection_requires_every_one_of_50_cwe_rows(self):
        rows = [
            {"sample_id": f"cwe:{index}", "field": "cwe_ids"}
            for index in range(50)
        ] + [{"sample_id": "severity:1", "field": "severity"}]
        self.assertEqual(len(cwe_rows(rows)), 50)
        with self.assertRaisesRegex(ValueError, "expected 50 CWE rows"):
            cwe_rows(rows[:-2])

    def test_selection_rejects_duplicate_sample_ids(self):
        rows = [
            {"sample_id": f"cwe:{index}", "field": "cwe_ids"}
            for index in range(49)
        ]
        rows.append({"sample_id": "cwe:0", "field": "cwe_ids"})
        with self.assertRaisesRegex(ValueError, "not unique"):
            cwe_rows(rows)


if __name__ == "__main__":
    unittest.main()
