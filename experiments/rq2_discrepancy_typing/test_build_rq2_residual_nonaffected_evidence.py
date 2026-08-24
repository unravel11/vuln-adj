import unittest

import build_rq2_residual_nonaffected_evidence as target


def consensus(sample_id, cve_id, field, strict=False):
    return {
        "sample_id": sample_id,
        "cve_id": cve_id,
        "field": field,
        "secondary_strict_consensus": strict,
    }


class BuildResidualNonAffectedEvidenceTests(unittest.TestCase):
    def expected_rows(self):
        return [
            consensus(sample_id, cve_id, field)
            for sample_id, (cve_id, field) in target.EXPECTED_ROWS.items()
        ]

    def test_selects_exact_three_nonaffected_unresolved_rows(self):
        rows = self.expected_rows() + [
            consensus("affected", "CVE-X", "affected_versions"),
            consensus("strict", "CVE-Y", "cwe_ids", strict=True),
        ]
        selected = target.select_residual(rows)
        self.assertEqual({row["sample_id"] for row in selected}, set(target.EXPECTED_ROWS))

    def test_selection_drift_fails_closed(self):
        with self.assertRaises(ValueError):
            target.select_residual(self.expected_rows()[:-1])

    def test_projection_excludes_labels_and_baseline(self):
        row = {
            "sample_id": "sample",
            "cve_id": "CVE-X",
            "field": "cwe_ids",
            "nvd_value": ["CWE-1"],
            "ghsa_value": ["CWE-2"],
            "baseline_status": "factual_conflict",
            "annotation": {"label": "uncertain"},
        }
        projected = target.worklist_projection(row)
        self.assertNotIn("baseline_status", projected)
        self.assertNotIn("annotation", projected)

    def test_cache_names_are_url_deterministic(self):
        first = target.cache_paths(target.Path("cache"), "https://example.test/a")
        second = target.cache_paths(target.Path("cache"), "https://example.test/a")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
