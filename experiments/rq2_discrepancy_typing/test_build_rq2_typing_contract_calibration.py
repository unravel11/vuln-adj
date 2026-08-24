import unittest
from unittest import mock

import build_rq2_typing_contract_calibration as target


def severity_row(sample_id, *, left_score=7.5, right_score=None, left_vector="V", right_vector="V"):
    return {
        "sample_id": sample_id,
        "cve_id": f"CVE-TEST-{sample_id}",
        "field": "severity",
        "baseline_status": "equivalent",
        "nvd_source_id": sample_id,
        "ghsa_source_id": sample_id,
        "nvd_value": {"label": "HIGH", "score": left_score, "vector": left_vector},
        "ghsa_value": {"label": "HIGH", "score": right_score, "vector": right_vector},
        "field_context": {},
        "package_names": {"nvd": [], "ghsa": []},
        "reference_context": {"nvd_urls": [], "ghsa_urls": []},
    }


def affected_row(sample_id, *, unbounded=False):
    value = [{"vulnerable": True, "introduced": "0"}]
    return {
        "sample_id": sample_id,
        "cve_id": f"CVE-TEST-{sample_id}",
        "field": "affected_versions",
        "baseline_status": "equivalent",
        "nvd_source_id": sample_id,
        "ghsa_source_id": sample_id,
        "nvd_value": value,
        "ghsa_value": [] if unbounded else value,
        "field_context": {},
        "package_names": {"nvd": ["pkg"], "ghsa": ["pkg"]},
        "reference_context": {"nvd_urls": [], "ghsa_urls": []},
    }


def consensus(sample_id, label="equivalent"):
    return {
        "sample_id": sample_id,
        "strict_consensus": True,
        "consensus_label": label,
    }


class BuildContractCalibrationTests(unittest.TestCase):
    def test_boundary_strata(self):
        self.assertEqual(
            target.boundary_stratum(severity_row("exact")),
            "severity_exact_vector_one_missing_score",
        )
        self.assertEqual(
            target.boundary_stratum(
                severity_row("prefix", left_vector="V/X", right_vector="V")
            ),
            "severity_prefix_vector_one_missing_score",
        )
        self.assertEqual(
            target.boundary_stratum(
                severity_row("different", left_vector="V/X", right_vector="V/Y")
            ),
            "severity_different_vector_one_missing_score",
        )
        self.assertEqual(
            target.boundary_stratum(
                severity_row("missing", left_vector="V", right_vector=None)
            ),
            "severity_missing_vector_one_missing_score",
        )
        self.assertEqual(
            target.boundary_stratum(affected_row("affected", unbounded=True)),
            "affected_one_sided_unbounded_claim",
        )

    def test_controls_require_strict_unchanged_consensus(self):
        row = severity_row("control", left_score=7.5, right_score=7.5)
        self.assertEqual(
            target.control_stratum(row, consensus("control")),
            "severity_unchanged_control",
        )
        self.assertIsNone(
            target.control_stratum(row, consensus("control", "incomplete"))
        )

    def test_selection_is_complete_unique_and_blind(self):
        rows = [
            severity_row("exact"),
            severity_row("prefix", left_vector="V/X", right_vector="V"),
            severity_row("different", left_vector="V/X", right_vector="V/Y"),
            severity_row("missing", left_vector="V", right_vector=None),
            affected_row("affected", unbounded=True),
            severity_row("severity-control", left_score=7.5, right_score=7.5),
            affected_row("affected-control"),
        ]
        consensus_rows = [
            consensus(row["sample_id"], "incomplete" if row["sample_id"] in {
                "exact", "prefix", "missing", "affected"
            } else "factual_conflict" if row["sample_id"] == "different" else "equivalent")
            for row in rows
        ]
        targets = {name: 1 for name in target.STRATUM_TARGETS}
        with (
            mock.patch.object(target, "EXPECTED_SOURCE_ROWS", len(rows)),
            mock.patch.object(target, "EXPECTED_CALIBRATION_ROWS", len(rows)),
            mock.patch.object(target, "STRATUM_TARGETS", targets),
        ):
            selected = target.select_rows(rows, consensus_rows)
        self.assertEqual(len(selected), len(rows))
        self.assertEqual(len({row["sample_id"] for row in selected}), len(rows))
        blind = target.holdout.blind_row(selected[0])
        self.assertNotIn("calibration_stratum", blind)
        self.assertNotIn("prior_non_human_consensus_label", blind)
        self.assertNotIn("baseline_status", blind)


if __name__ == "__main__":
    unittest.main()
