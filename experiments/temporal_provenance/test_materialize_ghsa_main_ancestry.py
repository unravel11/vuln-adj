import unittest

import materialize_ghsa_main_ancestry as target


SYNTHETIC_LOG = b"""@@@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t\t2024-01-01T00:00:00+00:00\t2024-01-01T00:00:00+00:00\troot

A\tREADME.md
@@@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\t2024-01-02T00:00:00+00:00\t2024-01-02T00:00:00+00:00\tpublish

A\tadvisories/unreviewed/2024/01/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json
@@@cccccccccccccccccccccccccccccccccccccccc\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\t2024-01-03T00:00:00+00:00\t2023-12-31T00:00:00+00:00\tmigrate

R100\tadvisories/unreviewed/2024/01/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json\tadvisories/github-reviewed/2024/01/GHSA-2345-6789-cfgh/GHSA-2345-6789-cfgh.json
"""


class ParserTests(unittest.TestCase):
    def test_parse_keeps_first_parent_and_rename(self):
        commits = target.parse_log(SYNTHETIC_LOG)
        self.assertEqual(len(commits), 3)
        self.assertEqual(commits[2].parents[0], commits[1].oid)
        self.assertEqual(commits[2].changes[0]["status"], "R100")
        self.assertEqual(
            target.validate_topology(commits, commits[-1].oid), []
        )

    def test_commit_rows_detect_nonmonotone_clock(self):
        commits = target.parse_log(SYNTHETIC_LOG)
        rows, anomalies = target.commit_rows(commits)
        self.assertEqual(len(anomalies), 1)
        self.assertTrue(rows[-1]["clock_anomaly_from_previous"])

    def test_advisory_change_tracks_path_migration(self):
        commits = target.parse_log(SYNTHETIC_LOG)
        rows = target.advisory_change_rows(commits)
        self.assertEqual(len(rows), 2)
        self.assertFalse(rows[0]["path_migration"])
        self.assertTrue(rows[1]["path_migration"])
        self.assertEqual(rows[1]["old_ghsa_id"], rows[1]["new_ghsa_id"])

    def test_topology_break_fails(self):
        commits = target.parse_log(SYNTHETIC_LOG)
        commits[1].parents[0] = "0" * 40
        failures = target.validate_topology(commits, commits[-1].oid)
        self.assertEqual(failures[0]["kind"], "first_parent_chain_break")

    def test_expected_root_is_checked_separately(self):
        commits = target.parse_log(SYNTHETIC_LOG)
        failures = target.validate_topology(commits, commits[-1].oid, "0" * 40)
        self.assertEqual(failures[0]["kind"], "first_parent_root_mismatch")


class ChangeParserTests(unittest.TestCase):
    def test_deletion_keeps_old_path(self):
        self.assertEqual(
            target.parse_change_line("D\told.json"),
            {"status": "D", "old_path": "old.json", "new_path": None},
        )

    def test_invalid_rename_fails(self):
        with self.assertRaises(ValueError):
            target.parse_change_line("R100\tonly-one-path")


if __name__ == "__main__":
    unittest.main()
