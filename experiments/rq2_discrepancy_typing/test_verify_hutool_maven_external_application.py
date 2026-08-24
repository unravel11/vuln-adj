import unittest

import verify_hutool_maven_external_application as target


class VerifyHutoolExternalApplicationTests(unittest.TestCase):
    def test_remote_path_relocates_to_local_project(self):
        remote = target.AUTHORITATIVE_PROJECT_ROOT / "AGENTS.md"
        self.assertEqual(target.resolve(remote), target.PROJECT_ROOT / "AGENTS.md")

    def test_boundaries_ignore_open_lower_zero(self):
        self.assertEqual(
            target.boundaries([{
                "version_start_including": "0", "version_end_including": "5.8.19"
            }]),
            {"5.8.19"},
        )

    def test_relation_candidate_mapping_reuses_independent_v1_contract(self):
        self.assertEqual(
            target.base.candidate(target.base.relation({"5.8.21"}, {"5.8.20", "5.8.21"})),
            "incomplete",
        )


if __name__ == "__main__":
    unittest.main()
