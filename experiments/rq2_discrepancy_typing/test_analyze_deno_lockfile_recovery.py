#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_deno_lockfile_recovery as subject


class DenoLockfileRecoveryTests(unittest.TestCase):
    def test_release_domain_filters_and_selects_immediate_anchors(self):
        page = [
            {"tag_name": "v2.3.3", "draft": False, "prerelease": False},
            {"tag_name": "v2.3.2", "draft": False, "prerelease": False},
            {"tag_name": "v2.3.2-rc.0", "draft": False, "prerelease": True},
            {"tag_name": "v2.3.0", "draft": False, "prerelease": False},
            {"tag_name": "v2.2.13", "draft": False, "prerelease": False},
            {"tag_name": "v2.2.0", "draft": False, "prerelease": False},
            {"tag_name": "v2.1.13", "draft": False, "prerelease": False},
            {"tag_name": "v1.41.3", "draft": False, "prerelease": False},
            {"tag_name": "v1.41.2", "draft": False, "prerelease": False},
        ]
        releases = subject.eligible_releases([page, []])
        domain = subject.select_product_domain(releases)
        self.assertEqual(domain["predecessor"].text(), "1.41.2")
        self.assertEqual(domain["successor"].text(), "2.3.3")
        self.assertEqual(domain["missing_boundaries"], [])
        self.assertEqual([item.text() for item in domain["core"]][0], "1.41.3")
        self.assertEqual([item.text() for item in domain["core"]][-1], "2.3.2")

    def test_duplicate_stable_release_is_rejected(self):
        duplicate = {"tag_name": "v1.41.3", "draft": False, "prerelease": False}
        with self.assertRaisesRegex(ValueError, "duplicate eligible"):
            subject.eligible_releases([[duplicate, duplicate], []])

    def test_lockfile_requires_one_exact_runtime(self):
        body = b'''version = 3\n\n[[package]]\nname = "deno_runtime"\nversion = "0.150.0"\n'''
        parsed = subject.parse_lockfile_runtime(body)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["runtime_version"], "0.150.0")

        duplicate = body + b'\n[[package]]\nname = "deno_runtime"\nversion = "0.151.0"\n'
        parsed = subject.parse_lockfile_runtime(duplicate)
        self.assertFalse(parsed["passed"])
        self.assertEqual(parsed["match_count"], 2)

    def test_relation_and_candidate_are_directional(self):
        nvd = {"1.41.3", "1.41.4"}
        ghsa = {"1.41.3", "1.41.4", "2.1.13"}
        relation = subject.set_relation(nvd, ghsa)
        self.assertEqual(relation, "nvd_subset_of_ghsa")
        self.assertEqual(subject.relation_candidate(relation), "incomplete")
        self.assertEqual(subject.relation_candidate("equal"), "representation_discrepancy")

    def test_direct_spans_exclude_fixed_boundaries(self):
        self.assertTrue(subject.in_spans(subject.StableVersion.parse("1.41.3"), subject.DIRECT_SPANS))
        self.assertFalse(subject.in_spans(subject.StableVersion.parse("2.1.13"), subject.DIRECT_SPANS))
        self.assertTrue(subject.in_spans(subject.StableVersion.parse("2.2.0"), subject.DIRECT_SPANS))
        self.assertFalse(subject.in_spans(subject.StableVersion.parse("2.3.2"), subject.DIRECT_SPANS))


if __name__ == "__main__":
    unittest.main()
