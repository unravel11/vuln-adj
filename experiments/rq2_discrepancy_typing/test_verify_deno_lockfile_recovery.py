#!/usr/bin/env python3

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_deno_lockfile_recovery as subject


class VerifyDenoLockfileRecoveryTests(unittest.TestCase):
    def test_lockfile_parser_rejects_ambiguous_runtime(self):
        body = b'''version = 3\n\n[[package]]\nname = "deno_runtime"\nversion = "0.150.0"\n'''
        self.assertEqual(subject.parse_lockfile(body), "0.150.0")
        duplicate = body + b'\n[[package]]\nname = "deno_runtime"\nversion = "0.151.0"\n'
        with self.assertRaisesRegex(ValueError, "expected one"):
            subject.parse_lockfile(duplicate)

    def test_directional_relation(self):
        self.assertEqual(subject.set_relation({"a"}, {"a", "b"}), "nvd_subset_of_ghsa")
        self.assertEqual(subject.set_relation({"a", "b"}, {"a"}), "ghsa_subset_of_nvd")
        self.assertEqual(subject.set_relation({"a", "b"}, {"b", "c"}), "overlap")

    def test_direct_fixed_boundaries_are_excluded(self):
        self.assertTrue(subject.in_direct_spans(subject.Version.parse("1.41.3")))
        self.assertFalse(subject.in_direct_spans(subject.Version.parse("2.1.13")))
        self.assertTrue(subject.in_direct_spans(subject.Version.parse("2.3.0")))
        self.assertFalse(subject.in_direct_spans(subject.Version.parse("2.3.2")))


if __name__ == "__main__":
    unittest.main()
