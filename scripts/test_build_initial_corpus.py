#!/usr/bin/env python3
"""Focused tests for raw-corpus normalization semantics."""

from __future__ import annotations

import unittest

from build_initial_corpus import normalize_nvd_affected


class NormalizeNvdAffectedTest(unittest.TestCase):
    def test_excludes_non_vulnerable_applicability_matches(self) -> None:
        configurations = [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                "vulnerable": True,
                                "versionEndExcluding": "2.0.0",
                            },
                            {
                                "criteria": "cpe:2.3:o:acme:platform:*:*:*:*:*:*:*:*",
                                "vulnerable": False,
                            },
                        ],
                        "children": [
                            {
                                "cpeMatch": [
                                    {
                                        "criteria": "cpe:2.3:h:acme:device:*:*:*:*:*:*:*:*",
                                        "vulnerable": False,
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ]

        affected = normalize_nvd_affected(configurations)

        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0]["package_name"], "widget")
        self.assertIs(affected[0]["vulnerable"], True)

    def test_retains_match_when_legacy_input_omits_vulnerable_flag(self) -> None:
        configurations = [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ]
            }
        ]

        affected = normalize_nvd_affected(configurations)

        self.assertEqual(len(affected), 1)
        self.assertIsNone(affected[0]["vulnerable"])


if __name__ == "__main__":
    unittest.main()
