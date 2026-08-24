#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_cwe_taxonomy_evidence_secondary_audit as target


class BuildCweTaxonomyEvidenceSecondaryAuditTests(unittest.TestCase):
    def test_commit_and_pull_urls_use_patch_snapshots(self) -> None:
        self.assertEqual(
            target.derive_fetch_url("https://github.com/acme/project/commit/abc"),
            "https://github.com/acme/project/commit/abc.patch",
        )
        self.assertEqual(
            target.derive_fetch_url("https://github.com/acme/project/pull/12"),
            "https://github.com/acme/project/pull/12.patch",
        )

    def test_blob_url_uses_raw_snapshot(self) -> None:
        self.assertEqual(
            target.derive_fetch_url(
                "https://github.com/acme/project/blob/main/src/file.py"
            ),
            "https://raw.githubusercontent.com/acme/project/main/src/file.py",
        )

    def test_reference_selection_excludes_aggregators_and_repo_roots(self) -> None:
        aligned = {
            "nvd": {
                "references": [
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-1"},
                    {"url": "https://github.com/acme/project"},
                    {"url": "https://github.com/acme/project/commit/abc"},
                ]
            },
            "ghsa": [
                {
                    "references": [
                        {
                            "url": "https://github.com/acme/project/security/advisories/GHSA-1"
                        }
                    ]
                }
            ],
        }
        selected = target.collect_references(aligned)
        self.assertEqual(
            [row["source_url"] for row in selected],
            [
                "https://github.com/acme/project/security/advisories/GHSA-1",
                "https://github.com/acme/project/commit/abc",
            ],
        )

    def test_priority_contract_includes_unresolved_and_regression(self) -> None:
        unresolved = {
            "agent_a": {"discrepancy_label": "uncertain"},
            "agent_b": {"discrepancy_label": "representation_discrepancy"},
            "strict_consensus": False,
            "consensus_label": None,
            "current_prediction": "factual_conflict",
            "taxonomy_v1_prediction": "representation_discrepancy",
        }
        regression = {
            "agent_a": {"discrepancy_label": "factual_conflict"},
            "agent_b": {"discrepancy_label": "factual_conflict"},
            "strict_consensus": True,
            "consensus_label": "factual_conflict",
            "current_prediction": "factual_conflict",
            "taxonomy_v1_prediction": "representation_discrepancy",
        }
        self.assertTrue(target.expected_priority(unresolved))
        self.assertTrue(target.expected_priority(regression))


if __name__ == "__main__":
    unittest.main()
