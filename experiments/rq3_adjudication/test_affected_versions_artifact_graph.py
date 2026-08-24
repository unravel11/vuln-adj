#!/usr/bin/env python3
"""Focused tests for the artifact-bound branch graph candidate."""

from __future__ import annotations

import unittest

from affected_versions_artifact_graph import (
    artifact_bound_prediction,
    artifact_bound_support,
    source_artifact_aliases,
)


def support(value: bool) -> dict:
    return {"has_positive_support": value}


class ArtifactGraphTest(unittest.TestCase):
    def test_source_aliases_remove_shared_generic_identity(self) -> None:
        row = {
            "nvd_context": {"package_names": ["build_of_keycloak"]},
            "ghsa_context": {
                "package_names": ["org.keycloak:keycloak-services"]
            },
        }
        aliases = source_artifact_aliases(row)
        self.assertIn("buildofkeycloak", aliases["nvd"])
        self.assertIn("keycloakservices", aliases["ghsa"])
        self.assertNotIn("keycloak", aliases["nvd"])
        self.assertNotIn("keycloak", aliases["ghsa"])

    def test_support_requires_cve_alias_and_version_in_same_record(self) -> None:
        row = {
            "cve_id": "CVE-2025-3910",
            "nvd_value": [{"version_end_excluding": "26.0.11"}],
            "evidence_context": {
                "records": [
                    {
                        "url": "https://example.test/CVE-2025-3910",
                        "host": "example.test",
                        "fetch_status": "ok",
                        "title": "build_of_keycloak advisory",
                        "text_snippet": "Versions before 26.0.11 are affected.",
                    }
                ]
            },
        }
        result = artifact_bound_support(row, "nvd", ["buildofkeycloak"])
        self.assertTrue(result["has_positive_support"])
        self.assertEqual(result["matched_version_tokens"], ["26.0.11"])

    def test_support_rejects_unscoped_or_split_evidence(self) -> None:
        row = {
            "cve_id": "CVE-2025-3910",
            "nvd_value": [{"version_end_excluding": "26.0.11"}],
            "evidence_context": {
                "records": [
                    {
                        "url": "https://example.test/unrelated",
                        "host": "example.test",
                        "fetch_status": "ok",
                        "title": "build_of_keycloak 26.0.11",
                        "text_snippet": "No target CVE is present.",
                    },
                    {
                        "url": "https://example.test/CVE-2025-3910",
                        "host": "example.test",
                        "fetch_status": "ok",
                        "title": "build_of_keycloak",
                        "text_snippet": "No version is present.",
                    },
                ]
            },
        }
        result = artifact_bound_support(row, "nvd", ["buildofkeycloak"])
        self.assertFalse(result["has_positive_support"])

    def test_override_rejecting_prediction_when_both_sides_supported(self) -> None:
        prediction, reason = artifact_bound_prediction(
            "neither",
            "no_package_name_overlap",
            {"nvd": support(True), "ghsa": support(True)},
        )
        self.assertEqual(prediction, "both")
        self.assertIn("independent_artifact_bound_support", reason)

    def test_retain_one_sided_prediction(self) -> None:
        prediction, _ = artifact_bound_prediction(
            "nvd",
            "no_package_name_overlap",
            {"nvd": support(True), "ghsa": support(True)},
        )
        self.assertEqual(prediction, "nvd")

    def test_retain_when_support_or_identifier_separation_is_missing(self) -> None:
        prediction, _ = artifact_bound_prediction(
            "abstain",
            "no_package_name_overlap",
            {"nvd": support(True), "ghsa": support(False)},
        )
        self.assertEqual(prediction, "abstain")
        prediction, _ = artifact_bound_prediction(
            "neither",
            "exact_or_canonical_package_overlap",
            {"nvd": support(True), "ghsa": support(True)},
        )
        self.assertEqual(prediction, "neither")


if __name__ == "__main__":
    unittest.main()
