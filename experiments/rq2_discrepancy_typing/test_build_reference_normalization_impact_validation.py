#!/usr/bin/env python3

from __future__ import annotations

import unittest

import build_reference_normalization_impact_validation as target


def row(nvd_urls: list[str], ghsa_urls: list[str]) -> dict:
    current = target.VARIANTS["current_exact"]
    proposed = target.VARIANTS["transport_line_known_query_aliases"]
    return {
        "nvd_urls": nvd_urls,
        "ghsa_urls": ghsa_urls,
        "proposed_normalized_nvd": sorted(
            {target.canonicalize_reference_url(url, proposed) for url in nvd_urls}
        ),
        "proposed_normalized_ghsa": sorted(
            {target.canonicalize_reference_url(url, proposed) for url in ghsa_urls}
        ),
        "current_normalized_nvd": sorted(
            {target.canonicalize_reference_url(url, current) for url in nvd_urls}
        ),
        "current_normalized_ghsa": sorted(
            {target.canonicalize_reference_url(url, current) for url in ghsa_urls}
        ),
    }


class BuildReferenceNormalizationImpactValidationTests(unittest.TestCase):
    def test_encoded_line_group_requires_one_identity_proof(self) -> None:
        base = "https://github.com/acme/project/blob/main/file.py"
        groups = target.identity_groups(row([base + "%23L10-L20"], [base]))
        proof = [group for group in groups if group["proof_required"]]
        self.assertEqual(len(proof), 1)
        certificate = target.structural_eligibility(proof[0])
        self.assertEqual(certificate["rules"], ["encoded_line_suffix"])
        self.assertTrue(certificate["eligible"])

    def test_encoded_line_rule_is_rejected_off_github_blob(self) -> None:
        base = "https://example.com/file.py"
        proof = [
            group
            for group in target.identity_groups(row([base + "%23L10"], [base]))
            if group["proof_required"]
        ][0]
        self.assertFalse(target.structural_eligibility(proof)["eligible"])

    def test_huntr_domains_share_uuid_identity(self) -> None:
        left = "https://huntr.com/bounties/81b1e1da-10dd-435e-94ae-4bdd41df6df9"
        right = "https://huntr.dev/bounties/81b1e1da-10dd-435e-94ae-4bdd41df6df9"
        proof = [
            group
            for group in target.identity_groups(row([left], [right]))
            if group["proof_required"]
        ][0]
        certificate = target.structural_eligibility(proof)
        self.assertEqual(certificate["rules"], ["huntr_bounty_alias"])
        self.assertTrue(certificate["eligible"])

    def test_liferay_query_is_structurally_scoped(self) -> None:
        base = (
            "https://liferay.dev/portal/security/known-vulnerabilities/"
            "-/asset_publisher/jekt/content/cve-2024-1"
        )
        proof = [
            group
            for group in target.identity_groups(row([base], [base + "?p_r_p_assetEntryId=1"]))
            if group["proof_required"]
        ][0]
        certificate = target.structural_eligibility(proof)
        self.assertEqual(certificate["rules"], ["known_presentation_query"])
        self.assertTrue(certificate["eligible"])

    def test_same_final_url_is_live_corroboration(self) -> None:
        left = "http://example.com/advisory"
        right = "https://example.com/advisory"
        proof = [
            group
            for group in target.identity_groups(row([left], [right]))
            if group["proof_required"]
        ][0]
        probes = {
            left: {"url": left, "final_url": right, "status": "ok", "text_snippet": "same"},
            right: {"url": right, "final_url": right, "status": "ok", "text_snippet": "same"},
        }
        certificate = target.network_certificate(proof, probes)
        self.assertTrue(certificate["supported"])
        self.assertEqual(certificate["reason"], "same_final_url")

    def test_http_and_https_without_redirect_are_not_same_final_url(self) -> None:
        left = "http://example.com/advisory"
        right = "https://example.com/advisory"
        proof = [
            group
            for group in target.identity_groups(row([left], [right]))
            if group["proof_required"]
        ][0]
        probes = {
            left: {
                "url": left,
                "final_url": left,
                "status": "ok",
                "text_snippet": "A" * 100,
                "body_sha256": "left",
            },
            right: {
                "url": right,
                "final_url": right,
                "status": "ok",
                "text_snippet": "B" * 100,
                "body_sha256": "right",
            },
        }
        self.assertFalse(target.network_certificate(proof, probes)["supported"])

    def test_one_matching_pair_does_not_cover_three_identities(self) -> None:
        base = "https://github.com/acme/project/blob/main/file.py"
        line_10 = base + "%23L10"
        line_20 = base + "%23L20"
        proof = [
            group
            for group in target.identity_groups(row([line_10, line_20], [base]))
            if group["proof_required"]
        ][0]
        probes = {
            line_10: {
                "url": line_10,
                "final_url": base,
                "status": "ok",
                "text_snippet": "same",
                "body_sha256": "shared",
            },
            line_20: {
                "url": line_20,
                "final_url": "",
                "status": "http_404",
                "text_snippet": "",
                "body_sha256": None,
            },
            base: {
                "url": base,
                "final_url": base,
                "status": "ok",
                "text_snippet": "same",
                "body_sha256": "shared",
            },
        }
        certificate = target.network_certificate(proof, probes)
        self.assertFalse(certificate["supported"])
        self.assertEqual(certificate["live_identity_count"], 2)

    def test_secondary_worklist_masks_candidate_transformation(self) -> None:
        source = {
            "review_id": "rq2_reference_identity:001",
            "cve_id": "CVE-2026-0001",
            "field": "references",
            "trigger_stage": "transport_and_line",
            "proposed_subset_side": "nvd",
            "current_status": "representation_discrepancy",
            "proposed_status": "incomplete",
            "structural_eligible": True,
            "network_corroborated": False,
            "validation_status": "structural_only",
            "proof_required_groups": [
                {
                    "proposed_identity": "https://example.com/a",
                    "current_identities": ["http://example.com/a", "https://example.com/a"],
                    "sides": ["ghsa", "nvd"],
                    "members": [],
                    "structural_eligibility": {
                        "rules": ["transport_upgrade"],
                        "checks": {"transport_upgrade": True},
                        "eligible": True,
                    },
                    "network_certificate": {"supported": False},
                    "probe_records": [],
                }
            ],
        }
        masked = target.masked_secondary_row(source)
        for key in (
            "current_status",
            "proposed_status",
            "validation_status",
            "trigger_stage",
            "proposed_subset_side",
        ):
            self.assertNotIn(key, masked)
        group = masked["identity_groups"][0]
        for key in (
            "proposed_identity",
            "current_identities",
            "structural_rules",
            "structural_checks",
            "network_certificate",
        ):
            self.assertNotIn(key, group)

    def test_source_validation_recomputes_derived_fields(self) -> None:
        source = row(
            ["http://example.com/advisory"],
            ["https://example.com/advisory", "https://example.com/extra"],
        )
        source.update(
            {
                "cve_id": "CVE-2026-0001",
                "current_status": "representation_discrepancy",
                "proposed_status": "incomplete",
                "trigger_stage": "transport_and_line",
            }
        )
        diagnostic = {
            "variants": {
                "transport_line_known_query_aliases": {
                    "full_corpus": {
                        "changed_vs_current_count": 1,
                        "changed_vs_current_transitions": {
                            "representation_discrepancy->incomplete": 1
                        },
                        "changed_cve_ids": ["CVE-2026-0001"],
                    }
                }
            },
            "changed_case_worklist": {
                "row_count": 1,
                "trigger_stage_counts": {"transport_and_line": 1},
            },
        }
        result = target.validate_source_rows([source], diagnostic)
        self.assertTrue(result["derived_fields_recomputed"])
        source["proposed_normalized_nvd"] = []
        with self.assertRaisesRegex(ValueError, "stale derived field"):
            target.validate_source_rows([source], diagnostic)


if __name__ == "__main__":
    unittest.main()
