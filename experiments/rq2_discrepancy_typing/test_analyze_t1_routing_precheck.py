#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

import analyze_t1_routing_precheck as target


def span(
    *,
    start: str | None = None,
    end: str | None = None,
    point: str | None = None,
) -> dict:
    return {
        "version_start_including": start,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": end,
        "fixed": None,
        "introduced": None,
        "version": point,
    }


def base_view() -> dict:
    return {
        "severity": {
            "nvd": {
                "label": "HIGH",
                "canonical_label": "HIGH",
                "vector": "CVSS:3.1/AV:N",
            },
            "ghsa": {
                "label": "HIGH",
                "canonical_label": "HIGH",
                "vector": "CVSS:3.1/AV:N",
            },
        },
        "published": {
            "nvd": "2026-01-01T00:00:00Z",
            "ghsa": "2026-01-02T00:00:00Z",
        },
        "references": {
            "nvd_urls": ["https://example.test/a", "https://example.test/c"],
            "ghsa_urls": ["https://example.test/a", "https://example.test/b"],
        },
        "affected_versions": {
            "nvd": [span(end="1.0.0")],
            "ghsa": [span(start="2.0.0", end="3.0.0")],
        },
        "package_names": {
            "nvd": ["demo"],
            "ghsa": ["pkg:pypi/demo"],
        },
    }


def base_discrepancies() -> dict:
    return {
        "severity": {"status": "equivalent"},
        "published": {"status": "temporal_discrepancy"},
        "references": {"status": "representation_discrepancy"},
        "affected_versions": {"status": "representation_discrepancy"},
    }


def policy_view() -> dict:
    view = base_view()
    view["field_discrepancies"] = base_discrepancies()
    return view


def corpus() -> list[dict]:
    view = base_view()
    discrepancies = base_discrepancies()
    return [
        {
            "cve_id": f"CVE-2026-{index + 1:04d}",
            "unified_view": copy.deepcopy(view),
            "field_discrepancies": copy.deepcopy(discrepancies),
        }
        for index in range(8066)
    ]


class RoutingPrecheckTests(unittest.TestCase):
    def test_exact_mcnemar_boundary(self) -> None:
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 0), 1.0)
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 5), 0.0625)
        self.assertEqual(target.exact_two_sided_mcnemar_p(0, 6), 0.03125)
        self.assertEqual(target.minimum_rows_for_any_rejection(), 6)

    def test_conditional_power_search_is_minimal(self) -> None:
        result = target.minimum_rows_for_power(0.80)
        rows = result["minimum_effective_discordant_rows"]
        self.assertGreaterEqual(result["achieved_exact_power"], 0.80)
        self.assertLess(target.conditional_power(rows - 1, 0.80), 0.80)

    def test_field_aware_simple_actions(self) -> None:
        view = base_view()
        self.assertEqual(
            target.simple_policy_action(view, "severity"), "no_action"
        )
        self.assertEqual(
            target.simple_policy_action(view, "published"), "wait_for_sync"
        )
        self.assertEqual(
            target.simple_policy_action(view, "references"), "enrich_record"
        )
        self.assertEqual(
            target.simple_policy_action(view, "affected_versions"),
            "conflict_escalation",
        )

    def test_type_first_abstains_on_frozen_rule_limits(self) -> None:
        view = policy_view()
        view["severity"]["ghsa"]["label"] = "CRITICAL"
        view["severity"]["ghsa"]["canonical_label"] = "CRITICAL"
        view["severity"]["ghsa"]["vector"] = "CVSS:4.0/AV:N"
        view["field_discrepancies"]["severity"]["status"] = "factual_conflict"
        self.assertEqual(
            target.type_first_action(view, "severity", abstention=False),
            "conflict_escalation",
        )
        self.assertEqual(
            target.type_first_action(view, "severity", abstention=True),
            "abstain",
        )

        view = policy_view()
        view["package_names"]["ghsa"] = ["other"]
        self.assertEqual(
            target.type_first_action(view, "affected_versions", abstention=True),
            "abstain",
        )

        view = policy_view()
        view["field_discrepancies"]["references"]["status"] = "factual_conflict"
        self.assertEqual(
            target.type_first_action(view, "references", abstention=True),
            "abstain",
        )

    def test_full_census_gate_uses_two_informative_fields(self) -> None:
        analysis = target.compute_analysis(corpus())
        self.assertEqual(analysis["rows"], 8066)
        self.assertEqual(analysis["field_instances"], 32264)
        self.assertEqual(
            analysis["primary_comparison"]["by_field"]["severity"][
                "action_disagreement"
            ],
            0,
        )
        self.assertEqual(
            analysis["primary_comparison"]["by_field"]["affected_versions"][
                "manual_review_disagreement"
            ],
            8066,
        )
        self.assertEqual(
            analysis["primary_comparison"]["by_field"]["references"][
                "action_disagreement"
            ],
            8066,
        )
        self.assertEqual(
            analysis["decision"], "CONDITIONAL_GO_FOR_V3_PACKET_DESIGN"
        )
        self.assertFalse(analysis["eligible_for_policy_superiority_claim"])

    def test_unexpected_status_fails_closed(self) -> None:
        view = policy_view()
        view["field_discrepancies"]["severity"]["status"] = "unknown"
        with self.assertRaisesRegex(ValueError, "unsupported deterministic status"):
            target.type_first_action(view, "severity", abstention=True)


if __name__ == "__main__":
    unittest.main()
