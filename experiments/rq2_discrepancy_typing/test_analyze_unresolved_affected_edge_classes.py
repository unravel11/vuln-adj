import unittest

import analyze_unresolved_affected_edge_classes as target


def item(subject, *, start=None, end=None, version=None, ecosystem="Go", criteria=None):
    return {
        "package_name": subject,
        "product": subject,
        "ecosystem": ecosystem,
        "criteria": criteria,
        "version": version,
        "introduced": start,
        "fixed": end,
        "version_start_including": start,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": end,
    }


class AnalyzeUnresolvedAffectedEdgeClassesTests(unittest.TestCase):
    def test_span_signature_treats_introduced_zero_as_open_lower(self):
        self.assertEqual(
            target.span_signature(item("demo", start="0", end="1.2.3")),
            ("range", None, False, "1.2.3", False),
        )

    def test_singleton_is_not_an_open_range(self):
        value = item("demo", version="1.2.3")
        self.assertEqual(
            target.span_signature(value),
            ("singleton", "1.2.3", True, "1.2.3", True),
        )

    def test_project_family_recognizes_mattermost_without_labels(self):
        row = {
            "nvd_value": [{**item("mattermost_server"), "vendor": "mattermost"}],
            "ghsa_value": [item("github.com/mattermost/mattermost/server/v8")],
        }
        self.assertEqual(target.project_family(row), "mattermost")

    def test_row_features_detect_shared_range_and_pseudo_version(self):
        row = {
            "sample_id": "sample:1",
            "cve_id": "CVE-2000-0001",
            "field": "affected_versions",
            "nvd_value": [
                {**item("mattermost_server", start="9.11.0", end="9.11.6"), "vendor": "mattermost"}
            ],
            "ghsa_value": [
                item("github.com/mattermost/mattermost/server/v8", start="9.11.0", end="9.11.6"),
                item(
                    "github.com/mattermost/mattermost/server/v8",
                    start="0",
                    end="8.0.0-20250102081831-64c566a8280b",
                ),
            ],
        }
        result = target.analyze_row(
            row,
            {("mattermost_server", "github.com/mattermost/mattermost/server/v8")},
        )
        self.assertEqual(result["features"]["shared_range_signature_count"], 1)
        self.assertTrue(result["features"]["go_pseudo_version"])
        self.assertTrue(result["features"]["prior_official_edge_bound"])

    def test_family_ranking_prefers_prior_bound_repeated_family(self):
        base_features = {
            "singleton_count": 0,
            "cpe_update_qualifiers": [],
            "shared_range_signature_count": 1,
            "prior_official_edge_bound": False,
            "go_pseudo_version": True,
            "open_upper_bound": False,
            "multi_subject_union_required": False,
        }
        rows = []
        for family, prior in (("mattermost", True), ("lf_edge_eve", False)):
            for index in range(2):
                rows.append({
                    "sample_id": f"{family}:{index}",
                    "cve_id": f"CVE-2000-000{index}",
                    "project_family": family,
                    "source_structure": {
                        "nvd_subjects": [family],
                        "ghsa_subjects": [family],
                        "ghsa_ecosystems": ["Go"],
                    },
                    "features": {**base_features, "prior_official_edge_bound": prior},
                })
        ranking = target.build_family_ranking(rows)
        self.assertEqual(ranking[0]["project_family"], "mattermost")
        self.assertEqual(ranking[0]["eligible_rank"], 1)


if __name__ == "__main__":
    unittest.main()
