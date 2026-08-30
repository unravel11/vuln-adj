import unittest

import temporal_provenance_lib as target


class PathTests(unittest.TestCase):
    def test_source_paths(self):
        self.assertEqual(
            target.fkie_nvd_path("CVE-2023-34624"),
            "CVE-2023/CVE-2023-346xx/CVE-2023-34624.json",
        )
        self.assertEqual(
            target.cvelist_v5_path("CVE-2023-34624"),
            "cves/2023/34xxx/CVE-2023-34624.json",
        )
        self.assertEqual(
            target.cvelist_v5_path("CVE-2023-0028"),
            "cves/2023/0xxx/CVE-2023-0028.json",
        )


class ProjectionTests(unittest.TestCase):
    def test_ghsa_preserves_versions_only_and_all_range_events(self):
        record = {
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "g:a"},
                    "versions": ["1.0", "1.1"],
                },
                {
                    "package": {"ecosystem": "npm", "name": "pkg"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0"},
                                {"introduced": "3.0"},
                                {"last_affected": "3.2"},
                            ],
                        }
                    ],
                },
            ]
        }
        projected = target.project_ghsa_affected(record)
        self.assertEqual(projected[0]["versions"], ["1.0", "1.1"])
        events = projected[1]["ranges"][0]["events"]
        self.assertEqual(len(events), 4)
        self.assertEqual(events[3]["values"], {"last_affected": "3.2"})

    def test_nvd_keeps_cpe_and_top_level_affected_separate(self):
        record = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.0",
                                }
                            ],
                        }
                    ]
                }
            ],
            "affected": [
                {"source": "cna@example.org", "affectedData": {"vendor": "v"}}
            ],
        }
        self.assertEqual(len(target.project_nvd_cpe_configurations(record)), 1)
        self.assertEqual(len(target.project_nvd_top_level_affected(record)), 1)
        self.assertNotIn(
            "source",
            target.project_nvd_cpe_configurations(record)[0],
        )

    def test_reference_type_and_canonical_url_are_retained(self):
        projected = target.project_references(
            [
                {
                    "type": "WEB",
                    "url": "HTTPS://GitHub.com/Org/Repo/commit/abcdef/",
                }
            ]
        )
        self.assertEqual(projected[0]["source_type"], "WEB")
        self.assertEqual(projected[0]["resource_type"], "git_commit")
        self.assertEqual(
            projected[0]["canonical_url"],
            "https://github.com/Org/Repo/commit/abcdef",
        )

    def test_cvelist_preserves_all_affected_versions_and_container_identity(self):
        record = {
            "cveMetadata": {
                "cveId": "CVE-2023-0001",
                "assignerOrgId": "org-cna",
                "dateUpdated": "2025-01-01T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "providerMetadata": {"orgId": "org-cna"},
                    "affected": [
                        {
                            "vendor": "vendor",
                            "product": "product",
                            "defaultStatus": "unaffected",
                            "versions": [
                                {"version": "1.0", "status": "affected"},
                                {"version": "2.0", "status": "unaffected"},
                            ],
                        }
                    ],
                },
                "adp": [
                    {
                        "providerMetadata": {"orgId": "org-adp"},
                        "affected": [{"product": "other", "versions": []}],
                    }
                ],
            },
        }
        projected = target.project_cvelist_v5_record(record)
        self.assertEqual(len(projected["containers"]), 2)
        self.assertEqual(
            len(projected["containers"][0]["affected"][0]["versions"]),
            2,
        )
        self.assertEqual(projected["containers"][1]["provider_org_id"], "org-adp")


if __name__ == "__main__":
    unittest.main()
