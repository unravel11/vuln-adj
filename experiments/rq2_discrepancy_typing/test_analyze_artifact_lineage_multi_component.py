import unittest

import analyze_artifact_lineage_multi_component as target


def metadata(coordinate):
    group, artifact = coordinate.split(":", 1)
    versions = "".join(
        f"<version>{version}</version>"
        for version in ("1.3.0", "1.4.0", "1.5.0", "1.6.0")
    )
    return (
        f"<metadata><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        f"<versioning><versions>{versions}</versions></versioning></metadata>"
    ).encode()


def pom(coordinate, version, *, parent_artifact="inlong-manager"):
    group, artifact = coordinate.split(":", 1)
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.apache.inlong</groupId>
    <artifactId>{parent_artifact}</artifactId>
    <version>{version}</version>
  </parent>
  <groupId>{group}</groupId>
  <artifactId>{artifact}</artifactId>
  <version>{version}</version>
  <name>Apache InLong - Manager {artifact}</name>
</project>""".encode()


def bodies():
    result = {}
    for coordinate, spec in target.CASE_SPEC["components"].items():
        result[spec["catalog"].key] = metadata(coordinate)
        for source in spec["anchors"]:
            result[source.key] = pom(coordinate, source.version)
    return result


def point(version):
    return {
        "criteria": f"cpe:2.3:a:apache:inlong:{version}:*:*:*:*:*:*:*",
        "product": "inlong",
        "package_name": "inlong",
        "version": version,
        "vulnerable": True,
    }


def component_range(coordinate, fixed="1.6.0"):
    return {
        "ecosystem": "Maven",
        "product": coordinate,
        "package_name": coordinate,
        "introduced": "1.4.0",
        "fixed": fixed,
        "version_start_including": "1.4.0",
        "version_end_excluding": fixed,
        "vulnerable": True,
    }


def row():
    coordinates = list(target.CASE_SPEC["components"])
    return {
        "sample_id": target.FIXED_SAMPLE_ID,
        "cve_id": target.CASE_SPEC["cve_id"],
        "nvd_subject": "inlong",
        "ghsa_subjects": coordinates,
        "nvd_range_signature": [
            {"start": "1.4.0", "end": "1.4.0"},
            {"start": "1.5.0", "end": "1.5.0"},
        ],
        "ghsa_range_signature": [
            {"start": "1.4.0", "end": "1.6.0"},
            {"start": "1.4.0", "end": "1.6.0"},
        ],
        "nvd_value": [point("1.4.0"), point("1.5.0")],
        "ghsa_value": [component_range(coordinate) for coordinate in coordinates],
    }


class AnalyzeArtifactLineageMultiComponentTests(unittest.TestCase):
    def test_equal_component_union_projects_to_representation_discrepancy(self):
        case = target.analyze_case(row(), bodies())
        self.assertTrue(case["gate"]["passed"])
        self.assertEqual(case["release_sets"]["relation"], "equal")
        self.assertEqual(
            case["gate"]["development_typing_candidate"],
            "representation_discrepancy",
        )
        self.assertFalse(case["release_sets"]["component_heterogeneity"])

    def test_component_heterogeneity_is_retained_even_when_union_is_equal(self):
        candidate = row()
        candidate["ghsa_value"][1] = component_range(
            candidate["ghsa_subjects"][1], fixed="1.5.0"
        )
        candidate["ghsa_range_signature"][1]["end"] = "1.5.0"
        case = target.analyze_case(candidate, bodies())
        self.assertTrue(case["gate"]["passed"])
        self.assertEqual(case["release_sets"]["relation"], "equal")
        self.assertTrue(case["release_sets"]["component_heterogeneity"])

    def test_unbound_component_parent_forces_abstention(self):
        evidence = bodies()
        spec = target.CASE_SPEC["components"]["org.apache.inlong:manager-service"]
        source = spec["anchors"][1]
        evidence[source.key] = pom(
            spec["coordinate"], source.version, parent_artifact="other-parent"
        )
        case = target.analyze_case(row(), evidence)
        self.assertFalse(case["gate"]["passed"])
        self.assertIn("component_product_edges_bound", case["gate"]["failed_checks"])
        self.assertEqual(case["gate"]["development_typing_candidate"], "uncertain")


if __name__ == "__main__":
    unittest.main()
