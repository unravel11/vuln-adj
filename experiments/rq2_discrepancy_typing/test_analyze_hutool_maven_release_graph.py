import io
import unittest
import zipfile

import analyze_hutool_maven_release_graph as target


def metadata(artifact, versions=("5.8.19", "5.8.21", "5.8.22", "5.8.4.M1")):
    values = "".join(f"<version>{version}</version>" for version in versions)
    return (
        f"<metadata><groupId>cn.hutool</groupId><artifactId>{artifact}</artifactId>"
        f"<versioning><versions>{values}</versions><lastUpdated>1</lastUpdated>"
        f"</versioning></metadata>"
    ).encode()


def pom(version, *, core_version="${project.parent.version}"):
    return f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>cn.hutool</groupId><artifactId>hutool-parent</artifactId><version>{version}</version></parent>
  <artifactId>hutool-all</artifactId><packaging>jar</packaging>
  <dependencies>
    <dependency><groupId>cn.hutool</groupId><artifactId>hutool-core</artifactId><version>{core_version}</version></dependency>
    <dependency><groupId>cn.hutool</groupId><artifactId>hutool-json</artifactId><version>${{project.parent.version}}</version></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>maven-shade-plugin</artifactId><executions><execution><goals><goal>shade</goal></goals></execution></executions></plugin></plugins></build>
</project>""".encode()


def aggregate_jar(*, include_json=True):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("cn/hutool/core/Util.class", b"core")
        if include_json:
            archive.writestr("cn/hutool/json/JSON.class", b"json")
    return stream.getvalue()


class AnalyzeHutoolMavenReleaseGraphTests(unittest.TestCase):
    def test_versions_use_numeric_order(self):
        values = ["5.8.9", "5.8.19", "4.0.0"]
        self.assertEqual(sorted(values, key=target.Version.parse), ["4.0.0", "5.8.9", "5.8.19"])

    def test_catalog_separates_stable_and_milestone_tokens(self):
        parsed = target.parse_catalog(metadata("hutool-core"), "cn.hutool:hutool-core")
        self.assertTrue(parsed["identity_bound"])
        self.assertEqual(parsed["stable_version_count"], 3)
        self.assertEqual(parsed["excluded_versions"], ["5.8.4.M1"])

    def test_source_pom_resolves_parent_version_dependencies(self):
        parsed = target.parse_source_pom(pom("5.8.21"), "5.8.21")
        self.assertTrue(parsed["bound"])
        self.assertEqual(
            parsed["required_dependencies"]["cn.hutool:hutool-core"]["resolved_version"],
            "5.8.21",
        )

    def test_source_pom_rejects_component_version_drift(self):
        parsed = target.parse_source_pom(pom("5.8.21", core_version="5.8.20"), "5.8.21")
        self.assertFalse(parsed["bound"])
        self.assertFalse(parsed["checks"]["required_dependencies_bound"])

    def test_aggregate_jar_requires_both_component_prefixes(self):
        self.assertTrue(target.parse_aggregate_jar(aggregate_jar(), "5.8.21")["bound"])
        self.assertFalse(
            target.parse_aggregate_jar(aggregate_jar(include_json=False), "5.8.21")["bound"]
        )

    def test_introduced_zero_normalizes_to_open_lower_bound(self):
        item = {
            "package_name": "cn.hutool:hutool-core",
            "version_start_including": "0",
        }
        self.assertEqual(target.claim_signature([item]), {
            "cn.hutool:hutool-core": [target.span(None, None)]
        })

    def test_strict_subset_maps_to_incomplete(self):
        relation = target.set_relation({"5.8.21"}, {"5.8.19", "5.8.21", "5.8.22"})
        self.assertEqual(relation, "nvd_subset_of_ghsa")
        self.assertEqual(target.candidate_for_relation(relation), "incomplete")


if __name__ == "__main__":
    unittest.main()
